import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request


app = Flask(__name__)


# ------------------------------------------------------------
# Constants / regexes
# ------------------------------------------------------------

URI_RE = re.compile(r"^gs://([^/]+)/(.+)$")
GENERATION_RE = re.compile(r"^[0-9]+$")
CRC32C_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

SAFE_INT_MAX = 9007199254740991


# ------------------------------------------------------------
# CRC32C
# ------------------------------------------------------------

CRC32C_TABLE = []


def make_crc32c_table():
    poly = 0x82F63B78

    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        CRC32C_TABLE.append(crc)


make_crc32c_table()


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data: bytes) -> str:
    return f"{crc32c(data):08x}"


# ------------------------------------------------------------
# UTF-8 sorting
# ------------------------------------------------------------

def utf8_key(value):
    if value is None:
        return b""

    return str(value).encode("utf-8")


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# ------------------------------------------------------------
# Timestamp parsing / normalization
# ------------------------------------------------------------

def parse_time(value):
    if not isinstance(value, str):
        return None

    match = TIME_RE.fullmatch(value)

    if not match:
        return None

    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    fraction = match.group(7)
    offset = match.group(8)

    # Calendar/time validation
    try:
        if fraction is None:
            microsecond = 0
        else:
            microsecond = int(fraction.ljust(3, "0")) * 1000

        base = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
        )
    except ValueError:
        return None

    if offset == "Z":
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        off_hour = int(offset[1:3])
        off_minute = int(offset[4:6])

        # Maximum magnitude is 14:00.
        if off_hour > 14:
            return None

        if off_minute >= 60:
            return None

        if off_hour == 14 and off_minute != 0:
            return None

        tz = timezone(
            sign * timedelta(
                hours=off_hour,
                minutes=off_minute,
            )
        )

    return base.replace(tzinfo=tz).astimezone(timezone.utc)


def normalize_time(value):
    dt = parse_time(value)

    if dt is None:
        return None

    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.microsecond // 1000:03d}Z"


# ------------------------------------------------------------
# Unicode canonicalization
# ------------------------------------------------------------

def canonicalize(value):
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()

    # Unicode whitespace -> ASCII space
    chars = []

    for char in value:
        if char.isspace():
            chars.append(" ")
        else:
            chars.append(char)

    value = "".join(chars)

    # Collapse whitespace
    value = re.sub(r" +", " ", value)

    return value.strip()


# ------------------------------------------------------------
# Word set for contamination
# Unicode letters/numbers only
# ------------------------------------------------------------

def word_set(text):
    words = set()

    current = []

    for char in text.lower():
        category = unicodedata.category(char)

        if category.startswith("L") or category.startswith("N"):
            current.append(char)
        else:
            if current:
                words.add("".join(current))
                current = []

    if current:
        words.add("".join(current))

    return words


def jaccard(a, b):
    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ------------------------------------------------------------
# Input validation
# ------------------------------------------------------------

def invalid_input():
    return jsonify({"error": "INVALID_INPUT"}), 400


def validate_policy(policy):
    if not isinstance(policy, dict):
        return False, None

    required = {
        "minTime",
        "maxTime",
        "contaminationThreshold",
    }

    if set(policy.keys()) != required:
        return False, None

    min_time = parse_time(policy["minTime"])
    max_time = parse_time(policy["maxTime"])

    threshold = policy["contaminationThreshold"]

    if min_time is None or max_time is None:
        return False, None

    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
    ):
        return False, None

    # finite
    if threshold != threshold:
        return False, None

    if threshold in (float("inf"), float("-inf")):
        return False, None

    if threshold < 0 or threshold > 1:
        return False, None

    return True, (
        min_time,
        max_time,
        float(threshold),
    )


# ------------------------------------------------------------
# Object validation
# ------------------------------------------------------------

def validate_object(obj):
    codes = []

    if not isinstance(obj, dict):
        return ["URI_INVALID", "GENERATION_INVALID",
                "CRC32C_INVALID", "SCHEMA_INVALID"]

    uri = obj.get("uri")

    # URI
    if not isinstance(uri, str) or URI_RE.fullmatch(uri) is None:
        codes.append("URI_INVALID")

    # Generation
    generation = obj.get("generation")
    fetched_generation = obj.get("fetchedGeneration")

    generation_valid = (
        isinstance(generation, str)
        and GENERATION_RE.fullmatch(generation) is not None
    )

    fetched_generation_valid = (
        isinstance(fetched_generation, str)
        and GENERATION_RE.fullmatch(fetched_generation) is not None
    )

    if not generation_valid or not fetched_generation_valid:
        codes.append("GENERATION_INVALID")

    if (
        generation_valid
        and fetched_generation_valid
        and generation != fetched_generation
    ):
        codes.append("GENERATION_MISMATCH")

    # CRC syntax
    supplied_crc = obj.get("crc32c")

    crc_valid = (
        isinstance(supplied_crc, str)
        and CRC32C_RE.fullmatch(supplied_crc) is not None
    )

    if not crc_valid:
        codes.append("CRC32C_INVALID")

    # Schema/content
    schema_ok = obj.get("schemaId") == "training-v1"
    content = obj.get("content")

    if not schema_ok:
        codes.append("SCHEMA_INVALID")

    if not isinstance(content, str):
        codes.append("SCHEMA_INVALID")

    return sorted(set(codes), key=utf8_key)


# ------------------------------------------------------------
# JSONL parsing
# ------------------------------------------------------------

def parse_jsonl(content):
    rows = []

    lines = content.splitlines()

    # Empty file / no nonblank lines
    nonblank_found = False

    for line in lines:
        if line.strip() == "":
            continue

        nonblank_found = True

        try:
            parsed = json.loads(line)
        except Exception:
            return None, "JSONL_INVALID"

        if not isinstance(parsed, dict):
            return None, "SCHEMA_INVALID"

        expected_keys = {
            "id",
            "entity",
            "eventTime",
            "revision",
            "text",
        }

        if set(parsed.keys()) != expected_keys:
            return None, "SCHEMA_INVALID"

        if not all(
            isinstance(parsed.get(k), str)
            for k in ["id", "entity", "eventTime", "text"]
        ):
            return None, "SCHEMA_INVALID"

        revision = parsed.get("revision")

        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or revision > SAFE_INT_MAX
        ):
            return None, "SCHEMA_INVALID"

        if parse_time(parsed["eventTime"]) is None:
            return None, "SCHEMA_INVALID"

        rows.append(parsed)

    if not nonblank_found:
        return None, "SCHEMA_INVALID"

    return rows, None


# ------------------------------------------------------------
# Main endpoint
# ------------------------------------------------------------

@app.route("/build-corpus", methods=["POST"])
def build_corpus():

    # Accept JSON only
    if not request.is_json:
        return invalid_input()

    try:
        body = request.get_json()
    except Exception:
        return invalid_input()

    if not isinstance(body, dict):
        return invalid_input()

    policy = body.get("policy")
    objects = body.get("objects")

    if policy is None or not isinstance(objects, list):
        return invalid_input()

    policy_valid, policy_data = validate_policy(policy)

    if policy_valid:
        min_time, max_time, threshold = policy_data
    else:
        min_time = max_time = threshold = None

    train = []
    validation = []
    test = []

    rejected_objects = []
    rejected_rows = []
    lineage = []

    # --------------------------------------------------------
    # First pass: validate objects + parse rows
    # --------------------------------------------------------

    all_rows = []

    for obj in objects:

        uri = obj.get("uri") if isinstance(obj, dict) else None

        object_codes = validate_object(obj)

        content = obj.get("content") if isinstance(obj, dict) else None

        # CRC mismatch is checked only if content is string and CRC
        # syntax is valid.
        if (
            isinstance(content, str)
            and isinstance(obj.get("crc32c"), str)
            and CRC32C_RE.fullmatch(obj["crc32c"]) is not None
        ):
            actual_crc = crc32c_hex(content.encode("utf-8"))

            if actual_crc != obj["crc32c"]:
                object_codes.append("CRC32C_MISMATCH")

        object_codes = sorted(
            set(object_codes),
            key=utf8_key,
        )

        if object_codes:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": object_codes,
            })
            continue

        # JSONL parsing
        rows, parse_error = parse_jsonl(content)

        if parse_error:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": [parse_error],
            })
            continue

        # Valid object -> lineage
        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"],
            "schemaId": obj["schemaId"],
        })

        for row in rows:
            normalized_row = {
                "id": row["id"],
                "entity": canonicalize(row["entity"]),
                "eventTime": normalize_time(row["eventTime"]),
                "revision": row["revision"],
                "text": canonicalize(row["text"]),
                "_uri": obj["uri"],
            }

            all_rows.append(normalized_row)

    # --------------------------------------------------------
    # Deduplication
    # --------------------------------------------------------

    groups = {}

    for row in all_rows:
        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(key, []).append(row)

    retained = []

    for key, candidates in groups.items():

        # Highest revision first, then UTF-8 smallest ID.
        candidates_sorted = sorted(
            candidates,
            key=lambda r: (
                -r["revision"],
                utf8_key(r["id"]),
            ),
        )

        winner = candidates_sorted[0]
        retained.append(winner)

        for loser in candidates_sorted[1:]:
            rejected_rows.append({
                "id": loser["id"],
                "reasonCodes": ["DUPLICATE"],
            })

    # --------------------------------------------------------
    # Policy / window
    # --------------------------------------------------------

    eligible = []

    for row in retained:

        reasons = []

        if not policy_valid:
            reasons.append("POLICY_INVALID")
        else:
            dt = parse_time(row["eventTime"])

            if dt < min_time or dt > max_time:
                reasons.append("OUT_OF_WINDOW")

        if reasons:
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": sorted(
                    set(reasons),
                    key=utf8_key,
                ),
            })
        else:
            eligible.append(row)

    # --------------------------------------------------------
    # Split
    # --------------------------------------------------------

    for row in eligible:

        entity_bytes = row["entity"].encode("utf-8")

        bucket = hashlib.sha256(entity_bytes).digest()[0] % 10

        if bucket <= 5:
            split = "train"
        elif bucket <= 7:
            split = "validation"
        else:
            split = "test"

        row["_split"] = split

    train_rows = [
        r for r in eligible
        if r["_split"] == "train"
    ]

    validation_rows = [
        r for r in eligible
        if r["_split"] == "validation"
    ]

    test_rows = [
        r for r in eligible
        if r["_split"] == "test"
    ]

    # --------------------------------------------------------
    # Contamination
    # --------------------------------------------------------

    train_word_sets = [
        word_set(row["text"])
        for row in train_rows
    ]

    def contamination_rejected(row):
        row_words = word_set(row["text"])

        for train_words in train_word_sets:
            if jaccard(row_words, train_words) >= threshold:
                return True

        return False

    final_validation = []

    for row in validation_rows:
        if contamination_rejected(row):
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["TRAIN_CONTAMINATION"],
            })
        else:
            final_validation.append(row)

    final_test = []

    for row in test_rows:
        if contamination_rejected(row):
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["TRAIN_CONTAMINATION"],
            })
        else:
            final_test.append(row)

    # --------------------------------------------------------
    # Serialization
    # --------------------------------------------------------

    def clean_row(row):
        return {
            "id": row["id"],
            "entity": row["entity"],
            "eventTime": row["eventTime"],
            "revision": row["revision"],
            "text": row["text"],
        }

    def sort_rows(rows):
        return sorted(
            [clean_row(r) for r in rows],
            key=lambda r: (
                utf8_key(r["id"]),
                compact_json(r).encode("utf-8"),
            ),
        )

    train_output = sort_rows(train_rows)
    validation_output = sort_rows(final_validation)
    test_output = sort_rows(final_test)

    def digest(rows):
        payload = b"".join(
            (
                compact_json(row) + "\n"
            ).encode("utf-8")
            for row in rows
        )

        return hashlib.sha256(payload).hexdigest()

    # --------------------------------------------------------
    # Rejected row merging
    # --------------------------------------------------------

    merged_rejected = {}

    for item in rejected_rows:
        rid = item["id"]

        if rid not in merged_rejected:
            merged_rejected[rid] = set()

        merged_rejected[rid].update(item["reasonCodes"])

    rejected_rows_output = [
        {
            "id": rid,
            "reasonCodes": sorted(
                reasons,
                key=utf8_key,
            ),
        }
        for rid, reasons in merged_rejected.items()
    ]

    rejected_rows_output.sort(
        key=lambda x: (
            utf8_key(x["id"]),
            compact_json(x).encode("utf-8"),
        )
    )

    # --------------------------------------------------------
    # Sort rejected objects
    # --------------------------------------------------------

    for item in rejected_objects:
        item["reasonCodes"] = sorted(
            set(item["reasonCodes"]),
            key=utf8_key,
        )

    rejected_objects.sort(
        key=lambda x: (
            utf8_key(x["uri"]),
            compact_json(x).encode("utf-8"),
        )
    )

    # --------------------------------------------------------
    # Sort lineage
    # --------------------------------------------------------

    lineage.sort(
        key=lambda x: (
            utf8_key(x["uri"]),
            compact_json(x).encode("utf-8"),
        )
    )

    # --------------------------------------------------------
    # Exact response shape
    # --------------------------------------------------------

    response = {
        "splits": {
            "train": train_output,
            "validation": validation_output,
            "test": test_output,
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows_output,
        "digests": {
            "train": digest(train_output),
            "validation": digest(validation_output),
            "test": digest(test_output),
        },
        "lineage": lineage,
    }

    return jsonify(response)


@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "service": "immutable-corpus-service",
        "status": "ok",
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
    )
