import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request


app = Flask(__name__)

# ============================================================
# Constants
# ============================================================

SAFE_INT_MAX = 9007199254740991

URI_RE = re.compile(r"^gs://[^/]+/[^/]+$")
GEN_RE = re.compile(r"^[0-9]+$")
CRC_RE = re.compile(r"^[0-9a-f]{8}$")

TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T"
    r"(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,3}))?"
    r"(Z|[+-]\d{2}:\d{2})$"
)

OBJECT_CODES = {
    "URI_INVALID",
    "GENERATION_INVALID",
    "GENERATION_MISMATCH",
    "CRC32C_INVALID",
    "CRC32C_MISMATCH",
    "SCHEMA_INVALID",
    "JSONL_INVALID",
}

ROW_CODES = {
    "DUPLICATE",
    "POLICY_INVALID",
    "OUT_OF_WINDOW",
    "TRAIN_CONTAMINATION",
}


# ============================================================
# CRC32C
# ============================================================

CRC32C_TABLE = []


def _make_crc32c_table():
    poly = 0x82F63B78

    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        CRC32C_TABLE.append(crc)


_make_crc32c_table()


def crc32c(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)

    return crc ^ 0xFFFFFFFF


def crc32c_hex(data):
    return f"{crc32c(data):08x}"


# ============================================================
# Deterministic JSON / UTF-8 helpers
# ============================================================

def utf8(value):
    if value is None:
        return b""
    return str(value).encode("utf-8")


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sorted_reason_codes(codes):
    return sorted(set(codes), key=lambda x: utf8(x))


# ============================================================
# Timestamp parsing
# ============================================================

def parse_time(value):
    if not isinstance(value, str):
        return None

    m = TIME_RE.fullmatch(value)
    if not m:
        return None

    year = int(m.group(1))
    month = int(m.group(2))
    day = int(m.group(3))
    hour = int(m.group(4))
    minute = int(m.group(5))
    second = int(m.group(6))
    fraction = m.group(7)
    offset = m.group(8)

    if fraction is None:
        microsecond = 0
    else:
        microsecond = int(fraction.ljust(3, "0")) * 1000

    try:
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

        if off_minute > 59:
            return None

        if off_hour > 14:
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

    return (
        dt.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{dt.microsecond // 1000:03d}Z"
    )


# ============================================================
# Canonicalization
# ============================================================

def canonicalize(value):
    value = unicodedata.normalize("NFKC", value)
    value = value.lower()

    out = []

    for ch in value:
        if ch.isspace():
            out.append(" ")
        else:
            out.append(ch)

    value = "".join(out)

    value = re.sub(r" +", " ", value)

    return value.strip()


# ============================================================
# Contamination word sets
# ============================================================

def word_set(text):
    result = set()
    current = []

    for ch in text.lower():
        category = unicodedata.category(ch)

        if category.startswith("L") or category.startswith("N"):
            current.append(ch)
        else:
            if current:
                result.add("".join(current))
                current = []

    if current:
        result.add("".join(current))

    return result


def jaccard(a, b):
    if not a and not b:
        return 1.0

    union = a | b

    if not union:
        return 1.0

    return len(a & b) / len(union)


# ============================================================
# Policy
# ============================================================

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

    if min_time is None or max_time is None:
        return False, None

    # minTime must not be after maxTime.
    if min_time > max_time:
        return False, None

    threshold = policy["contaminationThreshold"]

    if isinstance(threshold, bool):
        return False, None

    if not isinstance(threshold, (int, float)):
        return False, None

    if not math.isfinite(float(threshold)):
        return False, None

    if not 0 <= float(threshold) <= 1:
        return False, None

    return True, (
        min_time,
        max_time,
        float(threshold),
    )


# ============================================================
# Object validation
# ============================================================

def validate_object(obj):
    codes = []

    if not isinstance(obj, dict):
        return [
            "URI_INVALID",
            "GENERATION_INVALID",
            "CRC32C_INVALID",
            "SCHEMA_INVALID",
        ]

    uri = obj.get("uri")

    if not isinstance(uri, str) or URI_RE.fullmatch(uri) is None:
        codes.append("URI_INVALID")

    generation = obj.get("generation")
    fetched = obj.get("fetchedGeneration")

    generation_valid = (
        isinstance(generation, str)
        and GEN_RE.fullmatch(generation) is not None
    )

    fetched_valid = (
        isinstance(fetched, str)
        and GEN_RE.fullmatch(fetched) is not None
    )

    if not generation_valid or not fetched_valid:
        codes.append("GENERATION_INVALID")
    elif generation != fetched:
        codes.append("GENERATION_MISMATCH")

    crc = obj.get("crc32c")

    crc_valid = (
        isinstance(crc, str)
        and CRC_RE.fullmatch(crc) is not None
    )

    if not crc_valid:
        codes.append("CRC32C_INVALID")

    schema_valid = (
        obj.get("schemaId") == "training-v1"
        and isinstance(obj.get("content"), str)
    )

    if not schema_valid:
        codes.append("SCHEMA_INVALID")

    return sorted_reason_codes(codes)


# ============================================================
# JSONL validation
# ============================================================

EXPECTED_ROW_KEYS = {
    "id",
    "entity",
    "eventTime",
    "revision",
    "text",
}


def parse_jsonl(content):
    rows = []

    # splitlines handles normal JSONL line endings.
    lines = content.splitlines()

    if not any(line.strip() for line in lines):
        return None, "SCHEMA_INVALID"

    for line in lines:
        if line.strip() == "":
            continue

        try:
            row = json.loads(line)
        except Exception:
            return None, "JSONL_INVALID"

        if not isinstance(row, dict):
            return None, "SCHEMA_INVALID"

        if set(row.keys()) != EXPECTED_ROW_KEYS:
            return None, "SCHEMA_INVALID"

        for field in ("id", "entity", "eventTime", "text"):
            if not isinstance(row[field], str):
                return None, "SCHEMA_INVALID"

        revision = row["revision"]

        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or revision > SAFE_INT_MAX
        ):
            return None, "SCHEMA_INVALID"

        if parse_time(row["eventTime"]) is None:
            return None, "SCHEMA_INVALID"

        rows.append(row)

    if not rows:
        return None, "SCHEMA_INVALID"

    return rows, None


# ============================================================
# Row output
# ============================================================

def public_row(row):
    return {
        "id": row["id"],
        "entity": row["entity"],
        "eventTime": row["eventTime"],
        "revision": row["revision"],
        "text": row["text"],
    }


def row_sort_key(row):
    public = public_row(row)

    return (
        utf8(public["id"]),
        compact_json(public).encode("utf-8"),
    )


def serialize_rows(rows):
    rows = sorted(
        rows,
        key=row_sort_key,
    )

    payload = b""

    for row in rows:
        payload += (
            compact_json(public_row(row)) + "\n"
        ).encode("utf-8")

    return rows, payload


def digest_rows(rows):
    _, payload = serialize_rows(rows)
    return hashlib.sha256(payload).hexdigest()


# ============================================================
# Rejection sorting
# ============================================================

def rejected_row_sort_key(item):
    return (
        utf8(item["id"]),
        compact_json(item).encode("utf-8"),
    )


def rejected_object_sort_key(item):
    return (
        utf8(item["uri"]),
        compact_json(item).encode("utf-8"),
    )


def lineage_sort_key(item):
    return (
        utf8(item["uri"]),
        compact_json(item).encode("utf-8"),
    )


# ============================================================
# Endpoint
# ============================================================

@app.route("/build-corpus", methods=["POST"])
def build_corpus():

    # Request must contain JSON.
    if not request.is_json:
        return jsonify({"error": "INVALID_INPUT"}), 400

    try:
        body = request.get_json()
    except Exception:
        return jsonify({"error": "INVALID_INPUT"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "INVALID_INPUT"}), 400

    # Missing policy OR non-array objects => exact 400 response.
    if "policy" not in body or "objects" not in body:
        return jsonify({"error": "INVALID_INPUT"}), 400

    if not isinstance(body["objects"], list):
        return jsonify({"error": "INVALID_INPUT"}), 400

    policy = body["policy"]
    objects = body["objects"]

    policy_valid, policy_data = validate_policy(policy)

    if policy_valid:
        min_time, max_time, threshold = policy_data
    else:
        min_time = None
        max_time = None
        threshold = None

    rejected_objects = []
    rejected_rows = []
    lineage = []

    valid_rows = []

    # ========================================================
    # Object processing
    # ========================================================

    for obj in objects:

        uri = obj.get("uri") if isinstance(obj, dict) else None

        object_codes = validate_object(obj)

        content = (
            obj.get("content")
            if isinstance(obj, dict)
            else None
        )

        # CRC mismatch is checked only when:
        # - content is a string
        # - CRC syntax is valid
        if (
            isinstance(content, str)
            and isinstance(obj.get("crc32c"), str)
            and CRC_RE.fullmatch(obj["crc32c"]) is not None
        ):
            actual_crc = crc32c_hex(
                content.encode("utf-8")
            )

            if actual_crc != obj["crc32c"]:
                object_codes.append("CRC32C_MISMATCH")

        object_codes = sorted_reason_codes(object_codes)

        # Object integrity/schema failure.
        if object_codes:
            rejected_objects.append({
                "uri": uri if isinstance(uri, str) else None,
                "reasonCodes": object_codes,
            })
            continue

        # Parse JSONL only after object-level checks pass.
        rows, jsonl_error = parse_jsonl(content)

        if jsonl_error is not None:
            rejected_objects.append({
                "uri": uri,
                "reasonCodes": [jsonl_error],
            })
            continue

        # Valid object contributes lineage.
        lineage.append({
            "uri": obj["uri"],
            "generation": obj["generation"],
            "crc32c": obj["crc32c"],
            "schemaId": obj["schemaId"],
        })

        # Canonicalize rows.
        for row in rows:
            valid_rows.append({
                "id": row["id"],
                "entity": canonicalize(row["entity"]),
                "eventTime": normalize_time(row["eventTime"]),
                "revision": row["revision"],
                "text": canonicalize(row["text"]),
            })

    # ========================================================
    # Deduplication
    # ========================================================

    groups = {}

    for row in valid_rows:
        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(key, []).append(row)

    retained = []

    for candidates in groups.values():

        candidates.sort(
            key=lambda r: (
                -r["revision"],
                utf8(r["id"]),
            )
        )

        winner = candidates[0]
        retained.append(winner)

        for loser in candidates[1:]:
            rejected_rows.append({
                "id": loser["id"],
                "reasonCodes": ["DUPLICATE"],
            })

    # ========================================================
    # Policy / time window
    # ========================================================

    eligible = []

    for row in retained:

        if not policy_valid:
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["POLICY_INVALID"],
            })
            continue

        dt = parse_time(row["eventTime"])

        if dt < min_time or dt > max_time:
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["OUT_OF_WINDOW"],
            })
            continue

        eligible.append(row)

    # ========================================================
    # Deterministic split
    # ========================================================

    train_rows = []
    validation_rows = []
    test_rows = []

    for row in eligible:

        first_byte = hashlib.sha256(
            row["entity"].encode("utf-8")
        ).digest()[0]

        bucket = first_byte % 10

        if bucket <= 5:
            train_rows.append(row)
        elif bucket <= 7:
            validation_rows.append(row)
        else:
            test_rows.append(row)

    # ========================================================
    # Train contamination
    # ========================================================

    train_sets = [
        word_set(row["text"])
        for row in train_rows
    ]

    def contaminated(row):
        candidate = word_set(row["text"])

        for train_set in train_sets:
            if jaccard(candidate, train_set) >= threshold:
                return True

        return False

    final_validation = []

    for row in validation_rows:
        if contaminated(row):
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["TRAIN_CONTAMINATION"],
            })
        else:
            final_validation.append(row)

    final_test = []

    for row in test_rows:
        if contaminated(row):
            rejected_rows.append({
                "id": row["id"],
                "reasonCodes": ["TRAIN_CONTAMINATION"],
            })
        else:
            final_test.append(row)

    # ========================================================
    # Merge rejected row reasons by ID
    # ========================================================

    # A row can independently receive more than one applicable
    # reason. Keep deterministic one-record-per-ID output.
    merged = {}

    for item in rejected_rows:
        rid = item["id"]

        if rid not in merged:
            merged[rid] = set()

        merged[rid].update(item["reasonCodes"])

    rejected_rows = [
        {
            "id": rid,
            "reasonCodes": sorted_reason_codes(reasons),
        }
        for rid, reasons in merged.items()
    ]

    rejected_rows.sort(
        key=rejected_row_sort_key
    )

    # ========================================================
    # Deterministic split serialization
    # ========================================================

    train_public, train_bytes = serialize_rows(train_rows)
    validation_public, validation_bytes = serialize_rows(
        final_validation
    )
    test_public, test_bytes = serialize_rows(test_rows=final_test)

    # SHA-256 of exact UTF-8 JSONL bytes.
    train_digest = hashlib.sha256(train_bytes).hexdigest()
    validation_digest = hashlib.sha256(
        validation_bytes
    ).hexdigest()
    test_digest = hashlib.sha256(test_bytes).hexdigest()

    # ========================================================
    # Sort object rejections
    # ========================================================

    for item in rejected_objects:
        item["reasonCodes"] = sorted_reason_codes(
            item["reasonCodes"]
        )

    rejected_objects.sort(
        key=rejected_object_sort_key
    )

    # ========================================================
    # Sort lineage
    # ========================================================

    lineage.sort(
        key=lineage_sort_key
    )

    # ========================================================
    # Exact response shape
    # ========================================================

    response = {
        "splits": {
            "train": [
                public_row(row)
                for row in train_public
            ],
            "validation": [
                public_row(row)
                for row in validation_public
            ],
            "test": [
                public_row(row)
                for row in test_public
            ],
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": rejected_rows,
        "digests": {
            "train": train_digest,
            "validation": validation_digest,
            "test": test_digest,
        },
        "lineage": lineage,
    }

    return jsonify(response)


# ============================================================
# Health endpoint
# ============================================================

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
