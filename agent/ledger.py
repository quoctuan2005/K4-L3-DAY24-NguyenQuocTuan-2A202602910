"""BƯỚC 3e — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng với chuỗi băm SHA-256 (hash chain).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def _compute_hash(entry_without_hash: dict) -> str:
    """Tính sha256 từ nội dung dict (sort_keys=True, utf-8, ensure_ascii=False)."""
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào ledger và nối chuỗi hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = GENESIS_HASH
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_record = json.loads(lines[-1])
            prev_hash = last_record.get("hash", GENESIS_HASH)

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của ledger theo chuỗi hash."""
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = GENESIS_HASH
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        reason = record.get("reason")
        if not reason or not str(reason).strip():
            return False

        if record.get("prev_hash") != expected_prev:
            return False

        stored_hash = record.get("hash")
        record_without_hash = {k: v for k, v in record.items() if k != "hash"}
        if _compute_hash(record_without_hash) != stored_hash:
            return False

        expected_prev = stored_hash

    return True
