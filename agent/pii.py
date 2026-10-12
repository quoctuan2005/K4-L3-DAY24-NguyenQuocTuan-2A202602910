"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Nhận diện và làm sạch PII tiếng Việt: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_STK_PREFIX_RE = re.compile(
    r"(?:STK|số\s+tài\s+khoản|tài\s+khoản(?:\s+ngân\s+hàng)?)\s*(?:là|:|\s)\s*(\d{8,16})\b",
    re.IGNORECASE,
)
_CCCD_PREFIX_RE = re.compile(
    r"(?:CCCD|căn\s+cước(?:\s+công\s+dân)?)\s*(?:là|:|\s)\s*(\d{12})\b",
    re.IGNORECASE,
)
_CCCD_COLON_RE = re.compile(r":\s*(\d{12})\b")
_PHONE_PREFIX_RE = re.compile(
    r"(?:SĐT|số\s+điện\s+thoại|điện\s+thoại(?:\s+liên\s+hệ)?)\s*(?:là|:|\s)\s*(0\d{9})\b",
    re.IGNORECASE,
)
_PHONE_STANDALONE_RE = re.compile(r"\b(0\d{9})\b")
_CCCD_STANDALONE_RE = re.compile(r"\b(\d{12})\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản.

    Trả về danh sách dict: {"type": str, "start": int, "end": int}
    """
    entities: list[dict] = []
    occupied: set[int] = set()

    def _add_entity(ent_type: str, start: int, end: int) -> None:
        if not any(i in occupied for i in range(start, end)):
            entities.append({"type": ent_type, "start": start, "end": end})
            for i in range(start, end):
                occupied.add(i)

    # 1. EMAIL
    for m in _EMAIL_RE.finditer(text):
        _add_entity("EMAIL", m.start(), m.end())

    # 2. VN_BANK_ACCOUNT (STK đi kèm tiền tố)
    for m in _STK_PREFIX_RE.finditer(text):
        _add_entity("VN_BANK_ACCOUNT", m.start(1), m.end(1))

    # 3. VN_CCCD có tiền tố CCCD hoặc dấu :
    for m in _CCCD_PREFIX_RE.finditer(text):
        _add_entity("VN_CCCD", m.start(1), m.end(1))

    for m in _CCCD_COLON_RE.finditer(text):
        _add_entity("VN_CCCD", m.start(1), m.end(1))

    # 4. VN_PHONE có tiền tố
    for m in _PHONE_PREFIX_RE.finditer(text):
        _add_entity("VN_PHONE", m.start(1), m.end(1))

    # 5. VN_PHONE dạng số điện thoại 10 chữ số bắt đầu bằng 0
    for m in _PHONE_STANDALONE_RE.finditer(text):
        _add_entity("VN_PHONE", m.start(1), m.end(1))

    # 6. VN_CCCD dạng 12 chữ số chưa bị chiếm
    for m in _CCCD_STANDALONE_RE.finditer(text):
        _add_entity("VN_CCCD", m.start(1), m.end(1))

    return sorted(entities, key=lambda x: x["start"])


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII tìm thấy bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    res = text
    # Thay thế từ cuối về đầu để không làm lệch offset
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        tag = f"[REDACTED_{ent['type']}]"
        res = res[: ent["start"]] + tag + res[ent["end"] :]
    return res
