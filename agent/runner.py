"""BƯỚC 3c & 3d — trifecta split + egress allowlist + OBO enforcement.

Tách luồng xử lý thành 2 Run riêng biệt:
- Run A: Đọc untrusted content (search_docs). Không gọi read_customer, không gọi http_post.
  Chỉ trích xuất typed ticket IDs từ tên file (ví dụ "ticket-007.md" -> 7).
- Run B: Truy cập private data (read_customer). Tra cứu customer_id từ related_tickets
  trong data/customers.json. Chặn mọi truy cập trái quyền (OBO).
  Chặn mọi hành vi egress (http_post) khi xử lý dữ liệu restricted.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_PATH = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Giữ nguyên class này để tương thích với test_scaffold_dispatch."""


def handle(
    message: str,
    llm,
    log_dir: Path | str | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua Trifecta Split và OBO PEP."""
    log_dir_path = Path(log_dir) if log_dir else REPORTS_DIR
    ledger_path = log_dir_path / "ledger.jsonl"

    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(hours=1)).isoformat()
    run_a_id = f"run-a-{uuid.uuid4().hex[:8]}"
    run_b_id = f"run-b-{uuid.uuid4().hex[:8]}"

    # ==========================================
    # RUN A: UNTRUSTED CONTENT (search_docs)
    # ==========================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": run_a_id,
            "tool": "search_docs",
            "args_hash": hashlib.sha256(message.encode("utf-8")).hexdigest()[:16],
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    docs = []
    if allow_search:
        docs = tools.search_docs(message)

    # Trích xuất typed ticket IDs từ TÊN FILE (tuyệt đối không lấy từ free text)
    ticket_ids: list[int] = []
    for doc in docs:
        file_name = doc.get("id", "")
        for match in re.findall(r"ticket-(\d+)", file_name):
            ticket_ids.append(int(match))
    ticket_ids = sorted(set(ticket_ids))

    # Phát hiện chỉ thị injection (chỉ phân tích trong Run A)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # ==========================================
    # RUN B: PRIVATE DATA & EGRESS CONTROL
    # ==========================================
    customers = []
    if CUSTOMERS_PATH.exists():
        customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))

    # Map ticket_id sang customer_id thông qua nguồn tin cậy related_tickets
    target_customers: list[str] = []
    for cust in customers:
        related = cust.get("related_tickets", [])
        if any(tid in ticket_ids for tid in related):
            target_customers.append(cust["customer_id"])

    collected_records: list[dict] = []
    for cid in target_customers:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "tool": "read_customer",
                "args_hash": hashlib.sha256(cid.encode("utf-8")).hexdigest()[:16],
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_read:
            try:
                rec = tools.read_customer(cid)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # Nếu kẻ tấn công cố tình yêu cầu POST dữ liệu ra sink (egress)
    if injected is not None:
        target_url = injected.target_url
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "tool": "http_post",
                "args_hash": hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:16],
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)
