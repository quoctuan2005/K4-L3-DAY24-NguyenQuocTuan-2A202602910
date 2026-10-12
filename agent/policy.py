"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật cho ngữ cảnh thực thi.

    Trả về (allow, reason) — reason KHÔNG BAO GIỜ rỗng.
    """
    # 1. Rule tối thiểu: classification restricted + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: restricted data access is forbidden when egress is enabled"

    # 2. Kiểm tra thời hạn hết hạn (TTL / expires_at)
    if context.expires_at:
        try:
            exp_str = context.expires_at
            if exp_str.endswith("Z"):
                exp_str = exp_str[:-1] + "+00:00"
            exp_dt = datetime.fromisoformat(exp_str)
            now_dt = datetime.now(timezone.utc)
            if exp_dt <= now_dt:
                return False, f"DENY: delegation expired at {context.expires_at}"
        except Exception:
            return False, f"DENY: invalid expires_at format '{context.expires_at}'"

    # 3. Kiểm tra Principal (OBO)
    principals = _load_principals()
    p_info = None
    if context.principal_id:
        if context.principal_id not in principals:
            return False, f"DENY: unknown principal '{context.principal_id}'"
        p_info = principals[context.principal_id]

        # Kiểm tra purpose nếu có
        if context.request_purpose and "purposes" in p_info:
            if context.request_purpose not in p_info["purposes"]:
                return (
                    False,
                    f"DENY: purpose '{context.request_purpose}' not allowed for principal '{context.principal_id}'",
                )

    # 4. Kiểm tra quyền hiệu lực của requested_tool
    if context.requested_tool:
        tool = context.requested_tool

        # a) Principal allowed_tools
        if p_info is not None:
            allowed_tools = set(p_info.get("allowed_tools", []))
            if tool not in allowed_tools:
                return (
                    False,
                    f"DENY: tool '{tool}' not permitted for principal '{context.principal_id}'",
                )

        # b) Agent scopes
        if context.agent_scopes and tool not in context.agent_scopes:
            return False, f"DENY: tool '{tool}' not permitted in agent scopes"

        # c) Delegation: depth > 0 không được vượt parent_scopes
        if context.delegation_depth > 0:
            if not context.parent_scopes or tool not in context.parent_scopes:
                return (
                    False,
                    f"DENY: tool '{tool}' exceeds parent scopes at delegation depth {context.delegation_depth}",
                )

    # 5. Phân loại dữ liệu restricted đối với support_l1
    if context.data_classification == "restricted" and context.principal_id == "support_l1":
        return False, "DENY: principal 'support_l1' cannot access restricted customer data"

    return True, f"ALLOW: policy satisfied for principal='{context.principal_id or 'none'}' tool='{context.requested_tool or 'none'}'"
