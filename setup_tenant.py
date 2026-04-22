"""Provision the `geico-poc` tenant on the configured Shield deployment.

Run once before `python app.py`. Reads config from `.env`:

    SHIELD_ADMIN_KEY  - admin key with X-Admin-Key privileges
    LLM_SHIELD_URL    - base URL of the Shield deployment
    TENANT_ID         - target tenant id (default: geico-poc)
    TENANT_API_KEY    - existing key to reuse; if empty a new one is minted

On success the script writes `TENANT_API_KEY` back into `.env` so subsequent
scripts just work without the user having to copy/paste it.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name, default)
    if v is None:
        return ""
    return v.strip()


def _write_env(key: str, value: str) -> None:
    env_path = ROOT / ".env"
    if not env_path.exists():
        env_path.write_text(f"{key}={value}\n", encoding="utf-8")
        return
    lines = env_path.read_text(encoding="utf-8").splitlines()
    out = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}="):
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={value}")
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Sanitization rule library
# ---------------------------------------------------------------------------
# These patterns are the foundation of every tool's data policy. They map the
# sensitive data classes present across insurance workflows to redaction
# replacements that are safe to surface to the LLM. They align with the
# JSON schema expected by POST /v1/data-policies/tools/{tool}/policy:
#
#   {"pattern_id": str, "regex": str, "replacement": str,
#    "description": str, "severity": "low|medium|high|critical",
#    "enabled": bool}
#
# Reused via the `_san(*ids)` helper below so each tool only declares the
# patterns relevant to its payload.
SAN_LIB: dict[str, dict] = {
    "ssn": {
        "pattern_id": "ssn",
        "regex": r"\b\d{3}-?\d{2}-?\d{4}\b",
        "replacement": "[SSN_REDACTED]",
        "description": "US Social Security Number",
        "severity": "critical",
        "enabled": True,
    },
    "credit_card": {
        "pattern_id": "credit_card",
        "regex": r"\b(?:\d[ -]*?){13,16}\b",
        "replacement": "[CC_REDACTED]",
        "description": "Credit card number (13-16 digits, any spacing)",
        "severity": "critical",
        "enabled": True,
    },
    "bank_account": {
        "pattern_id": "bank_account",
        "regex": r"\b\d{9,17}\b",
        "replacement": "[ACCOUNT_REDACTED]",
        "description": "Bank account / routing number",
        "severity": "high",
        "enabled": True,
    },
    "dob": {
        "pattern_id": "date_of_birth",
        "regex": r"\b(0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b",
        "replacement": "[DOB_REDACTED]",
        "description": "Date of birth (US formats)",
        "severity": "high",
        "enabled": True,
    },
    "phone": {
        "pattern_id": "phone",
        "regex": r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b",
        "replacement": "[PHONE_REDACTED]",
        "description": "US phone number",
        "severity": "medium",
        "enabled": True,
    },
    "email": {
        "pattern_id": "email",
        "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "replacement": "[EMAIL_REDACTED]",
        "description": "Email address",
        "severity": "medium",
        "enabled": True,
    },
    "vin": {
        "pattern_id": "vin",
        "regex": r"\b[A-HJ-NPR-Z0-9]{17}\b",
        "replacement": "[VIN_REDACTED]",
        "description": "Vehicle Identification Number (17 chars, excluding I/O/Q)",
        "severity": "medium",
        "enabled": True,
    },
    "drivers_license": {
        "pattern_id": "drivers_license",
        "regex": r"\bDL[- ]?[A-Z0-9]{6,12}\b",
        "replacement": "[DL_REDACTED]",
        "description": "Driver's license number",
        "severity": "high",
        "enabled": True,
    },
    "policy_number": {
        "pattern_id": "policy_number",
        "regex": r"\b(?:POL|POLICY)[- ]?\d{4,}\b",
        "replacement": "[POLICY_REDACTED]",
        "description": "Internal policy number",
        "severity": "low",
        "enabled": True,
    },
}


def _san(*ids: str) -> list[dict]:
    """Return a list of sanitization rules by id from SAN_LIB."""
    return [SAN_LIB[i] for i in ids]


# ---------------------------------------------------------------------------
# Tool policy matrix
# ---------------------------------------------------------------------------
# Each tool gets two records:
#
#   * role_restrictions  -> {role: {"input": allow|deny|require_approval,
#                                   "output": allow|deny|redact}}
#                          consumed by PUT /v1/agents/tools/policies
#
#   * data_policy        -> compliance_framework + audit_required +
#                           sanitization_rules + role_policies with
#                           data_scope/redaction_level
#                          consumed by POST /v1/data-policies/tools/{tool}/policy
#
# Roles: customer, adjuster, underwriter, fraud_investigator, manager

_R = ["customer", "adjuster", "underwriter", "fraud_investigator", "manager"]


# The Shield tool-policy schema (routes_agent_policy.ToolPolicy) models
# role_restrictions as Dict[str, str] with values in {allow, block, redact,
# mask}. We keep our source-of-truth matrix as input/output pairs so the
# tenant portal can still render them richly, and flatten to a single verb
# just before PUT.
def _rr(**by_role) -> dict:
    """Build a role_restrictions dict {role: {"input": verb, "output": verb}}.

    Omitted roles default to block/block. Shorthand "allow/redact" expands
    to {"input":"allow","output":"redact"}. Accepted verbs per Shield:
    ``allow``, ``block``, ``redact``, ``mask`` — plus ``require_approval``
    on the input axis (we map that to ``allow`` when flattening).
    """
    default = {"input": "block", "output": "block"}
    out = {r: dict(default) for r in _R}
    for role, spec in by_role.items():
        inp, outp = spec.split("/", 1)
        out[role] = {"input": inp.strip(), "output": outp.strip()}
    return out


def _flatten_rr(rr: dict) -> dict[str, str]:
    """Collapse {role: {input, output}} -> {role: verb} for the Pydantic
    schema. Rules:
      - input == block                -> "block"
      - input == deny                 -> "block"  (legacy alias)
      - output in {redact, mask}      -> that verb
      - input == require_approval     -> "allow"  (approval handled by
        role_policies.input_rules downstream)
      - otherwise                     -> "allow"
    """
    out = {}
    for role, spec in rr.items():
        inp = (spec.get("input") or "allow").lower()
        outp = (spec.get("output") or "allow").lower()
        if inp in ("block", "deny"):
            out[role] = "block"
        elif outp in ("redact", "mask"):
            out[role] = outp
        else:
            out[role] = "allow"
    return out


def _rp(role: str, action: str, *, scope: list[str] | None = None,
        redaction: str = "none",
        input_rules: list[str] | None = None,
        output_rules: list[str] | None = None) -> dict:
    """One entry of the `role_policies` array for a data policy.

    Shield's RoleDataPolicy.action accepts {allow, redact, block, mask}.
    We accept ``deny`` as a shorthand and normalise to ``block``.
    """
    if action == "deny":
        action = "block"
    return {
        "role": role,
        "action": action,
        "data_scope": scope or [],
        "redaction_level": redaction,
        "input_rules": input_rules or [],
        "output_rules": output_rules or [],
    }


def _build_tool_policies() -> tuple[dict, dict]:
    """Return (tool_policies, data_policies) maps keyed by tool_name."""

    tool_policies: dict[str, dict] = {}
    data_policies: dict[str, dict] = {}

    def add(tool_name: str, *,
            compliance: str | None,
            audit: bool,
            retention_days: int | None,
            san_ids: list[str],
            role_restrictions: dict,
            role_policies: list[dict]):
        # Lightweight policy used by Tools & Role Access tab.
        # `data_sanitization` mirrors the pattern set so the tab shows a
        # pattern count > 0.
        tool_policies[tool_name] = {
            "role_restrictions": role_restrictions,
            "data_sanitization": {
                "patterns": [p["pattern_id"] for p in _san(*san_ids)],
            },
        }
        # Rich policy used by Data Policies tab.
        data_policies[tool_name] = {
            "tool_name": tool_name,
            "compliance_framework": compliance,
            "audit_required": audit,
            "retention_days": retention_days,
            "sanitization_rules": _san(*san_ids),
            "role_policies": role_policies,
        }

    # ---- Read-only / low-sensitivity tools ---------------------------------

    add("search_policy_docs",
        compliance=None, audit=False, retention_days=30, san_ids=[],
        role_restrictions=_rr(
            customer="allow/allow", adjuster="allow/allow",
            underwriter="allow/allow", fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "allow", scope=["public_docs"]),
            _rp("adjuster", "allow", scope=["public_docs"]),
            _rp("underwriter", "allow", scope=["public_docs"]),
            _rp("fraud_investigator", "allow", scope=["public_docs"]),
            _rp("manager", "allow", scope=["public_docs"]),
        ])

    add("quote_estimate",
        compliance=None, audit=True, retention_days=90, san_ids=[],
        role_restrictions=_rr(
            customer="allow/allow", adjuster="allow/allow",
            underwriter="allow/allow", fraud_investigator="deny/deny",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "allow", scope=["quote_inputs", "price"]),
            _rp("adjuster", "allow", scope=["quote_inputs", "price"]),
            _rp("underwriter", "allow", scope=["quote_inputs", "price", "risk"]),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["quote_inputs", "price", "risk"]),
        ])

    # ---- PII-bearing read tools -------------------------------------------

    add("lookup_customer",
        compliance="glba", audit=True, retention_days=365,
        san_ids=["ssn", "dob", "phone", "email"],
        role_restrictions=_rr(
            customer="allow/redact",
            adjuster="allow/allow",
            underwriter="allow/allow",
            fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "redact",
                scope=["name", "policy_list"], redaction="full",
                output_rules=["redact all PII columns except first name"]),
            _rp("adjuster", "allow",
                scope=["name", "contact", "policy_list"], redaction="partial"),
            _rp("underwriter", "allow",
                scope=["name", "contact", "policy_list", "risk_profile"],
                redaction="partial"),
            _rp("fraud_investigator", "allow",
                scope=["name", "contact", "policy_list", "claim_history"],
                redaction="none"),
            _rp("manager", "allow",
                scope=["*"], redaction="none"),
        ])

    add("pull_credit_report",
        compliance="glba", audit=True, retention_days=2555,  # 7 years
        san_ids=["ssn", "dob", "credit_card", "bank_account"],
        role_restrictions=_rr(
            underwriter="allow/allow",
            fraud_investigator="allow/allow",
            manager="allow/allow",
            # adjuster + customer intentionally denied
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "deny"),
            _rp("underwriter", "allow",
                scope=["credit_score", "trade_lines", "public_records"],
                redaction="partial",
                input_rules=["requires legitimate underwriting purpose"]),
            _rp("fraud_investigator", "allow",
                scope=["credit_score", "trade_lines", "public_records",
                       "ssn_verification"],
                redaction="none"),
            _rp("manager", "allow", scope=["*"], redaction="none"),
        ])

    add("get_claim",
        compliance="glba", audit=True, retention_days=2555,
        san_ids=["ssn", "vin", "phone", "email", "drivers_license"],
        role_restrictions=_rr(
            customer="allow/redact",
            adjuster="allow/allow",
            underwriter="allow/allow",
            fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "redact",
                scope=["claim_status", "claim_amount"], redaction="partial",
                output_rules=["hide adjuster notes",
                              "hide fraud indicators"]),
            _rp("adjuster", "allow",
                scope=["claim_status", "claim_amount", "notes"],
                redaction="partial"),
            _rp("underwriter", "allow",
                scope=["claim_status", "claim_amount", "loss_history"]),
            _rp("fraud_investigator", "allow",
                scope=["claim_status", "claim_amount", "notes",
                       "fraud_flags"]),
            _rp("manager", "allow", scope=["*"]),
        ])

    # ---- Mutating / financial tools ---------------------------------------

    add("update_claim_status",
        compliance="sox", audit=True, retention_days=2555, san_ids=[],
        role_restrictions=_rr(
            adjuster="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "allow", scope=["claim_status"],
                input_rules=["must include a notes string"]),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["*"]),
        ])

    add("approve_claim_payment",
        compliance="sox", audit=True, retention_days=2555,
        san_ids=["bank_account"],
        role_restrictions=_rr(
            adjuster="require_approval/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "allow", scope=["payment"],
                input_rules=["amount <= adjuster daily limit",
                             "claim must be in 'approved' status"]),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["payment"]),
        ])

    add("flag_for_fraud_investigation",
        compliance="sox", audit=True, retention_days=2555, san_ids=[],
        role_restrictions=_rr(
            adjuster="allow/allow",
            fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "allow", scope=["fraud_flag"]),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "allow",
                scope=["fraud_flag", "notes"]),
            _rp("manager", "allow", scope=["*"]),
        ])

    add("bind_policy",
        compliance="sox", audit=True, retention_days=2555,
        san_ids=["ssn", "credit_card"],
        role_restrictions=_rr(
            underwriter="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "deny"),
            _rp("underwriter", "allow", scope=["policy_binding"],
                input_rules=["credit score >= 600",
                             "no active cancellation"]),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["*"]),
        ])

    add("cancel_policy",
        compliance="sox", audit=True, retention_days=2555, san_ids=[],
        role_restrictions=_rr(
            underwriter="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "deny"),
            _rp("underwriter", "allow", scope=["policy_cancel"],
                input_rules=["requires documented reason"]),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["*"]),
        ])

    add("issue_refund",
        compliance="sox", audit=True, retention_days=2555,
        san_ids=["bank_account"],
        role_restrictions=_rr(
            adjuster="require_approval/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "allow", scope=["refund"],
                input_rules=["amount <= $2,500 without manager approval"]),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["refund"]),
        ])

    add("delete_customer_record",
        compliance="gdpr", audit=True, retention_days=2555, san_ids=[],
        role_restrictions=_rr(
            manager="require_approval/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "deny"),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "deny"),
            _rp("manager", "allow", scope=["customer_record"],
                input_rules=["requires GDPR deletion ticket id",
                             "requires 2-person approval"]),
        ])

    # ---- Analytics / NL2SQL -----------------------------------------------
    # `run_analytics_query` is the most interesting tool from a guardrails
    # standpoint: the agent writes raw SQL that hits the warehouse. Shield's
    # data policy enforces the read-only contract, tags it for SOX audit,
    # and restricts invocation to analyst-grade roles only.

    add("run_analytics_query",
        compliance="sox", audit=True, retention_days=365,
        san_ids=["ssn", "email", "phone", "dob"],
        role_restrictions=_rr(
            underwriter="allow/redact",
            fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "deny"),
            _rp("underwriter", "allow",
                scope=["aggregates", "policies", "claims_summary"],
                redaction="partial",
                input_rules=[
                    "only SELECT statements allowed",
                    "no raw PII columns (ssn, dob, email) without aggregation",
                ],
                output_rules=["redact SSN/DOB/email if leaked into result"]),
            _rp("fraud_investigator", "allow",
                scope=["aggregates", "policies", "claims", "audit_log"],
                redaction="none",
                input_rules=["only SELECT/WITH statements allowed",
                             "justify query with case id"]),
            _rp("manager", "allow",
                scope=["*"], redaction="none",
                input_rules=["only SELECT/WITH statements allowed"]),
        ])

    # ---- Delegation tools --------------------------------------------------

    add("delegate_to_claims_agent",
        compliance=None, audit=True, retention_days=90, san_ids=[],
        role_restrictions=_rr(
            customer="allow/allow", adjuster="allow/allow",
            underwriter="allow/allow", fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[_rp(r, "allow", scope=["delegation"]) for r in _R])

    add("delegate_to_underwriting_agent",
        compliance=None, audit=True, retention_days=90, san_ids=[],
        role_restrictions=_rr(
            customer="allow/allow", adjuster="allow/allow",
            underwriter="allow/allow", fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[_rp(r, "allow", scope=["delegation"]) for r in _R])

    add("delegate_to_fraud_agent",
        compliance=None, audit=True, retention_days=90, san_ids=[],
        role_restrictions=_rr(
            adjuster="allow/allow",
            fraud_investigator="allow/allow",
            manager="allow/allow",
        ),
        role_policies=[
            _rp("customer", "deny"),
            _rp("adjuster", "allow", scope=["delegation"]),
            _rp("underwriter", "deny"),
            _rp("fraud_investigator", "allow", scope=["delegation"]),
            _rp("manager", "allow", scope=["delegation"]),
        ])

    return tool_policies, data_policies


def _build_guardrail_config() -> dict:
    """Return the input/output guardrail bundle used for the GEICO tenant.

    Strict posture: every guardrail uses `action: "block"` so the GEICO
    security team can demo true deny behaviour end-to-end. A few of the
    enforcement layers (pii_detection, role_redaction) *also* return a
    sanitized string when they fire; our `shield_client.check_output()`
    will surface that sanitized text even when action=block so the UI
    shows an inline redacted reply rather than a generic "blocked"
    placeholder.
    """
    return {
        "input_guardrails": {
            "keyword_blocklist": {
                "enabled": True, "action": "block",
                "settings": {"keywords": [
                    "Progressive", "Allstate", "State Farm", "Liberty Mutual",
                    "Farmers Insurance", "Nationwide Insurance",
                    "USAA", "Travelers Insurance",
                ]},
            },
            # Block any user prompt that contains raw PII so it never enters
            # our logs, prompt, or LLM context window.
            "pii_detection":         {"enabled": True, "action": "block"},
            "adversarial_detection": {"enabled": True, "action": "block"},
            "topic_enforcement": {
                # Set to `block` at the integrator's request — this is the
                # production-correct posture. Known caveat (DEF-005): the
                # LLM topic classifier false-positives on core insurance
                # vocabulary ("claims", "insurance", "underwriting") even
                # when those match `system_purpose`, because the
                # confidence-weighted `overall_allowed` logic collapses to
                # false whenever `allowed_topics` is empty. Expect some
                # legitimate prompts to be blocked at the input stage
                # until the classifier is retuned server-side; this is
                # evidence for DEF-005, not a regression in the app.
                "enabled": True, "action": "block",
                "settings": {
                    "blocked_topics": [
                        "medical advice", "legal advice",
                        "cryptocurrency", "stock trading",
                        "creative writing", "poetry", "fiction",
                        "weapons", "self-harm", "adult content",
                        "religion", "politics",
                    ],
                    "system_purpose": "GEICO customer service and insurance operations (auto, home, motorcycle, claims, fraud, underwriting, analytics)",
                    "confidence_threshold": 0.8,
                },
            },
            "length_limit": {"enabled": True, "action": "block",
                             "settings": {"max_chars": 4000}},
            "rate_limiter": {"enabled": True, "action": "block",
                             "settings": {"requests_per_minute": 60}},
        },
        "output_guardrails": {
            "pii_detection":      {"enabled": True, "action": "block"},
            "role_redaction":     {"enabled": True, "action": "block"},
            "hallucinated_links": {"enabled": True, "action": "block"},
            "bias_detection":     {"enabled": True, "action": "block"},
        },
    }


# ---------------------------------------------------------------------------
# Tenant-level RBAC (Shield's `rbac` config block)
# ---------------------------------------------------------------------------
# This is different from the per-agent `role_permissions` we push via
# `/v1/agents/registry`. The registry permissions say "what can user_role X
# call on agent Y". Shield's tenant-level `rbac` instead answers:
#
#   "When agent Y runs, what is its intrinsic clearance level?"
#
# The clearance level is consumed by the `role_redaction` output guardrail,
# which compares the sensitivity of the reply to the running agent's
# clearance and redacts anything above its tier.
#
# We define a one-to-one mapping: one role per agent, named `<agent>_tier`.
# `data_clearance` uses Shield's 4-step scale: public < internal <
# confidential < restricted.

def _build_rbac_config() -> dict:
    """Map each GEICO agent to an RBAC role (tier) with an appropriate
    clearance level and tool whitelist.
    """
    from agents import AGENTS, SUPERVISOR

    tiers: dict[str, dict] = {
        # Public-facing; only sees safe, non-PII content.
        "intake-agent": {
            "role_name": "customer_tier",
            "data_clearance": "public",
            "rate_limit": "120/min",
            "max_tokens_per_request": 4096,
            "allowed_data_scopes": ["public_docs", "quote_inputs", "price"],
        },
        # Internal; can see claim notes and adjuster payment data.
        "claims-agent": {
            "role_name": "adjuster_tier",
            "data_clearance": "internal",
            "rate_limit": "200/min",
            "max_tokens_per_request": 4096,
            "allowed_data_scopes": [
                "public_docs", "claim_status", "claim_amount", "notes",
                "fraud_flag", "payment",
            ],
        },
        # Confidential; sees credit reports and writes policies.
        "underwriting-agent": {
            "role_name": "underwriter_tier",
            "data_clearance": "confidential",
            "rate_limit": "200/min",
            "max_tokens_per_request": 6144,
            "allowed_data_scopes": [
                "public_docs", "name", "contact", "policy_list",
                "risk_profile", "credit_score", "trade_lines",
                "public_records", "policy_binding", "policy_cancel",
                "aggregates", "quote_inputs", "price", "risk",
            ],
        },
        # Restricted; sees everything, can delete customers.
        "fraud-agent": {
            "role_name": "fraud_tier",
            "data_clearance": "restricted",
            "rate_limit": "180/min",
            "max_tokens_per_request": 6144,
            "allowed_data_scopes": [
                "*", "fraud_flag", "notes", "claim_history",
                "ssn_verification", "audit_log",
            ],
        },
        # Internal; only routes (no direct data reads).
        "supervisor-agent": {
            "role_name": "supervisor_tier",
            "data_clearance": "internal",
            "rate_limit": "300/min",
            "max_tokens_per_request": 8192,
            "allowed_data_scopes": ["delegation"],
        },
    }

    all_defs = {a.agent_id: a for a in list(AGENTS.values()) + [SUPERVISOR]}

    roles: dict[str, dict] = {}
    agent_map: dict[str, str] = {}
    for agent_id, tier in tiers.items():
        ad = all_defs.get(agent_id)
        if not ad:
            continue
        role_name = tier["role_name"]
        roles[role_name] = {
            "name": role_name,
            "allowed_tools": list(ad.tool_names),
            "denied_tools": [],
            "max_tokens_per_request": tier["max_tokens_per_request"],
            "rate_limit": tier["rate_limit"],
            "data_clearance": tier["data_clearance"],
            "allowed_data_scopes": tier["allowed_data_scopes"],
            "denied_data_scopes": [],
        }
        agent_map[agent_id] = role_name

    return {"roles": roles, "agents": agent_map}


def main() -> int:
    shield_url = _env("LLM_SHIELD_URL").rstrip("/")
    admin_key = _env("SHIELD_ADMIN_KEY")
    tenant_id = _env("TENANT_ID", "geico-poc")
    tenant_key = _env("TENANT_API_KEY")
    runpod_token = _env("RUNPOD_TOKEN")

    if not shield_url:
        print("ERROR: LLM_SHIELD_URL is required in .env")
        return 1
    if not admin_key:
        print("ERROR: SHIELD_ADMIN_KEY is required in .env")
        return 1

    admin_headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}
    if runpod_token:
        admin_headers["Authorization"] = f"Bearer {runpod_token}"

    # 1. Ensure tenant exists -------------------------------------------------
    r = requests.get(f"{shield_url}/v1/admin/tenants/{tenant_id}",
                     headers=admin_headers, timeout=30)

    guardrails = _build_guardrail_config()
    rbac_config = _build_rbac_config()
    print(f"  RBAC tiers: {', '.join(rbac_config['roles'].keys())}")
    print(f"  Agent -> tier map: {rbac_config['agents']}")

    if r.status_code == 404:
        print(f"Creating tenant '{tenant_id}'...")
        if not tenant_key:
            tenant_key = f"sk-geico-{secrets.token_urlsafe(18)}"
        payload = {
            "tenant_id": tenant_id,
            "name": "GEICO Insurance POC",
            "plan": "enterprise",
            "api_keys": [tenant_key],
            "rbac": rbac_config,
            **guardrails,
        }
        r2 = requests.post(f"{shield_url}/v1/admin/tenants",
                           headers=admin_headers, json=payload, timeout=30)
        if r2.status_code >= 300:
            print(f"ERROR: tenant create failed: {r2.status_code} {r2.text}")
            return 1
        print(f"  tenant created: {tenant_id}")
        print(f"  API key: {tenant_key}")
        _write_env("TENANT_API_KEY", tenant_key)
    elif r.status_code == 200:
        print(f"Tenant '{tenant_id}' already exists — updating guardrails + RBAC.")
        update_payload = {**guardrails, "rbac": rbac_config}
        r_upd = requests.put(f"{shield_url}/v1/admin/tenants/{tenant_id}",
                             headers=admin_headers, json=update_payload,
                             timeout=30)
        if r_upd.status_code >= 300:
            print(f"  WARN: tenant update failed: {r_upd.status_code} {r_upd.text}")
        else:
            print("  guardrail + RBAC config updated.")
        if not tenant_key:
            new_key = f"sk-geico-{secrets.token_urlsafe(18)}"
            r3 = requests.post(
                f"{shield_url}/v1/admin/tenants/{tenant_id}/api-keys",
                headers=admin_headers, json={"api_key": new_key}, timeout=30,
            )
            if r3.status_code >= 300:
                print(f"ERROR: could not add API key: {r3.status_code} {r3.text}")
                return 1
            tenant_key = new_key
            print(f"  minted new API key: {tenant_key}")
            _write_env("TENANT_API_KEY", tenant_key)
        else:
            print(f"  reusing existing API key from .env")
    else:
        print(f"ERROR: unexpected status while fetching tenant: {r.status_code} {r.text}")
        return 1

    # 2. Register the agents --------------------------------------------------
    from agents import AGENTS, SUPERVISOR

    tenant_headers = {
        "X-API-Key": tenant_key,
        "Content-Type": "application/json",
    }
    if runpod_token:
        tenant_headers["Authorization"] = f"Bearer {runpod_token}"
    all_defs = list(AGENTS.values()) + [SUPERVISOR]

    for ad in all_defs:
        payload = {
            "agent_id": ad.agent_id,
            "name": ad.name,
            "description": ad.description,
            "tools": ad.tool_names,
            "role_permissions": ad.role_permissions,
        }
        r = requests.post(f"{shield_url}/v1/agents/registry",
                          headers=tenant_headers, json=payload, timeout=30)
        if r.status_code in (200, 201):
            status_label = "ok"
        elif r.status_code == 409:
            # Already registered — update in place.
            ru = requests.put(
                f"{shield_url}/v1/agents/registry/{ad.agent_id}",
                headers=tenant_headers, json=payload, timeout=30,
            )
            status_label = "updated" if ru.status_code < 300 else f"upd-err {ru.status_code}"
            r = ru
        else:
            status_label = "FAIL"
        print(f"  register {ad.agent_id:22s} [{status_label}] status={r.status_code}")
        if r.status_code >= 400:
            try:
                print(f"    body: {r.json()}")
            except Exception:  # noqa: BLE001
                print(f"    body: {r.text}")

    # 3. Push tool policies (role restrictions + data sanitization) ----------
    tool_policies, data_policies = _build_tool_policies()

    # Shape for the strict `/v1/agents/tools/policies` endpoint: outer
    # {"policies": {...}} wrapper, and role_restrictions as a flat
    # {role: verb} dict.
    strict_payload = {"policies": {}}
    for name, pol in tool_policies.items():
        strict_pol = {
            "data_sanitization": pol.get("data_sanitization") or {},
            "role_restrictions": _flatten_rr(pol.get("role_restrictions") or {}),
        }
        if "llm_validation" in pol:
            strict_pol["llm_validation"] = pol["llm_validation"]
        strict_payload["policies"][name] = strict_pol

    print("\nPushing tool policies (Tools & Role Access)...")
    r_tp = requests.put(
        f"{shield_url}/v1/agents/tools/policies",
        headers=tenant_headers, json=strict_payload, timeout=30,
    )
    if r_tp.status_code in (200, 201):
        body = {}
        try:
            body = r_tp.json()
        except Exception:  # noqa: BLE001
            pass
        print(f"  tool policies saved: {len(strict_payload['policies'])} tools "
              f"(success={body.get('success', True)})")
    else:
        print(f"  WARN: tool policies PUT failed: {r_tp.status_code} "
              f"{r_tp.text[:400]}")

    # 4. Push per-tool data policies (Data Policies tab) ---------------------
    print("\nPushing data policies (compliance + sanitization rules)...")
    dp_ok = 0
    dp_fail = 0
    for tool_name, policy in data_policies.items():
        rdp = requests.post(
            f"{shield_url}/v1/data-policies/tools/{tool_name}/policy",
            headers=tenant_headers, json=policy, timeout=30,
        )
        if rdp.status_code in (200, 201):
            dp_ok += 1
            compl = (policy.get("compliance_framework") or "").upper() or "—"
            n_rules = len(policy.get("sanitization_rules") or [])
            n_roles = len(policy.get("role_policies") or [])
            print(f"  data_policy {tool_name:32s} [ok]  compliance={compl:5s} "
                  f"rules={n_rules} roles={n_roles} audit={policy['audit_required']}")
        else:
            dp_fail += 1
            err = ""
            try:
                err = rdp.json().get("detail") or rdp.text
            except Exception:  # noqa: BLE001
                err = rdp.text
            print(f"  data_policy {tool_name:32s} [FAIL] status={rdp.status_code} {err}")
    print(f"  {dp_ok} saved, {dp_fail} failed")

    print("\nSetup complete. You can now run:  python app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
