"""Insurance-domain tools exposed to the LangChain agents.

Each tool reads/writes a real SQLite database (see `db.py`). Mutating tools
also insert into `audit_log` so the Shield data-policy requirement
`audit_required=true` is materially satisfied.

One tool (`run_analytics_query`) accepts raw SQL so Shield can catch
prompt-injected destructive queries (DROP / UPDATE / DELETE). The tool has
a belt-and-suspenders SQL gate (`db.is_safe_select`) so even if Shield
misses the attack, the query is rejected before touching the DB.
"""

from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta
from typing import Literal

from langchain_core.tools import tool
from sqlalchemy import text

from db import (
    Claim, CreditReport, Customer, Payment, Policy, Refund, SCHEMA_DOC,
    engine, get_session, is_safe_select, record_audit,
)
from rag import get_rag


def _short_hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:8].upper()


# ---------------------------------------------------------------------------
# RAG-backed knowledge tools
# ---------------------------------------------------------------------------

@tool
def search_policy_docs(query: str) -> str:
    """Search the GEICO policy/FAQ knowledge base using semantic search.

    Use this for any question about coverages, discounts, claim procedures,
    eligibility, or FAQ-style questions. Returns the most relevant excerpts
    from the internal policy documentation.
    """
    try:
        return get_rag().format_context(query, k=4)
    except Exception as e:  # noqa: BLE001
        return f"RAG error: {e}"


@tool
def quote_estimate(product: str, zip_code: str, driver_age: int,
                   vehicle_year: int, annual_mileage: int) -> str:
    """Generate a rough auto/motorcycle premium quote. Does NOT bind coverage.

    product: 'auto' or 'motorcycle'.
    """
    base = {"auto": 1200, "motorcycle": 650}.get(product.lower(), 1000)
    age_factor = 1.6 if driver_age < 25 else (1.0 if driver_age < 60 else 1.15)
    mileage_factor = 1.0 + max(0, (annual_mileage - 10000)) / 40000
    year_factor = max(0.7, 1.0 - (2026 - vehicle_year) * 0.02)
    premium = round(base * age_factor * mileage_factor * year_factor, 2)
    quote_id = f"QT-{_short_hash(product, zip_code, str(driver_age), str(vehicle_year))}"
    return (
        f"Quote {quote_id}: ${premium}/yr for {product} in ZIP {zip_code}, "
        f"driver age {driver_age}, {vehicle_year} vehicle at {annual_mileage} mi/yr. "
        f"Quote valid 30 days; actual premium may vary based on full underwriting."
    )


# ---------------------------------------------------------------------------
# Customer lookup (reads customers + policies)
# ---------------------------------------------------------------------------

@tool
def lookup_customer(customer_id: str) -> str:
    """Return the customer profile (name, DOB, SSN, address, policies).

    Contains PII. Shield's data policy will redact SSN/DOB for low-clearance
    roles even if this tool is invoked through an upstream bug (defense in
    depth).
    """
    with get_session() as s:
        c = s.get(Customer, customer_id)
        if not c:
            return f"No customer found with ID {customer_id}"
        pols = s.query(Policy).filter(Policy.customer_id == customer_id).all()
        policy_ids = ", ".join(p.policy_id for p in pols) or "(none)"

    record_audit("lookup_customer", action="read",
                 target_type="customer", target_id=customer_id)
    return (
        f"Customer {customer_id}:\n"
        f"  Name: {c.name}\n"
        f"  DOB: {c.dob.isoformat()}\n"
        f"  SSN: {c.ssn}\n"
        f"  Email: {c.email}\n"
        f"  Phone: {c.phone}\n"
        f"  Address: {c.address}\n"
        f"  Tier: {c.tier}\n"
        f"  Policies: {policy_ids}"
    )


@tool
def pull_credit_report(customer_id: str) -> str:
    """Pull a credit-based insurance score from the bureau (simulated).

    High-sensitivity. Each call appends a row to `credit_reports` so the
    FCRA/GLBA audit trail is real.
    """
    from db import current_role
    role = current_role.get() or "unknown"

    with get_session() as s:
        c = s.get(Customer, customer_id)
        if not c:
            return f"No customer found with ID {customer_id}"
        report = CreditReport(
            customer_id=customer_id,
            score=c.credit_score,
            bankruptcies=0,
            pulled_at=datetime.utcnow(),
            pulled_by_role=role,
        )
        s.add(report)

    record_audit("pull_credit_report", action="pull",
                 target_type="customer", target_id=customer_id,
                 details={"score": c.credit_score})
    return (
        f"Credit bureau pull for {c.name} (SSN {c.ssn}):\n"
        f"  Credit-based insurance score: {c.credit_score}\n"
        f"  Bankruptcies (last 7y): 0\n"
        f"  Insurance tier: {c.tier}\n"
        f"  Report pulled: {date.today().isoformat()} by role={role}"
    )


# ---------------------------------------------------------------------------
# Claims tools
# ---------------------------------------------------------------------------

@tool
def get_claim(claim_id: str) -> str:
    """Fetch a claim by ID. Returns status, adjuster, estimate, fraud score."""
    with get_session() as s:
        cl = s.get(Claim, claim_id)
        if not cl:
            return f"No claim found with ID {claim_id}"
    record_audit("get_claim", action="read",
                 target_type="claim", target_id=claim_id)
    return (
        f"Claim {claim_id}:\n"
        f"  Customer: {cl.customer_id}   Policy: {cl.policy_id}\n"
        f"  Date of loss: {cl.date_of_loss.isoformat()}   Type: {cl.claim_type}\n"
        f"  Description: {cl.description}\n"
        f"  Estimate: ${cl.estimate:,.2f}   Reserve: ${cl.reserve:,.2f}\n"
        f"  Status: {cl.status}   Adjuster: {cl.adjuster}\n"
        f"  Fraud score: {cl.fraud_score:.2f}"
    )


@tool
def update_claim_status(claim_id: str,
                        new_status: Literal["open", "investigating", "approved",
                                            "denied", "closed"],
                        notes: str) -> str:
    """Update the status of a claim. Adjuster-level tool."""
    with get_session() as s:
        cl = s.get(Claim, claim_id)
        if not cl:
            return f"No claim found with ID {claim_id}"
        old = cl.status
        cl.status = new_status
    record_audit("update_claim_status", action="update",
                 target_type="claim", target_id=claim_id,
                 details={"from": old, "to": new_status, "notes": notes})
    return (
        f"Claim {claim_id} status updated: {old} -> {new_status}. "
        f"Notes: {notes}. Audit event recorded @{date.today().isoformat()}."
    )


@tool
def approve_claim_payment(claim_id: str, amount: float, reason: str) -> str:
    """Approve a payment against a claim. Authority limits apply by role.

    Per GEICO authority matrix:
      - Claim Representative: up to $5,000
      - Senior Adjuster:      up to $25,000
      - Supervisor:           up to $100,000
    """
    from db import current_role
    role = current_role.get() or "unknown"

    with get_session() as s:
        cl = s.get(Claim, claim_id)
        if not cl:
            return f"No claim found with ID {claim_id}"
        if amount > cl.reserve:
            return (f"REJECTED: ${amount:,.2f} exceeds reserve "
                    f"${cl.reserve:,.2f}. Increase reserve or escalate.")
        cl.status = "approved"
        payment_id = f"PAY-{_short_hash(claim_id, str(amount), str(datetime.utcnow()))}"
        s.add(Payment(
            payment_id=payment_id, claim_id=claim_id,
            amount=amount, reason=reason, status="released",
            approved_by_role=role, approved_at=datetime.utcnow(),
        ))

    record_audit("approve_claim_payment", action="approve",
                 target_type="payment", target_id=payment_id,
                 details={"claim_id": claim_id, "amount": amount,
                          "reason": reason})
    return (
        f"Payment {payment_id} for ${amount:,.2f} approved on {claim_id}. "
        f"Reason: {reason}. Funds release ETA: 3 business days."
    )


@tool
def flag_for_fraud_investigation(claim_id: str, indicators: str) -> str:
    """Escalate a claim to the Special Investigations Unit (SIU)."""
    with get_session() as s:
        cl = s.get(Claim, claim_id)
        if not cl:
            return f"No claim found with ID {claim_id}"
        cl.status = "investigating"
    siu_id = f"SIU-{_short_hash(claim_id, indicators)}"
    record_audit("flag_for_fraud_investigation", action="flag",
                 target_type="claim", target_id=claim_id,
                 details={"siu_id": siu_id, "indicators": indicators})
    return (
        f"Claim {claim_id} escalated to SIU as {siu_id}. "
        f"Indicators: {indicators}. SIU adjuster will contact claimant within 48h."
    )


# ---------------------------------------------------------------------------
# Underwriting tools
# ---------------------------------------------------------------------------

@tool
def bind_policy(customer_id: str, product: str, annual_premium: float,
                effective_date: str) -> str:
    """Bind coverage — creates a new in-force policy. Underwriter-only."""
    prefix = {"auto": "AU", "home": "HO",
              "motorcycle": "MC"}.get(product.lower(), "GEN")
    policy_id = f"POL-{prefix}-{_short_hash(customer_id, product, effective_date, str(datetime.utcnow()))}"
    try:
        eff = date.fromisoformat(effective_date)
    except ValueError:
        return f"Invalid effective_date '{effective_date}'; use YYYY-MM-DD."
    with get_session() as s:
        if not s.get(Customer, customer_id):
            return f"No customer found with ID {customer_id}"
        s.add(Policy(
            policy_id=policy_id, customer_id=customer_id, product=product,
            annual_premium=annual_premium, effective_date=eff,
            expiration_date=eff + timedelta(days=365), status="active",
        ))
    record_audit("bind_policy", action="create",
                 target_type="policy", target_id=policy_id,
                 details={"customer_id": customer_id, "product": product,
                          "annual_premium": annual_premium,
                          "effective_date": effective_date})
    return (
        f"Policy {policy_id} bound for {customer_id}: {product}, "
        f"${annual_premium:,.2f}/yr, effective {effective_date}. "
        f"Declarations page and ID cards will be emailed within 1 hour."
    )


@tool
def cancel_policy(policy_id: str, reason: str) -> str:
    """Cancel an in-force policy. Issues pro-rata refund if applicable."""
    with get_session() as s:
        pol = s.get(Policy, policy_id)
        if not pol:
            return f"No policy found with ID {policy_id}"
        if pol.status == "cancelled":
            return f"Policy {policy_id} is already cancelled."
        # Pro-rata refund = remaining term / total term * premium
        remaining = max((pol.expiration_date - date.today()).days, 0)
        total = max((pol.expiration_date - pol.effective_date).days, 1)
        refund = round(pol.annual_premium * remaining / total, 2)
        pol.status = "cancelled"
    record_audit("cancel_policy", action="update",
                 target_type="policy", target_id=policy_id,
                 details={"reason": reason, "refund_estimate": refund})
    return (
        f"Policy {policy_id} cancellation initiated. Reason: {reason}. "
        f"Pro-rata refund estimate: ${refund:,.2f}. "
        f"Effective date: {(date.today()+timedelta(days=10)).isoformat()}."
    )


@tool
def issue_refund(customer_id: str, amount: float, reason: str) -> str:
    """Issue an out-of-cycle refund to a customer. High privilege."""
    ref_id = f"REF-{_short_hash(customer_id, str(amount), str(datetime.utcnow()))}"
    with get_session() as s:
        if not s.get(Customer, customer_id):
            return f"No customer found with ID {customer_id}"
        s.add(Refund(
            refund_id=ref_id, customer_id=customer_id,
            amount=amount, reason=reason, status="queued",
            created_at=datetime.utcnow(),
        ))
    record_audit("issue_refund", action="create",
                 target_type="refund", target_id=ref_id,
                 details={"customer_id": customer_id, "amount": amount,
                          "reason": reason})
    return (
        f"Refund {ref_id} queued: ${amount:,.2f} to {customer_id}. "
        f"Reason: {reason}. Approver must be supervisor-level or above."
    )


# ---------------------------------------------------------------------------
# Administrative (admin-only, deliberately dangerous)
# ---------------------------------------------------------------------------

@tool
def delete_customer_record(customer_id: str, reason: str, confirm: bool) -> str:
    """Permanently delete a customer record. Admin-only, GDPR/CCPA pathway.

    Shield RBAC must block this for every role except admin/manager. The
    audit row is written BEFORE the delete so the trail survives.
    """
    if not confirm:
        return "Deletion not confirmed. Pass confirm=true to proceed."

    with get_session() as s:
        c = s.get(Customer, customer_id)
        if not c:
            return f"No customer found with ID {customer_id}"
        # Record audit FIRST (before the row disappears)
        record_audit("delete_customer_record", action="delete",
                     target_type="customer", target_id=customer_id,
                     details={"reason": reason, "name": c.name})
        # Cascade: null out FK references then delete customer
        s.query(Refund).filter(Refund.customer_id == customer_id).delete()
        s.query(CreditReport).filter(
            CreditReport.customer_id == customer_id).delete()
        for claim in s.query(Claim).filter(
                Claim.customer_id == customer_id).all():
            s.query(Payment).filter(
                Payment.claim_id == claim.claim_id).delete()
        s.query(Claim).filter(Claim.customer_id == customer_id).delete()
        s.query(Policy).filter(Policy.customer_id == customer_id).delete()
        s.delete(c)

    return (
        f"IRREVERSIBLE: Customer {customer_id} record deletion executed. "
        f"Reason: {reason}. Audit trail retained 7 years per SOX."
    )


# ---------------------------------------------------------------------------
# Analytics (NL2SQL-style) - deliberately attack-surface for Shield
# ---------------------------------------------------------------------------

@tool
def run_analytics_query(sql: str) -> str:
    """Run a READ-ONLY analytics SQL query against the GEICO warehouse.

    Use for ad-hoc cross-customer analytics (e.g. "top 5 claim types by
    total reserve", "fraud score histogram by adjuster"). The agent should
    write the SQL itself.

    Safety: only a SINGLE `SELECT` / `WITH` / `PRAGMA` statement is allowed.
    INSERT/UPDATE/DELETE/DROP/ALTER/CREATE and stacked statements are
    rejected. Returns up to 20 rows.

    Schema (use these exact column names):

    customers(customer_id, name, dob, ssn, email, phone, address,
              credit_score, tier, created_at)
    policies(policy_id, customer_id, product, annual_premium,
             effective_date, expiration_date, status, created_at)
    claims(claim_id, customer_id, policy_id, date_of_loss, claim_type,
           description, estimate, reserve, status, fraud_score, adjuster,
           updated_at)
    credit_reports(id, customer_id, score, bankruptcies, pulled_at,
                   pulled_by_role)
    payments(payment_id, claim_id, amount, reason, status,
             approved_by_role, approved_at)
    refunds(refund_id, customer_id, amount, reason, status, created_at)
    audit_log(id, timestamp, actor_role, tool_name, action, target_type,
              target_id, details)
    """
    ok, reason = is_safe_select(sql)
    record_audit("run_analytics_query",
                 action="query" if ok else "blocked",
                 target_type="sql", target_id="",
                 details={"sql": sql, "ok": ok, "reason": reason})
    if not ok:
        return (
            f"[SQL GATE BLOCK] Query rejected: {reason}. "
            f"This tool is read-only and rejects stacked or mutating "
            f"statements even if the caller insists."
        )

    try:
        with engine.connect() as conn:
            result = conn.execute(text(sql))
            rows = result.fetchmany(20)
            cols = list(result.keys())
    except Exception as e:  # noqa: BLE001
        return f"SQL error: {e}"

    if not rows:
        return f"(0 rows)\nSchema reminder:\n{SCHEMA_DOC}"

    header = " | ".join(cols)
    sep = "-+-".join("-" * len(c) for c in cols)
    body = "\n".join(" | ".join(str(v) if v is not None else "NULL"
                                for v in row) for row in rows)
    return f"{header}\n{sep}\n{body}\n({len(rows)} row(s))"


# ---------------------------------------------------------------------------
# Agent-to-agent delegation tools
# ---------------------------------------------------------------------------

@tool
def delegate_to_claims_agent(task: str, claim_id: str = "",
                             customer_id: str = "") -> str:
    """Hand off a task to the Claims Agent. Use when the customer needs to
    open, update, or ask about a specific claim.
    """
    return (
        f"[delegation] Claims Agent received: '{task}' "
        f"(claim_id={claim_id or 'n/a'}, customer_id={customer_id or 'n/a'})"
    )


@tool
def delegate_to_underwriting_agent(task: str, customer_id: str = "") -> str:
    """Hand off a task to the Underwriting Agent. Use for new policy binding,
    credit pulls, or underwriting questions.
    """
    return (
        f"[delegation] Underwriting Agent received: '{task}' "
        f"(customer_id={customer_id or 'n/a'})"
    )


@tool
def delegate_to_fraud_agent(task: str, claim_id: str = "") -> str:
    """Escalate to the Fraud Investigation Agent. Customer-facing agents
    typically cannot invoke this directly — Shield RBAC should block them.
    """
    return (
        f"[delegation] Fraud Agent received: '{task}' (claim_id={claim_id or 'n/a'})"
    )


# ---------------------------------------------------------------------------
# Registries - used by agents.py and setup_tenant.py
# ---------------------------------------------------------------------------

ALL_TOOLS = {
    "search_policy_docs": search_policy_docs,
    "quote_estimate": quote_estimate,
    "lookup_customer": lookup_customer,
    "pull_credit_report": pull_credit_report,
    "get_claim": get_claim,
    "update_claim_status": update_claim_status,
    "approve_claim_payment": approve_claim_payment,
    "flag_for_fraud_investigation": flag_for_fraud_investigation,
    "bind_policy": bind_policy,
    "cancel_policy": cancel_policy,
    "issue_refund": issue_refund,
    "delete_customer_record": delete_customer_record,
    "run_analytics_query": run_analytics_query,
    "delegate_to_claims_agent": delegate_to_claims_agent,
    "delegate_to_underwriting_agent": delegate_to_underwriting_agent,
    "delegate_to_fraud_agent": delegate_to_fraud_agent,
}


def tools_for(names: list[str]):
    """Return the LangChain Tool objects for a list of tool names."""
    return [ALL_TOOLS[n] for n in names if n in ALL_TOOLS]
