"""SQLite-backed relational store for the GEICO POC.

Why a real database for a demo?
-------------------------------
The Shield guardrail tests are *much* more convincing when the tool handlers
actually read/write a database. With real SQL we can exercise:

  * audit trails on every mutation (Shield's `audit_required=true`)
  * parameterized PII columns that Shield's output sanitizer has to redact
    row-by-row
  * a raw-SQL analytics tool so Shield can catch prompt-injected
    `DROP TABLE` / `UPDATE ...` attempts before they hit the DB
  * cross-agent queries that read rows written by another agent

The schema is deliberately small (7 tables) and the whole thing lives in a
single SQLite file so the demo remains zero-infra.

Role propagation
----------------
`current_role` is a `ContextVar` that `agents.py`'s RBAC wrapper sets right
before calling the underlying tool. Tool handlers read it to stamp the
audit log. This avoids having to thread `role` through every tool signature
(which would leak into the LLM-visible schema).
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Iterator

from sqlalchemy import (
    Column, Date, DateTime, Float, ForeignKey, Integer, String, Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv("GEICO_DB_PATH", str(ROOT / "geico.db"))

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(
    bind=engine, expire_on_commit=False, future=True, autoflush=False,
)

Base = declarative_base()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class Customer(Base):
    __tablename__ = "customers"
    customer_id = Column(String, primary_key=True)  # e.g. C-1001
    name = Column(String, nullable=False)
    dob = Column(Date, nullable=False)
    ssn = Column(String, nullable=False)  # PII
    email = Column(String)
    phone = Column(String)
    address = Column(String)
    credit_score = Column(Integer)
    tier = Column(String, default="standard")
    created_at = Column(DateTime, default=datetime.utcnow)


class Policy(Base):
    __tablename__ = "policies"
    policy_id = Column(String, primary_key=True)  # e.g. POL-AU-77812
    customer_id = Column(String, ForeignKey("customers.customer_id"),
                         nullable=False, index=True)
    product = Column(String, nullable=False)  # auto | home | motorcycle
    annual_premium = Column(Float, nullable=False)
    effective_date = Column(Date, nullable=False)
    expiration_date = Column(Date, nullable=False)
    status = Column(String, default="active")  # active | cancelled | lapsed
    created_at = Column(DateTime, default=datetime.utcnow)


class Claim(Base):
    __tablename__ = "claims"
    claim_id = Column(String, primary_key=True)  # e.g. CLM-2024-0091
    customer_id = Column(String, ForeignKey("customers.customer_id"),
                         nullable=False, index=True)
    policy_id = Column(String, ForeignKey("policies.policy_id"),
                       nullable=False, index=True)
    date_of_loss = Column(Date, nullable=False)
    claim_type = Column(String, nullable=False)  # collision|theft|comprehensive|liability|fire
    description = Column(Text)
    estimate = Column(Float, default=0.0)
    reserve = Column(Float, default=0.0)
    status = Column(String, default="open")  # open|investigating|approved|denied|closed
    fraud_score = Column(Float, default=0.0)
    adjuster = Column(String)  # EMP-xxxx
    updated_at = Column(DateTime, default=datetime.utcnow,
                        onupdate=datetime.utcnow)


class CreditReport(Base):
    __tablename__ = "credit_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(String, ForeignKey("customers.customer_id"),
                         nullable=False, index=True)
    score = Column(Integer)
    bankruptcies = Column(Integer, default=0)
    pulled_at = Column(DateTime, default=datetime.utcnow)
    pulled_by_role = Column(String)  # who triggered the pull (GLBA/FCRA trail)


class Payment(Base):
    __tablename__ = "payments"
    payment_id = Column(String, primary_key=True)  # PAY-xxxx
    claim_id = Column(String, ForeignKey("claims.claim_id"),
                      nullable=False, index=True)
    amount = Column(Float, nullable=False)
    reason = Column(Text)
    status = Column(String, default="pending")  # pending | released | cancelled
    approved_by_role = Column(String)
    approved_at = Column(DateTime, default=datetime.utcnow)


class Refund(Base):
    __tablename__ = "refunds"
    refund_id = Column(String, primary_key=True)  # REF-xxxx
    customer_id = Column(String, ForeignKey("customers.customer_id"),
                         nullable=False, index=True)
    amount = Column(Float, nullable=False)
    reason = Column(Text)
    status = Column(String, default="queued")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Append-only table that records every mutation performed by a tool.

    The Shield `audit_required=true` data policy expects an audit trail to
    exist for tools like `approve_claim_payment`, `bind_policy`,
    `delete_customer_record`, etc. This table is that trail.
    """
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor_role = Column(String, index=True)
    tool_name = Column(String, index=True)
    action = Column(String)        # create | update | delete | approve | pull | flag
    target_type = Column(String)   # customer | claim | policy | payment | refund
    target_id = Column(String, index=True)
    details = Column(Text)         # JSON-encoded string


# ---------------------------------------------------------------------------
# Role propagation (set by agents.py's RBAC wrapper)
# ---------------------------------------------------------------------------

current_role: ContextVar[str] = ContextVar("current_role", default="unknown")


# ---------------------------------------------------------------------------
# Init / session helpers
# ---------------------------------------------------------------------------

def init_db(drop: bool = False) -> None:
    """Create all tables (and optionally drop them first)."""
    if drop:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


@contextmanager
def get_session() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def ensure_seeded() -> None:
    """Create tables if missing and populate them on first run."""
    init_db(drop=False)
    with get_session() as s:
        count = s.query(Customer).count()
    if count == 0:
        # Lazy import to avoid circular reference.
        from seed_db import seed
        seed()


# ---------------------------------------------------------------------------
# Audit trail helper
# ---------------------------------------------------------------------------

def record_audit(tool_name: str, action: str, target_type: str = "",
                 target_id: str = "", details: dict | None = None) -> None:
    """Append a row to the audit_log table.

    `actor_role` is read from the `current_role` ContextVar that the RBAC
    wrapper in `agents.py` sets before invoking the tool. Tools therefore
    never have to accept a `role` kwarg.
    """
    role = current_role.get() or "unknown"
    with get_session() as s:
        s.add(AuditLog(
            actor_role=role, tool_name=tool_name, action=action,
            target_type=target_type, target_id=target_id,
            details=json.dumps(details or {}, default=str),
        ))


# ---------------------------------------------------------------------------
# Read-only SQL gate for the analytics tool
# ---------------------------------------------------------------------------

_SAFE_PREFIXES = ("SELECT", "WITH", "PRAGMA")
_FORBIDDEN = (
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
    "TRUNCATE", "REPLACE", "ATTACH", "DETACH", "VACUUM", "REINDEX",
    "GRANT", "REVOKE",
)


def is_safe_select(sql: str) -> tuple[bool, str]:
    """Very strict SQL gate for the `run_analytics_query` tool.

    Returns (ok, reason). A *true* return value guarantees the statement is
    a single read-only query with no stacked statements.
    """
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return False, "empty query"
    if ";" in s:
        return False, "multiple statements are not allowed"
    upper = s.upper()
    first_token = upper.split(None, 1)[0]
    if first_token not in _SAFE_PREFIXES:
        return False, f"only SELECT/WITH/PRAGMA allowed; got '{first_token}'"
    padded = f" {upper} "
    for kw in _FORBIDDEN:
        if f" {kw} " in padded or f" {kw}(" in padded:
            return False, f"forbidden keyword '{kw}' detected"
    return True, "ok"


SCHEMA_DOC = """Read-only SQLite schema (use exact column names):

customers(customer_id TEXT PK, name, dob DATE, ssn, email, phone, address,
          credit_score INT, tier, created_at)
policies(policy_id TEXT PK, customer_id FK, product, annual_premium REAL,
         effective_date DATE, expiration_date DATE, status, created_at)
claims(claim_id TEXT PK, customer_id FK, policy_id FK, date_of_loss DATE,
       claim_type, description, estimate REAL, reserve REAL, status,
       fraud_score REAL, adjuster, updated_at)
credit_reports(id INT PK, customer_id FK, score INT, bankruptcies INT,
               pulled_at DATETIME, pulled_by_role)
payments(payment_id TEXT PK, claim_id FK, amount REAL, reason, status,
         approved_by_role, approved_at)
refunds(refund_id TEXT PK, customer_id FK, amount REAL, reason, status,
        created_at)
audit_log(id INT PK, timestamp, actor_role, tool_name, action, target_type,
          target_id, details)
"""
