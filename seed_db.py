"""Seed the SQLite DB with synthetic customers, policies, claims, credit
reports, and sample payments/refunds.

Run directly to (re)build the demo dataset:

    python seed_db.py           # seed only if empty
    python seed_db.py --reset   # drop + recreate + seed

The data is deterministic (fixed random seed) so that red-team scripts and
portal audit rows are reproducible across runs.
"""

from __future__ import annotations

import argparse
import hashlib
import random
from datetime import date, datetime, timedelta, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

from db import (
    Claim, CreditReport, Customer, Payment, Policy, Refund,
    get_session, init_db,
)

FIRST = [
    "Alice", "Bob", "Carmen", "Derek", "Elena", "Farouk", "Grace", "Hiro",
    "Isla", "Jamal", "Kira", "Luis", "Maria", "Nate", "Olivia", "Priya",
    "Quentin", "Rosa", "Samir", "Tanya", "Umar", "Vera", "Wes", "Xiomara",
    "Yusuf", "Zara",
]
LAST = [
    "Johnson", "Mendoza", "Lee", "Rodriguez", "Patel", "Nguyen", "Kim",
    "Okafor", "Williams", "Chen", "Garcia", "Fischer", "O'Brien",
    "Jackson", "Singh", "Martinelli", "Dupont", "Haddad", "Schwartz",
    "Anderson", "Brooks", "Campbell", "Diaz", "Evans",
]
STREETS = [
    "Maple Ave", "Oak St", "Ocean Dr", "Elm Way", "Cedar Blvd",
    "Main St", "Hillcrest Rd", "Riverside Dr", "Pine Ln", "Lakeview Ct",
]
CITIES = [
    ("Chevy Chase", "MD", "20815"), ("Miami", "FL", "33139"),
    ("Austin", "TX", "78704"), ("Portland", "OR", "97205"),
    ("Brooklyn", "NY", "11201"), ("Denver", "CO", "80204"),
    ("Atlanta", "GA", "30309"), ("Phoenix", "AZ", "85004"),
    ("Seattle", "WA", "98101"), ("Boston", "MA", "02116"),
]
TIERS = ["standard", "preferred", "preferred-plus"]
PRODUCTS = ["auto", "home", "motorcycle"]
CLAIM_TYPES = {
    "auto": ["collision", "liability", "comprehensive"],
    "home": ["fire", "theft", "water_damage"],
    "motorcycle": ["collision", "comprehensive", "theft"],
}
ADJUSTERS = ["EMP-5521", "EMP-5712", "EMP-5804", "EMP-5910", "EMP-6001"]


def _short_hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:8].upper()


def _mk_dob(rng: random.Random) -> date:
    year = rng.randint(1955, 2003)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    return date(year, month, day)


def _mk_ssn(rng: random.Random) -> str:
    return f"{rng.randint(100, 899):03d}-{rng.randint(10, 99):02d}-{rng.randint(1000, 9999):04d}"


def _mk_phone(rng: random.Random) -> str:
    return f"555-{rng.randint(100, 999):03d}-{rng.randint(1000, 9999):04d}"


def _mk_address(rng: random.Random) -> str:
    num = rng.randint(10, 9999)
    street = rng.choice(STREETS)
    city, state, zip_ = rng.choice(CITIES)
    return f"{num} {street}, {city}, {state} {zip_}"


def seed(n_customers: int = 50) -> dict:
    """Populate the DB with deterministic synthetic data.

    Returns a small summary dict with row counts.
    """
    init_db(drop=False)
    rng = random.Random(42)

    today = date.today()
    customers: list[Customer] = []
    policies: list[Policy] = []
    claims: list[Claim] = []
    credit_reports: list[CreditReport] = []
    payments: list[Payment] = []
    refunds: list[Refund] = []

    with get_session() as s:
        # Purge existing rows (keeps schema, just rebuilds data)
        for cls in (Refund, Payment, Claim, CreditReport, Policy, Customer):
            s.query(cls).delete()

        for i in range(n_customers):
            cid = f"C-{1001 + i}"
            first = rng.choice(FIRST)
            last = rng.choice(LAST)
            credit = rng.randint(540, 830)
            tier = (
                "preferred-plus" if credit >= 780 else
                "preferred" if credit >= 700 else "standard"
            )
            customers.append(Customer(
                customer_id=cid,
                name=f"{first} {last}",
                dob=_mk_dob(rng),
                ssn=_mk_ssn(rng),
                email=f"{first.lower()}.{last.lower().replace(chr(39), '')}"
                      f"@example.com",
                phone=_mk_phone(rng),
                address=_mk_address(rng),
                credit_score=credit,
                tier=tier,
            ))

            # 1-3 policies per customer
            n_pol = rng.choices([1, 2, 3], weights=[4, 4, 2])[0]
            for _ in range(n_pol):
                product = rng.choice(PRODUCTS)
                prefix = {"auto": "AU", "home": "HO",
                          "motorcycle": "MC"}[product]
                pid = f"POL-{prefix}-{_short_hash(cid, product, str(i), str(_))}"
                eff = today - timedelta(days=rng.randint(30, 800))
                exp = eff + timedelta(days=365)
                status = "active" if exp >= today else rng.choice(
                    ["lapsed", "cancelled"])
                premium = {
                    "auto": rng.randint(900, 2400),
                    "home": rng.randint(800, 3000),
                    "motorcycle": rng.randint(400, 1200),
                }[product]
                policies.append(Policy(
                    policy_id=pid, customer_id=cid, product=product,
                    annual_premium=float(premium),
                    effective_date=eff, expiration_date=exp, status=status,
                ))

        # 2nd pass: claims (need policies in place)
        n_claims_target = 40
        policy_pool = [p for p in policies if p.status == "active"]
        for idx in range(n_claims_target):
            pol = rng.choice(policy_pool)
            ctype = rng.choice(CLAIM_TYPES[pol.product])
            dol = today - timedelta(days=rng.randint(5, 300))
            estimate = round(rng.uniform(500, 40000), 2)
            reserve = round(estimate * rng.uniform(1.05, 1.4), 2)
            fraud_score = round(rng.betavariate(1.5, 6), 2)  # skewed low
            # Force a couple of obvious fraud cases for demo purposes
            if idx in (7, 18, 29):
                fraud_score = round(rng.uniform(0.72, 0.94), 2)
            status = rng.choice([
                "open", "open", "investigating", "approved", "denied",
                "closed",
            ])
            claim_id = f"CLM-{dol.year}-{idx + 91:04d}"
            claims.append(Claim(
                claim_id=claim_id,
                customer_id=pol.customer_id,
                policy_id=pol.policy_id,
                date_of_loss=dol,
                claim_type=ctype,
                description=_claim_description(ctype, rng),
                estimate=estimate,
                reserve=reserve,
                status=status,
                fraud_score=fraud_score,
                adjuster=rng.choice(ADJUSTERS),
            ))

        # Historical credit-report pulls (scattered across last 2 years,
        # tagged with pulling role for the FCRA/GLBA trail)
        for _ in range(30):
            cust = rng.choice(customers)
            credit_reports.append(CreditReport(
                customer_id=cust.customer_id,
                score=cust.credit_score + rng.randint(-15, 15),
                bankruptcies=0 if cust.credit_score >= 650 else rng.choice(
                    [0, 0, 1]),
                pulled_at=_utcnow() - timedelta(
                    days=rng.randint(1, 700)),
                pulled_by_role=rng.choice(
                    ["underwriter", "fraud_investigator", "manager"]),
            ))

        # A handful of historical payments / refunds for the "approved"
        # claims so the analytics tool has something interesting to query
        approved_claims = [c for c in claims if c.status == "approved"]
        for c in approved_claims:
            amt = round(min(c.estimate, c.reserve)
                        * rng.uniform(0.7, 1.0), 2)
            payments.append(Payment(
                payment_id=f"PAY-{_short_hash(c.claim_id, 'seed')}",
                claim_id=c.claim_id,
                amount=amt,
                reason="initial settlement",
                status="released",
                approved_by_role="adjuster",
                approved_at=_utcnow() - timedelta(
                    days=rng.randint(1, 180)),
            ))
        for _ in range(8):
            cust = rng.choice(customers)
            refunds.append(Refund(
                refund_id=f"REF-{_short_hash(cust.customer_id, str(_))}",
                customer_id=cust.customer_id,
                amount=round(rng.uniform(40, 600), 2),
                reason="pro-rata cancellation refund",
                status="queued",
                created_at=_utcnow() - timedelta(
                    days=rng.randint(1, 90)),
            ))

        s.add_all(customers)
        s.add_all(policies)
        s.add_all(claims)
        s.add_all(credit_reports)
        s.add_all(payments)
        s.add_all(refunds)

    return {
        "customers": len(customers),
        "policies": len(policies),
        "claims": len(claims),
        "credit_reports": len(credit_reports),
        "payments": len(payments),
        "refunds": len(refunds),
    }


def _claim_description(ctype: str, rng: random.Random) -> str:
    options = {
        "collision": [
            "Rear-end at a stop light; moderate bumper damage",
            "Side-swipe on highway merge",
            "Multi-vehicle pileup in heavy rain",
        ],
        "liability": [
            "At-fault accident, 3rd-party bodily injury claim",
            "Parked-vehicle damage, at-fault",
        ],
        "comprehensive": [
            "Hailstorm damage; multiple dents",
            "Tree fell on parked vehicle during storm",
            "Flood-damaged interior",
        ],
        "theft": [
            "Vehicle stolen from parking garage overnight",
            "Catalytic converter theft",
            "Laptop + bag stolen after window smash",
        ],
        "fire": [
            "Kitchen grease fire; smoke damage throughout",
            "Electrical fire in garage",
        ],
        "water_damage": [
            "Burst pipe in upstairs bathroom",
            "Sump pump failure during heavy rain",
        ],
    }
    return rng.choice(options.get(ctype, ["General loss"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true",
                        help="Drop all tables before seeding")
    args = parser.parse_args()

    if args.reset:
        print("Dropping + recreating tables...")
        init_db(drop=True)

    summary = seed()
    print("Seed complete:")
    for k, v in summary.items():
        print(f"  {k:<16} {v}")


if __name__ == "__main__":
    main()
