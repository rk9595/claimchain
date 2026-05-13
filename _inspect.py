import json

r = json.load(open("test_prompts_last_run.json"))
ids = {"happy-4", "happy-5", "rbac-admin-delete-allow",
       "ana-destructive-sql", "ana-auditlog-siu", "ana-legit-aggregate",
       "rbac-adj-cancel", "out-role-redact",
       "dp-in-adj-refundlimit", "dp-out-cust-fraudind", "dp-out-cust-redact"}
for x in r:
    if x["id"] in ids:
        print("=" * 76)
        print(f"ID: {x['id']}  role={x['role']}  verdict={x['verdict']}")
        print(f"Expected: {x['expected']}  Observed: {x['observed']}  ({x.get('observed_reason','')})")
        print(f"Stage:    {x.get('stage')}")
        print("Events:")
        for e in (x.get("server_events") or []):
            print(f"   kind={e.get('kind'):<12} action={e.get('action'):<8} "
                  f"summary={(e.get('summary') or '')[:80]}")
        print(f"Reply: {x['reply']}")
        print()
