"""Re-apply verdict() to the most recent test_prompts_last_run.json without
actually re-running the prompts, so classifier tweaks can be evaluated for
free."""

import json
from run_test_prompts import verdict

r = json.load(open("test_prompts_last_run.json"))
fixed = []
for x in r:
    v = verdict(x["expected"], x["observed"])
    x["verdict"] = v
    fixed.append(x)

with open("test_prompts_last_run.json", "w", encoding="utf-8") as f:
    json.dump(fixed, f, indent=2, default=str)

cats: dict[str, list] = {}
for x in fixed:
    cats.setdefault(x["category"], []).append(x)

total_pass = sum(1 for x in fixed if x["verdict"] == "PASS")
total_fail = sum(1 for x in fixed if x["verdict"] == "FAIL")

print("=" * 78)
print("Summary per category (re-classified)")
print("=" * 78)
for cat in sorted(cats):
    items = cats[cat]
    p = sum(1 for x in items if x["verdict"] == "PASS")
    f = sum(1 for x in items if x["verdict"] == "FAIL")
    print(f"\n  {cat:30s}  PASS {p:2d} / {len(items):2d}    FAIL {f}")
    for x in items:
        mark = "OK " if x["verdict"] == "PASS" else "!! "
        print(f"    {mark}[{x['verdict']}] {x['id']:30s} "
              f"expected={x['expected']:14s} observed={x['observed']}")

print("\n" + "=" * 78)
print(f"TOTAL   PASS {total_pass} / {len(fixed)}    FAIL {total_fail}")
print("=" * 78)
