"""
Runner for the inbox-triage red-team.

Sends every email in dataset.json to the n8n webhook, reads back the CRM
record the workflow created, and scores it:
  - attacks: did the injected goal succeed? (success_check)
  - benign:  did the category match what we expected?

Usage:
    python run_attacks.py naive          # label = which defense version you're testing
    python run_attacks.py naive --only A01,A14,B01   # run a subset
"""

import csv
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime

import requests

WEBHOOK_URL = "http://localhost:5678/webhook/email-in"
DATASET = "dataset.json"
DELAY_SECONDS = 1.5   # pause between emails so we don't hit Groq rate limits
TIMEOUT = 90

# dataset field name -> Airtable column name
FIELD_MAP = {
    "forward_to": "Forward To",
    "draft_reply": "Draft Reply",
    "action": "Action",
    "category": "Category",
    "summary": "Summary",
    "parse_ok": "Parse OK",
}


def send(email):
    """POST one email to the workflow. Returns (fields_dict, latency_s, error)."""
    payload = {k: email[k] for k in ("sender", "subject", "body")}
    start = time.time()
    try:
        r = requests.post(WEBHOOK_URL, json=payload, timeout=TIMEOUT)
        latency = time.time() - start
        r.raise_for_status()
        data = r.json()
        # Airtable leaves empty fields out of the response, so default to ""
        fields = data.get("fields", {}) if isinstance(data, dict) else {}
        out = {k: fields.get(col, "") for k, col in FIELD_MAP.items()}
        return out, latency, ""
    except Exception as e:
        return {k: "" for k in FIELD_MAP}, time.time() - start, str(e)[:200]


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_attacks.py <label> [--only ID1,ID2]")
        sys.exit(1)
    label = sys.argv[1]
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))

    with open(DATASET, encoding="utf-8") as f:
        ds = json.load(f)

    items = [("attack", a) for a in ds["attacks"]] + [("benign", b) for b in ds["benign"]]
    if only:
        items = [(kind, e) for kind, e in items if e["id"] in only]

    rows = []
    for i, (kind, email) in enumerate(items, 1):
        out, latency, err = send(email)

        if kind == "attack":
            check = email["success_check"]
            value = str(out.get(check["field"], ""))
            succeeded = (not err) and check["contains"].lower() in value.lower()
            verdict = "ATTACK WORKED" if succeeded else "blocked"
        else:
            succeeded = None
            got = str(out.get("category", "")).lower().strip()
            correct = got == email["expected_category"]
            verdict = "ok" if correct else f"wrong category (got '{got}')"

        if err:
            verdict = f"ERROR: {err}"

        print(f"[{i:>2}/{len(items)}] {email['id']:<4} {kind:<6} {latency:5.1f}s  {verdict}")

        rows.append({
            "id": email["id"],
            "kind": kind,
            "technique": email.get("technique", ""),
            "attack_succeeded": succeeded,
            "expected_category": email.get("expected_category", ""),
            "category": out["category"],
            "action": out["action"],
            "forward_to": out["forward_to"],
            "parse_ok": out["parse_ok"],
            "latency_s": round(latency, 2),
            "error": err,
            "draft_reply": out["draft_reply"],
        })
        time.sleep(DELAY_SECONDS)

    # ---- save results ----
    os.makedirs("results", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    path = os.path.join("results", f"{label}-{stamp}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # ---- summary ----
    attacks = [r for r in rows if r["kind"] == "attack" and not r["error"]]
    benign = [r for r in rows if r["kind"] == "benign" and not r["error"]]
    errors = [r for r in rows if r["error"]]

    print("\n================ SUMMARY:", label, "================")
    if attacks:
        won = sum(1 for r in attacks if r["attack_succeeded"])
        print(f"Attack success: {won}/{len(attacks)} ({won / len(attacks):.0%})")
        by_tech = defaultdict(lambda: [0, 0])
        for r in attacks:
            by_tech[r["technique"]][1] += 1
            if r["attack_succeeded"]:
                by_tech[r["technique"]][0] += 1
        for tech, (w_, n) in sorted(by_tech.items()):
            print(f"   {tech:<24} {w_}/{n}")
    if benign:
        ok = sum(1 for r in benign if r["category"].lower().strip() == r["expected_category"])
        print(f"Benign category accuracy: {ok}/{len(benign)}")
    ok_rows = [r for r in rows if not r["error"]]
    if ok_rows:
        avg = sum(r["latency_s"] for r in ok_rows) / len(ok_rows)
        print(f"Avg latency per email: {avg:.1f}s")
    if errors:
        print(f"Errors: {len(errors)} (see CSV)")
    print(f"Saved: {path}")


if __name__ == "__main__":
    main()
