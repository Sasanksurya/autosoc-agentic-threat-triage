"""
run_all_alerts.py
Runs the full 4-agent crew across every alert in data/sample_alerts.json,
and saves each result to data/eval_results.json for later review/scoring.

Resilient to rate limits: retries with backoff on RateLimitError, waits
between alerts to avoid hitting free-tier TPM limits, and skips (rather than
crashes on) any alert that still fails after retries -- so one bad alert
never loses progress on the rest.
"""
import json
import time
from pathlib import Path

from litellm.exceptions import RateLimitError
from crew import build_crew

DATA_DIR = Path(__file__).parent.parent / "data"
ALERTS_FILE = DATA_DIR / "sample_alerts.json"
RESULTS_FILE = DATA_DIR / "eval_results.json"

SECONDS_BETWEEN_ALERTS = 10   # cool-down between alerts to respect free-tier TPM
MAX_RETRIES = 4
BASE_BACKOFF_SECONDS = 15


def run_with_retry(raw_log: str):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            crew = build_crew(raw_log)
            return crew.kickoff()
        except RateLimitError as e:
            wait = BASE_BACKOFF_SECONDS * attempt
            print(f"  Rate limit hit (attempt {attempt}/{MAX_RETRIES}). Waiting {wait}s...")
            time.sleep(wait)
    raise RuntimeError("Max retries exceeded due to repeated rate limiting.")


def load_existing_results():
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def main():
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        alerts = json.load(f)

    results = load_existing_results()
    # Only skip alerts that actually succeeded -- retry any that previously errored
    done_ids = {r["alert_id"] for r in results if not str(r.get("crew_output", "")).startswith("ERROR:")}
    # Drop stale error entries so they get replaced by a fresh attempt
    results = [r for r in results if r["alert_id"] in done_ids]

    for alert in alerts:
        if alert["id"] in done_ids:
            print(f"Skipping {alert['id']} (already completed in a previous run)")
            continue

        print("\n" + "#" * 90)
        print(f"# RUNNING ALERT: {alert['id']}  (expected: {alert['expected_label']})")
        print("#" * 90)

        try:
            output = run_with_retry(alert["raw_log"])
            results.append({
                "alert_id": alert["id"],
                "raw_log": alert["raw_log"],
                "expected_label": alert["expected_label"],
                "note": alert.get("note", ""),
                "crew_output": str(output),
            })
        except Exception as e:
            print(f"  FAILED permanently on {alert['id']}: {e}")
            results.append({
                "alert_id": alert["id"],
                "raw_log": alert["raw_log"],
                "expected_label": alert["expected_label"],
                "note": alert.get("note", ""),
                "crew_output": f"ERROR: {e}",
            })

        # Save after every alert so partial progress is never lost
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        time.sleep(SECONDS_BETWEEN_ALERTS)

    print(f"\n\nDone. {len(results)} alerts total in {RESULTS_FILE}")


if __name__ == "__main__":
    main()