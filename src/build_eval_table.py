"""
build_eval_table.py
Reads data/eval_results.json and produces a scored evaluation table:
alert ID -> expected label -> predicted severity -> match/mismatch -> notes.

A severity of Medium/High/Critical is treated as a "malicious" prediction;
Low is treated as "benign" -- this lets us score against the ground-truth
expected_label even though the crew outputs a severity, not a binary label.
"""
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
RESULTS_FILE = DATA_DIR / "eval_results.json"
TABLE_FILE = DATA_DIR / "eval_table.md"


def extract_severity(crew_output: str) -> str:
    match = re.search(r"Severity:\s*(\w+)", crew_output)
    return match.group(1) if match else "Unknown"


def severity_to_predicted_label(severity: str) -> str:
    return "benign" if severity.lower() == "low" else "malicious"


def main():
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        results = json.load(f)

    rows = []
    correct = 0
    for r in results:
        output = r["crew_output"]
        if output.startswith("ERROR:"):
            severity = "ERROR"
            predicted = "ERROR"
            is_match = "N/A"
        else:
            severity = extract_severity(output)
            predicted = severity_to_predicted_label(severity)
            is_match = "✅" if predicted == r["expected_label"] else "❌"
            if predicted == r["expected_label"]:
                correct += 1

        rows.append({
            "alert_id": r["alert_id"],
            "expected": r["expected_label"],
            "severity": severity,
            "predicted": predicted,
            "match": is_match,
            "note": r.get("note", ""),
        })

    total = len([r for r in rows if r["match"] != "N/A"])
    accuracy = correct / total * 100 if total else 0

    lines = [
        "# Evaluation Results — AutoSOC Agentic AI Threat Triage\n",
        f"**Accuracy: {correct}/{total} ({accuracy:.1f}%)** (severity Medium/High/Critical counted as 'malicious' prediction, Low as 'benign')\n",
        "| Alert | Expected | Severity Assigned | Predicted Label | Match | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        note = row["note"][:50] + "..." if len(row["note"]) > 50 else row["note"]
        lines.append(
            f"| {row['alert_id']} | {row['expected']} | {row['severity']} | {row['predicted']} | {row['match']} | {note} |"
        )

    table_md = "\n".join(lines)
    with open(TABLE_FILE, "w", encoding="utf-8") as f:
        f.write(table_md)

    print(table_md)
    print(f"\n\nSaved to {TABLE_FILE}")


if __name__ == "__main__":
    main()
