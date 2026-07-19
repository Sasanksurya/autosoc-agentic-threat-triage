"""
parse_attack_data.py
Parses the raw MITRE ATT&CK STIX bundle (enterprise-attack.json) into a clean,
simple list of techniques: {id, name, tactics, description}

The raw STIX format is deeply nested and full of fields we don't need (relationships,
identities, marking-definitions, etc). This script extracts just the "attack-pattern"
objects, which represent techniques, and flattens them into something easy to embed.
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
RAW_FILE = DATA_DIR / "enterprise-attack.json"
OUT_FILE = DATA_DIR / "techniques_clean.json"


def get_technique_id(obj):
    """External references contain the actual ATT&CK ID like T1059.001"""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def get_tactics(obj):
    """Tactics are stored as kill_chain_phases"""
    phases = obj.get("kill_chain_phases", [])
    return [p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"]


def main():
    print(f"Loading raw STIX bundle from {RAW_FILE} ...")
    with open(RAW_FILE, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    print(f"Total STIX objects in bundle: {len(objects)}")

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue  # skip retired techniques

        tid = get_technique_id(obj)
        if not tid:
            continue

        techniques.append({
            "id": tid,
            "name": obj.get("name", ""),
            "tactics": get_tactics(obj),
            "description": (obj.get("description", "") or "").replace("\n", " ").strip(),
            "platforms": obj.get("x_mitre_platforms", []),
        })

    # Sort by technique ID for readability
    techniques.sort(key=lambda t: t["id"])

    print(f"Extracted {len(techniques)} active techniques.")
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)
    print(f"Saved clean techniques to {OUT_FILE}")

    # Show a sample so we can sanity-check the output
    print("\n--- Sample entry ---")
    sample = next(t for t in techniques if t["id"] == "T1059")
    print(json.dumps(sample, indent=2)[:800])


if __name__ == "__main__":
    main()
