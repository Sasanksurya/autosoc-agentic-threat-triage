"""
tools.py
Custom CrewAI tools that wrap our existing functions so agents can call them.

Two tools:
1. mitre_lookup_tool   -> queries the vector DB (query_test.py)
2. playbook_lookup_tool -> looks up a recommended response action from playbooks.json

ROBUSTNESS NOTE:
Smaller/faster LLMs are inconsistent about how they format tool call arguments.
Across testing we saw at least three different malformed shapes for what should
just be a plain string argument:
  1. {"alert_description": {"description": "...", "type": "str"}}   (nested dict)
  2. {"description": "...", "metadata": {}}                        (wrong key name entirely)
  3. a correctly-formatted plain string (the happy path)
Rather than playing whack-a-mole with prompt engineering for each new shape a
model invents, both tools below use a permissive (extra="allow") args_schema
and a single "best-effort extraction" helper that pulls the actual description
text out of whatever shape arrives. This fixes the root cause: it's no longer
possible for a malformed-but-recoverable tool call to fail validation and
waste a retry (which is also what was contributing to hitting rate limits).
"""
import json
import sys
from pathlib import Path
from typing import Any
from pydantic import BaseModel, ConfigDict
from crewai.tools import BaseTool

SRC_DIR = Path(__file__).parent
DATA_DIR = SRC_DIR.parent / "data"
sys.path.insert(0, str(SRC_DIR))

from query_test import retrieve_techniques

with open(DATA_DIR / "playbooks.json", "r", encoding="utf-8") as f:
    PLAYBOOKS = json.load(f)

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Keys we've seen models use instead of the "real" parameter name
_DESCRIPTION_ALIASES = ("alert_description", "description", "value", "text", "input", "query")
_TACTICS_ALIASES = ("tactics_csv", "tactics", "value")
_SEVERITY_ALIASES = ("severity", "severity_level", "level")


def _best_effort_extract(kwargs: dict, aliases: tuple) -> str:
    """Pull a usable string out of whatever shape the model actually sent."""
    for key in aliases:
        val = kwargs.get(key)
        if isinstance(val, str) and val.strip():
            return val
        if isinstance(val, dict):
            # one level of nesting -- check the field's own aliases plus the
            # generic "description" key, since that's the most common pattern
            # models use regardless of what the outer field is called
            for inner_key in (*aliases, "description", "value", "text"):
                inner_val = val.get(inner_key)
                if isinstance(inner_val, str) and inner_val.strip():
                    return inner_val
    # last resort: return the first non-empty string value found anywhere
    for val in kwargs.values():
        if isinstance(val, str) and val.strip():
            return val
    return ""


class MitreArgs(BaseModel):
    model_config = ConfigDict(extra="allow")
    alert_description: Any = ""


class PlaybookArgs(BaseModel):
    model_config = ConfigDict(extra="allow")
    tactics_csv: Any = ""
    severity: Any = ""


class MitreLookupTool(BaseTool):
    name: str = "MITRE ATT&CK Technique Lookup"
    description: str = (
        "Given a plain-English description of suspicious behavior from a security "
        "alert, retrieves the top matching MITRE ATT&CK techniques (with IDs, names, "
        "and tactics) from the vector knowledge base. Use this to ground your "
        "reasoning about what attack technique an alert might represent, instead of "
        "guessing. Call with a single argument: alert_description (a plain string)."
    )
    args_schema: type[BaseModel] = MitreArgs

    def _run(self, **kwargs: Any) -> str:
        alert_description = _best_effort_extract(kwargs, _DESCRIPTION_ALIASES)
        if not alert_description:
            return "Error: no usable alert description was provided to this tool."

        matches = retrieve_techniques(alert_description, n_results=3)
        if not matches:
            return "No matching MITRE ATT&CK techniques found."

        lines = ["Top matching MITRE ATT&CK techniques:"]
        for m in matches:
            lines.append(f"- {m['id']} \"{m['name']}\" | tactics: {m['tactics']} | relevance_distance: {m['distance']}")
        return "\n".join(lines)


class PlaybookLookupTool(BaseTool):
    name: str = "Response Playbook Lookup"
    description: str = (
        "Given a comma-separated list of MITRE tactics (e.g. 'execution, persistence') "
        "and a severity level (low/medium/high/critical), returns the recommended "
        "response action from the static playbook library. Call with two arguments: "
        "tactics_csv and severity (both plain strings)."
    )
    args_schema: type[BaseModel] = PlaybookArgs

    def _run(self, **kwargs: Any) -> str:
        tactics_csv = _best_effort_extract(kwargs, _TACTICS_ALIASES)
        severity = _best_effort_extract(kwargs, _SEVERITY_ALIASES)

        tactics = [t.strip().lower() for t in tactics_csv.split(",") if t.strip()]
        severity = severity.strip().lower()
        if severity not in SEVERITY_ORDER:
            severity = "low"
        sev_rank = SEVERITY_ORDER.index(severity)

        for pb in PLAYBOOKS["playbooks"]:
            pb_tactics = [t.lower() for t in pb["trigger_tactics"]]
            min_rank = SEVERITY_ORDER.index(pb["severity_min"])
            if any(t in pb_tactics for t in tactics) and sev_rank >= min_rank:
                return f"Recommended action: {pb['action']}\nReasoning: {pb['description']}"

        return f"Recommended action: {PLAYBOOKS['default_action']}\nReasoning: No specific playbook matched; defaulting to manual review."


mitre_lookup_tool = MitreLookupTool()
playbook_lookup_tool = PlaybookLookupTool()