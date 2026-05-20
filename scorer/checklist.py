"""
Methodology checklist scorer — scorer/checklist.py

Parses an execution_log.json file and checks whether each of the 9 mandatory
CLAUDE.md investigation steps was executed with a successful return code.

9-step checklist:
  1. psscan       windows.psscan
  2. pstree       windows.pstree
  3. cmdline      windows.cmdline
  4. netscan      windows.netscan
  5. malfind      windows.malfind
  6. filescan     windows.filescan
  7. getsids      windows.getsids
  8. dlllist      windows.dlllist
  9. persistence  windows.registry.printkey OR windows.svcscan

Exit-code gating: a step only counts as PASS if the tool was invoked AND
returned successfully (return_code == 0, or status == "success" for run5 schema).
A tool called but errored is logged as FAIL.

Handles four schema variants observed across runs 1-6:
  - run1/run2: {"commands": [...]} entries have return_code + step + command
  - run3:      {"tool_invocations": [...]} entries have return_code + command
  - run5:      {"tool_invocations": [...]} entries have status (not return_code) + command
  - run6:      {"execution_log": [...]} entries have return_code + seq + command
"""

import json
import re
from pathlib import Path

# ── Checklist definition ──────────────────────────────────────────────────────

CHECKLIST_STEPS: list[dict] = [
    {"id": 1, "name": "psscan",      "plugins": ["windows.psscan"]},
    {"id": 2, "name": "pstree",      "plugins": ["windows.pstree"]},
    {"id": 3, "name": "cmdline",     "plugins": ["windows.cmdline"]},
    {"id": 4, "name": "netscan",     "plugins": ["windows.netscan"]},
    {"id": 5, "name": "malfind",     "plugins": ["windows.malfind"]},
    {"id": 6, "name": "filescan",    "plugins": ["windows.filescan"]},
    {"id": 7, "name": "getsids",     "plugins": ["windows.getsids"]},
    {"id": 8, "name": "dlllist",     "plugins": ["windows.dlllist"]},
    {"id": 9, "name": "persistence", "plugins": ["windows.registry.printkey",
                                                   "windows.svcscan"]},
]

# Aliases to normalise plugin names from different invocation styles
# (e.g. "pstree.PsTree" → "windows.pstree")
PLUGIN_ALIASES: dict[str, str] = {
    "psscan":             "windows.psscan",
    "pstree":             "windows.pstree",
    "pstree.pstree":      "windows.pstree",
    "cmdline":            "windows.cmdline",
    "netscan":            "windows.netscan",
    "malfind":            "windows.malfind",
    "filescan":           "windows.filescan",
    "getsids":            "windows.getsids",
    "dlllist":            "windows.dlllist",
    "registry.printkey":  "windows.registry.printkey",
    "svcscan":            "windows.svcscan",
}


# ── Schema normalisation ──────────────────────────────────────────────────────

def _extract_entries(log: dict) -> list[dict]:
    """Return a flat list of {command, success} dicts from any log schema."""
    for key in ("execution_log", "tool_invocations", "commands"):
        if key in log and isinstance(log[key], list):
            raw = log[key]
            break
    else:
        return []

    entries = []
    for e in raw:
        cmd = e.get("command", "")
        # return_code schema (runs 1, 2, 3, 6)
        if "return_code" in e:
            success = (e["return_code"] == 0)
        # status schema (run5)
        elif "status" in e:
            success = (str(e["status"]).lower() == "success")
        else:
            success = False   # unknown — conservative
        entries.append({"command": cmd, "success": success})
    return entries


def _canonical_plugin(command: str) -> str | None:
    """
    Extract and normalise the Volatility plugin stem from a command string.
    Returns None if the command is not a vol invocation.

    Examples:
      "vol -f img windows.psscan"             → "windows.psscan"
      "vol -f img windows.dlllist --pid 1234" → "windows.dlllist"
      "python3 vol.py windows.pstree"         → "windows.pstree"
    """
    # Must look like a vol invocation
    if not re.search(r'\bvol\b', command, re.IGNORECASE):
        return None

    # Extract the plugin token: the first word that contains a dot and no '/'
    tokens = command.split()
    for token in tokens:
        if "." in token and "/" not in token and not token.startswith("-"):
            stem = token.lower()
            # Try direct match first
            if stem in [s for step in CHECKLIST_STEPS for s in step["plugins"]]:
                return stem
            # Try alias lookup (strip leading "windows." for the key)
            bare = stem.removeprefix("windows.")
            if bare in PLUGIN_ALIASES:
                return PLUGIN_ALIASES[bare]
            # Try the full token in aliases
            if stem in PLUGIN_ALIASES:
                return PLUGIN_ALIASES[stem]
    return None


# ── Main scorer function ──────────────────────────────────────────────────────

def score_checklist(log_path: str | Path) -> dict:
    """
    Score the 9-step methodology checklist against an execution log file.

    Returns a dict with:
      steps:    list of {id, name, status ("pass"/"fail"/"missing"), plugin_found}
      passed:   count of passing steps
      total:    9
      coverage: passed / total (float 0.0–1.0)
      note:     any warnings (e.g. no log file)
    """
    log_path = Path(log_path)

    if not log_path.exists():
        return {
            "steps": [{"id": s["id"], "name": s["name"],
                        "status": "missing", "plugin_found": None}
                       for s in CHECKLIST_STEPS],
            "passed": 0, "total": 9, "coverage": 0.0,
            "note": f"no execution log at {log_path}",
        }

    with open(log_path) as f:
        log = json.load(f)

    entries = _extract_entries(log)

    # Build map: canonical_plugin → success (True if any successful invocation)
    plugin_success: dict[str, bool] = {}
    for entry in entries:
        plugin = _canonical_plugin(entry["command"])
        if plugin:
            # Once a plugin succeeds, mark it; don't downgrade on a later error
            if plugin not in plugin_success:
                plugin_success[plugin] = entry["success"]
            elif entry["success"]:
                plugin_success[plugin] = True

    results = []
    for step in CHECKLIST_STEPS:
        found_plugin = None
        status = "missing"
        for plugin in step["plugins"]:
            if plugin in plugin_success:
                found_plugin = plugin
                status = "pass" if plugin_success[plugin] else "fail"
                break   # first matching plugin wins

        results.append({
            "id": step["id"],
            "name": step["name"],
            "status": status,
            "plugin_found": found_plugin,
        })

    passed = sum(1 for r in results if r["status"] == "pass")
    return {
        "steps": results,
        "passed": passed,
        "total": 9,
        "coverage": round(passed / 9, 4),
        "note": None,
    }
