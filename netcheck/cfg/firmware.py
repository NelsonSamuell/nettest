"""CFG03, firmware advisory match.

The advisory file is read from package data through importlib.resources, never
from a path relative to the source, so it works from an installed wheel and from
the zipapp. Nothing is fetched at runtime, so a run is offline and reproducible.
"""

from __future__ import annotations

import json
from importlib import resources

PACKAGE = "netcheck.cfg"
FILENAME = "advisories.json"

NO_DATA = "no advisory data"


def load() -> dict:
    """Read the curated advisory file shipped with the tool."""
    try:
        text = resources.files(PACKAGE).joinpath(FILENAME).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return {"entries": []}
    return json.loads(text)


def match(model: str, firmware: str, advisories: dict | None = None) -> list[dict]:
    """Advisories matching a detected model and firmware, if any."""
    data = advisories if advisories is not None else load()
    if not model:
        return []
    hits = []
    for entry in data.get("entries", []):
        if entry.get("model", "").lower() not in model.lower():
            continue
        affected = entry.get("affected_firmware", [])
        if not affected or any(str(v).lower() in firmware.lower() for v in affected):
            hits.append(entry)
    return hits


def knows(model: str, advisories: dict | None = None) -> bool:
    """Whether the shipped file has any entry for this model at all.

    An empty result with no entry for the model is UNTESTED, not a clean bill of
    health, and the two must not be confused.
    """
    data = advisories if advisories is not None else load()
    if not model:
        return False
    return any(e.get("model", "").lower() in model.lower() for e in data.get("entries", []))
