"""Selection proposes an existing profile; it never manufactures permissions."""
import json
import re
from pathlib import Path
from .policy import digest

WORKFLOWS = {
    "tests": ("test", "tests", "pytest"),
    "docs": ("documentation", "docs"),
    "format": ("format", "formatting"),
    "report": ("report", "summarise", "summarize"),
    "fetch": ("fetch", "download"),
}


def classify(request):
    import re
    words = set(re.findall(r"[a-z]+", request.lower()))
    matches = [name for name, aliases in WORKFLOWS.items() if words.intersection(aliases)]
    return matches[0] if len(matches) == 1 else None


def register(profile, registry, context):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", profile["workflow"]):
        raise ValueError("Unsafe workflow ID")
    entry = {"profile": profile, "profile_hash": digest(profile), "context": context}
    registry = Path(registry)
    registry.mkdir(parents=True, exist_ok=True)
    target = registry / (profile["workflow"] + ".json")
    target.write_text(json.dumps(entry, indent=2) + "\n")
    return target


def select(registry, context, *, workflow=None, request=None):
    name = workflow or classify(request or "")
    if not name or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
        raise ValueError("Unknown or ambiguous workflow; review required")
    path = Path(registry) / (name + ".json")
    if not path.exists():
        raise ValueError("Workflow has no registered profile; review required")
    entry = json.loads(path.read_text())
    if entry["context"] != context:
        raise ValueError("Repository, environment or workflow version differs; relearn")
    if entry["profile_hash"] != digest(entry["profile"]):
        raise ValueError("Profile integrity check failed")
    return entry["profile"]
