"""Synthesis and compilation are separate: Landlock cannot enforce globs."""
import hashlib
import json
import re
from pathlib import Path

SECRET_NAMES = {".env", ".ssh", ".aws", ".npmrc", "secrets", "vault"}


def is_secret(path):
    return bool(SECRET_NAMES.intersection(Path(path).parts))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def synthesise(traces, workflow, *, generalise=False, support=0.0, protect_secrets=True):
    if not traces:
        raise ValueError("At least one successful, reviewed learning trace is required")
    evidence = {}
    for trace in traces:
        seen = {(e["kind"], str(e.get("path", e.get("port")))) for e in trace["events"]}
        for key in seen:
            evidence[key] = evidence.get(key, 0) + 1
    rules = []
    for (kind, resource), count in sorted(evidence.items()):
        if count / len(traces) < support or (protect_secrets and is_secret(resource)):
            continue
        rules.append({"kind": kind, "resource": resource, "support": count / len(traces), "source": "observed"})
    if generalise:
        groups = {}
        for rule in rules:
            if rule["kind"] not in {"read", "write"} or not rule["resource"].startswith("/workspace/"):
                continue
            # Intentionally narrow O1 prototype: varying numbered leaf filenames only.
            parts = re.split(r"(\d+)", Path(rule["resource"]).name)
            if len(parts) != 3:
                continue
            key = (rule["kind"], str(Path(rule["resource"]).parent), parts[0], parts[2])
            groups.setdefault(key, []).append(rule)
        for (kind, parent, prefix, suffix), group in groups.items():
            if len(group) < 2:
                continue
            # Keep literal writes: they carry evidence for creating missing outputs.
            # A template materialised against existing files alone cannot create one.
            if kind == "read":
                rules = [rule for rule in rules if rule not in group]
            rules.append({"kind": kind, "resource": parent + "/" + prefix + "{number}" + suffix,
                          "support": min(rule["support"] for rule in group), "source": "numbered-leaf-template"})
    return {"schema": 1, "workflow": workflow, "training_runs": len(traces),
            "trace_hashes": [digest(t) for t in traces], "generalise": generalise,
            "support_threshold": support, "protect_secrets": protect_secrets, "rules": rules}


def materialise(profile, *, promotion=0, budget=0):
    """Expand templates against existing objects; return actual kernel-grant paths.

    Creation of a new file requires a parent-directory grant. This is reported,
    not described as exact filename enforcement. Numeric templates do not grant
    names that appear later during the run.
    """
    grants, expansions = set(), []
    for rule in profile["rules"]:
        kind, resource = rule["kind"], rule["resource"]
        if kind == "connect":
            grants.add((kind, resource))
            continue
        paths = [Path(resource)]
        if "{number}" in resource:
            parent, name = Path(resource).parent, Path(resource).name
            regex = re.compile(re.escape(name).replace(re.escape("{number}"), r"\d+"))
            paths = [p for p in parent.iterdir() if regex.fullmatch(p.name)] if parent.exists() else []
        for path in paths:
            real = path.resolve()
            if profile["protect_secrets"] and is_secret(str(real)):
                continue
            if not real.exists():
                if kind != "write":
                    raise ValueError(f"Observed resource is absent: {path}")
                ancestor = real.parent
                while not ancestor.exists():
                    ancestor = ancestor.parent
                # Never silently turn a missing file into whole-workspace write access.
                if ancestor in {Path(p).resolve() for p in ("/", "/workspace", "/tmp")}:
                    raise ValueError(f"Creation would grant an unsafe ancestor: {ancestor}")
                expansions.append({"requested": str(real), "granted": str(ancestor), "reason": "creation-parent"})
                real = ancestor
            grants.add((kind, str(real)))
    if promotion:
        groups = {}
        for kind, resource in grants:
            path = Path(resource)
            if kind in {"read", "write"} and path.is_file() and resource.startswith("/workspace/"):
                groups.setdefault((kind, path.parent), []).append(resource)
        spent = 0
        for (kind, parent), leaves in sorted(groups.items(), key=lambda item: str(item[0])):
            objects = [p for p in parent.rglob("*") if p.is_file()]
            if len(leaves) < promotion or any(is_secret(str(p.resolve())) for p in objects):
                continue
            added = len(objects) - len(leaves)
            if spent + added > budget:
                continue
            spent += added
            grants.difference_update((kind, leaf) for leaf in leaves)
            grants.add((kind, str(parent)))
            expansions.append({"granted": str(parent), "reason": "subtree-promotion", "additional_objects": added})
    return sorted(grants), expansions


def reachable(grants, inventory):
    """Count read/write object pairs over a fixed inventory, not host-wide guesses."""
    allowed = set()
    for kind, resource in grants:
        if kind not in {"read", "write"}:
            continue
        parent = Path(resource)
        for name in inventory:
            path = Path(name).resolve()
            if path == parent or (parent.is_dir() and parent in path.parents):
                allowed.add((kind, name))
    return allowed
