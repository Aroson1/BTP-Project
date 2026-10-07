"""Learn resource roles from traces paired with trusted, structured task arguments.

This learns `$input`/`$output` relationships rather than granting a filename family.
Bindings are supplied by the trusted caller, never extracted from tool output.
"""
import copy
import os
from pathlib import Path
import stat

from .policy import digest, is_secret, materialise
from .runtime import BASE_READ


def synthesise_bound(samples, workflow, *, include_rare=False):
    if len(samples) < 2:
        raise ValueError("Binding inference needs at least two reviewed samples")
    slots = set(samples[0]["bindings"])
    if any(set(sample["bindings"]) != slots for sample in samples):
        raise ValueError("Training binding schemas differ")
    if any(len({str(Path(value).resolve()) for value in sample["bindings"].values()}) != len(slots)
           for sample in samples):
        raise ValueError("Ambiguous binding roles require review")
    scopes = {}
    for slot in sorted(slots):
        values = [Path(s["bindings"][slot]).resolve() for s in samples]
        parents = {str(p.parent) for p in values}
        if len(parents) != 1 or len(set(values)) < 2:
            raise ValueError("Each binding needs distinct examples in one trusted directory")
        scopes[slot] = parents.pop()
    observed = []
    for sample in samples:
        observed.append({(e["kind"], str(e.get("path", e.get("port")))) for e in sample["trace"]["events"]})
    rules = []
    for kind in ("read", "write"):
        for slot in sorted(slots):
            if all((kind, str(Path(s["bindings"][slot]).resolve())) in events
                   for s, events in zip(samples, observed)):
                rules.append({"kind": kind, "resource": "$" + slot, "source": "paired-task-evidence"})
    stable = set.union(*observed) if include_rare else set.intersection(*observed)
    binding_values = {str(Path(raw).resolve()) for sample in samples for raw in sample["bindings"].values()}
    for kind, resource in sorted(stable):
        if is_secret(resource) or resource in binding_values:
            continue
        # Shared interpreter libraries are declared by the controller, not learned anew.
        covered = kind in {"read", "list"} and any(
            resource == root or (Path(root).is_dir() and Path(root) in Path(resource).parents)
            for root in BASE_READ)
        if not covered:
            rules.append({"kind": kind, "resource": resource, "source": "stable-evidence"})
    if not any(r["resource"] == "$input" for r in rules):
        raise ValueError("No consistent input relationship was observed")
    return {"schema": 2, "workflow": workflow, "training_runs": len(samples), "include_rare": include_rare, "rules": rules,
            "scopes": scopes, "protect_secrets": True, "trace_hashes": [digest(s) for s in samples]}


def resolve_bindings(profile, bindings):
    if set(bindings) != set(profile["scopes"]):
        raise ValueError("Task binding schema differs")
    resolved = {}
    for slot, raw in bindings.items():
        path = Path(raw)
        if not path.is_absolute() or ".." in path.parts or is_secret(str(path)):
            raise ValueError("Unsafe task binding")
        root = Path(profile["scopes"][slot]).resolve(strict=True)
        real = path.resolve()
        if root == real or root not in real.parents or is_secret(str(real)):
            raise ValueError("Binding escapes its reviewed scope")
        if any(p.is_symlink() for p in [path, *path.parents]):
            raise ValueError("Symlink binding requires separate review")
        if path.exists() and path.stat().st_nlink != 1:
            raise ValueError("Multiply linked binding requires separate review")
        resolved[slot] = real
    return resolved


def compile_bound(profile, bindings, *, exact_outputs=True):
    """Reserve outputs before launch, so a file write need not grant its directory.

    The controller is trusted and no worker is active during reservation. This is
    for simple direct-file writers; atomic rename/temp-file workflows need more work.
    """
    resolved = resolve_bindings(profile, bindings)
    concrete = copy.deepcopy(profile)
    concrete["rules"] = []
    reserved = []
    for rule in profile["rules"]:
        rule = dict(rule)
        slot = rule["resource"][1:] if rule["resource"].startswith("$") else None
        if slot:
            target = resolved[slot]
            if rule["kind"] == "write" and exact_outputs:
                if not target.exists():
                    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
                    try:
                        if os.geteuid() == 0:
                            os.fchown(fd, 1000, 1000)
                    finally:
                        os.close(fd)
                    reserved.append(str(target))
                if not stat.S_ISREG(target.lstat().st_mode):
                    raise ValueError("Output must be a regular file")
            rule["resource"] = str(target)
        concrete["rules"].append(rule)
    grants, expansions = materialise(concrete)
    return grants, {"reserved_outputs": reserved, "expansions": expansions}


def prune_stable(profile, validator):
    """Counterfactual removal: retain a deletion only if development checks pass."""
    current = copy.deepcopy(profile)
    attempts = []
    for rule in list(current["rules"]):
        if rule["resource"].startswith("$") or rule["kind"] == "exec":
            continue
        candidate = copy.deepcopy(current)
        candidate["rules"].remove(rule)
        passed = validator(candidate)
        attempts.append({"rule": rule, "removed": passed})
        if passed:
            current = candidate
    current["pruning"] = attempts
    return current


def choose_candidate(measurements):
    """Selection uses development data only, not the final test results."""
    feasible = [m for m in measurements if m["benign_successes"] == m["benign_total"]
                and m["harmful_effects"] == 0]
    if not feasible:
        raise ValueError("No candidate passes development checks; review required")
    return min(feasible, key=lambda m: (m["excess_pairs"], m["rule_count"], m["name"]))["name"]
