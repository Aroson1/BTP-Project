"""Larger matched execution suite; candidates are selected on development only."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time

from agentprof.bound import choose_candidate, compile_bound, prune_stable, synthesise_bound
from agentprof.policy import digest, materialise, reachable, synthesise
from agentprof.runtime import doctor, run
from .fixtures import servers
from .large_fixtures import ATTACKS, DEV, TEST, TRAIN, SECRET, attack, benign, effect, reset, success, tasks
from .progent_runtime import ProgentGate

CONFIGS = ["C0_container", "C2_workspace", "C3_manual_exact", "union_k3", "numeric_k3",
           "directory_k3", "support_0.5_k3", "bound_stable_k3", "hybrid_validated_k3",
           "hybrid_without_exact_outputs",
           "Progent_manual_open_code", "Progent_manual_exact_code", "Progent_manual_structured",
           "Progent_manual_hardened", "Progent_exact_plus_hybrid"]


def command(request):
    return ["/usr/local/bin/python3", "/opt/agentprof/benchmarks/large_payload.py", json.dumps(request)]


def directory_profile(profile):
    result = copy.deepcopy(profile)
    for rule in result["rules"]:
        if rule["kind"] == "read" and "/input/" in rule["resource"]:
            rule["resource"] = str(Path(rule["resource"]).parent)
    result["rules"] = list({(r["kind"], r["resource"]): r for r in result["rules"]}.values())
    return result


def oracle_shape(task, bindings, variant):
    shape = {"scopes": {slot: str(Path(path).parent) for slot, path in bindings.items()},
             "rules": [{"kind": "read", "resource": "$input"}, {"kind": "write", "resource": "$output"},
                       {"kind": "exec", "resource": str(Path(sys.executable).resolve())}],
             "protect_secrets": True}
    if task["kind"] == "csv-total" and variant % 3 == 2:
        shape["rules"].append({"kind": "read", "resource": str(Path(bindings["input"]).parent.parent / "settings.json")})
    return shape


def grants_for(name, profile, task, bindings, variant):
    if name == "C0_container":
        return None
    if name == "C2_workspace":
        return [("read", "/workspace"), ("write", "/workspace"), ("connect", "8766"),
                ("exec", str(Path(sys.executable).resolve()))]
    if name == "C3_manual_exact":
        return compile_bound(oracle_shape(task, bindings, variant), bindings)[0]
    if profile["schema"] == 2:
        return compile_bound(profile, bindings, exact_outputs=name != "hybrid_without_exact_outputs")[0]
    return materialise(profile)[0]


def execute(request, grants):
    result = run(command(request), grants=grants)
    if result["exit_code"] == 124:
        raise RuntimeError("A timeout is an infrastructure failure, not attack prevention")
    return result


def footprint(grants, task, bindings, variant):
    # Include the concrete requested output in the inventory even before it exists.
    inventory = sorted({str(p) for p in Path("/workspace").rglob("*") if p.is_file()} | {bindings["output"]})
    expected_grants = [(r["kind"], bindings[r["resource"][1:]] if r["resource"].startswith("$") else r["resource"])
                       for r in oracle_shape(task, bindings, variant)["rules"]]
    expected = reachable(expected_grants, inventory)
    actual = reachable(grants, inventory) if grants is not None else {(k, p) for k in ("read", "write") for p in inventory}
    return {"excess_pairs": len(actual - expected), "missing_pairs": len(expected - actual),
            "granted_pairs": len(actual), "expected_pairs": len(expected), "rules": len(grants or [])}


def develop(task, profiles, received):
    measurements = []
    executions = []
    negatives = ["code-secret", "structured-sibling", "code-extra-output", "code-protected-write"]

    def check(profile):
        for variant in DEV:
            bindings = reset(task, variant)
            result = execute(benign(task, bindings, "structured"), grants_for("candidate", profile, task, bindings, variant))
            executions.append({"stage": "pruning", "profile_hash": digest(profile), "variant": variant,
                               "success": not result["exit_code"] and success(task, variant),
                               "exit_code": result["exit_code"], "stderr": result["stderr"]})
            if result["exit_code"] or not success(task, variant):
                return False
        return True

    profiles["bound_pruned"] = prune_stable(profiles["bound_rare"], check)
    for name, profile in profiles.items():
        passed, harmful, excess = 0, 0, []
        for variant in DEV:
            bindings = reset(task, variant)
            grants = grants_for("candidate", profile, task, bindings, variant)
            excess.append(footprint(grants, task, bindings, variant)["excess_pairs"])
            result = execute(benign(task, bindings, "structured"), grants)
            executions.append({"candidate": name, "variant": variant, "kind": "benign",
                               "success": not result["exit_code"] and success(task, variant), **result})
            passed += int(not result["exit_code"] and success(task, variant))
        for name_attack in negatives:
            bindings = reset(task, DEV[0]); received.clear()
            request = attack(task, bindings, name_attack)
            result = execute(request, grants_for("candidate", profile, task, bindings, DEV[0]))
            executions.append({"candidate": name, "case": name_attack, "kind": "attack",
                               "harmful_effect": effect(task, bindings, name_attack, result, received), **result})
            harmful += int(effect(task, bindings, name_attack, result, received))
        measurements.append({"name": name, "benign_successes": passed, "benign_total": len(DEV),
                             "harmful_effects": harmful, "attack_total": len(negatives),
                             "excess_pairs": statistics.mean(excess), "rule_count": len(profile["rules"])})
    selected = choose_candidate(measurements)
    return profiles[selected], {"selected": selected, "candidates": measurements,
                               "pruning": profiles["bound_pruned"]["pruning"], "executions": executions}


def evaluate(output, limit=30, only=None):
    output = Path(output)
    if Path("/results") in output.parents:
        # Host-owned results directory stays readable by its owner, not worker uid 1000.
        Path("/results").chmod(0o700)
    if output.exists():
        raise ValueError("Choose a fresh output directory")
    output.mkdir(parents=True)
    for folder in ("traces", "profiles", "development", "tool_policies"):
        (output / folder).mkdir()
    env = doctor()
    if not env["supported"]:
        raise RuntimeError(env)
    active, received = servers()
    gate = ProgentGate()
    configs = [c for c in CONFIGS if not only or c in only]
    profile_set = {}
    training_samples = {}
    development_runs = 0
    rows, footprints, generation = [], [], []
    task_set = tasks(limit)
    try:
        for task in task_set:
            samples = []
            start = time.perf_counter()
            for variant in TRAIN:
                bindings = reset(task, variant)
                result = run(command(benign(task, bindings, "structured")), record=True,
                             label="large-learning")
                if result["exit_code"] or not success(task, variant) or result["trace"]["skipped_split_calls"]:
                    raise RuntimeError(f"Learning failed: {task['id']} {result}")
                sample = {"bindings": bindings, "trace": result["trace"]}
                samples.append(sample)
                (output / "traces" / f"{task['id']}-{variant}.json").write_text(json.dumps(sample, indent=2))
                (output / "traces" / f"{task['id']}-{variant}.strace").write_text(result["raw_trace"])
            learned_at = time.perf_counter()
            traces = [s["trace"] for s in samples]
            profiles = {"union": synthesise(traces, task["id"]),
                        "numeric": synthesise(traces, task["id"], generalise=True),
                        "support": synthesise(traces, task["id"], support=.5),
                        "bound_stable": synthesise_bound(samples, task["id"]),
                        "bound_rare": synthesise_bound(samples, task["id"], include_rare=True)}
            profiles["directory"] = directory_profile(profiles["union"])
            selected, development = develop(task, profiles, received)
            development_runs += len(development["executions"])
            training_samples[task["id"]] = samples
            finished_at = time.perf_counter()
            selected["selection_evidence"] = digest(development)
            profile_set[task["id"]] = {"union_k3": profiles["union"], "numeric_k3": profiles["numeric"],
                                     "directory_k3": profiles["directory"], "support_0.5_k3": profiles["support"],
                                     "bound_stable_k3": profiles["bound_stable"], "hybrid_validated_k3": selected}
            generation.append({"task": task["id"], "learning_seconds": learned_at - start,
                               "synthesis_and_validation_seconds": finished_at - learned_at})
            (output / "development" / (task["id"] + ".json")).write_text(json.dumps(development, indent=2))
            for name, p in profile_set[task["id"]].items():
                (output / "profiles" / f"{task['id']}-{name}.json").write_text(json.dumps(p, indent=2))
            print("Prepared", task["id"], "selected", development["selected"], flush=True)
        # All candidates/selection are now frozen. No test outcomes alter a profile.
        with (output / "cases.jsonl").open("w") as evidence:
            for config in configs:
                for task in task_set:
                    profiles = profile_set[task["id"]]
                    for variant in TEST:
                        for interface in ("structured", "code"):
                            bindings = reset(task, variant)
                            request = benign(task, bindings, interface)
                            result, metrics = measured(config, task, variant, bindings, request, profiles, gate)
                            if config.startswith("Progent_") and interface == "structured":
                                policy_path = output / "tool_policies" / f"{config}-{task['id']}-{variant}.json"
                                policy_path.write_text(json.dumps({"policy": gate.upstream.security_policy,
                                                                  "trusted_bindings": bindings,
                                                                  "exact_code": benign(task, bindings, "code")["args"]["code"]}, indent=2,
                                                                default=lambda f: "callable:" + f.__name__))
                            outcome = not result["exit_code"] and success(task, variant)
                            row = record(config, task, variant, interface, "benign", outcome, result, request)
                            rows.append(row); evidence.write(json.dumps(row) + "\n"); evidence.flush()
                            if metrics:
                                footprints.append({"configuration": config, "task": task["id"], "variant": variant, **metrics})
                    attack_set = [*ATTACKS, *( ["input-payload"] if task["kind"] == "python-tests" else [])]
                    for name in attack_set:
                        bindings = reset(task, TEST[0]); received.clear()
                        request = attack(task, bindings, name)
                        result, _ = measured(config, task, TEST[0], bindings, request, profiles, gate, attack_case=True)
                        time.sleep(.005)
                        outcome = effect(task, bindings, name, result, received)
                        row = record(config, task, TEST[0], name, "attack", outcome, result, request)
                        rows.append(row); evidence.write(json.dumps(row) + "\n"); evidence.flush()
                print("Completed", config, len(rows), "total executions", flush=True)
        summary = summarise(rows, footprints)
        poisoning = poisoning_checks(task_set, training_samples, output)
        (output / "poisoning.json").write_text(json.dumps(poisoning, indent=2))
        with (output / "summary.csv").open("w") as f:
            writer = csv.DictWriter(f, fieldnames=summary[0].keys())
            writer.writeheader(); writer.writerows(summary)
        for name, value in (("footprints", footprints), ("generation_cost", generation)):
            (output / (name + ".json")).write_text(json.dumps(value, indent=2))
        root = Path(__file__).resolve().parents[1]
        hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for folder in ("agentprof", "benchmarks", "native") for p in sorted((root / folder).glob("*"))
                  if p.suffix in (".py", ".c")}
        manifest = {"suite": "larger-controlled-workflows-v2", "date": "2026-10-07", "environment": env,
                    "tasks": task_set, "train_variants": TRAIN, "development_variants": DEV, "test_variants": TEST,
                    "configurations": configs, "main_executions": len(rows), "cases_hash": digest(rows),
                    "learning_executions": len(task_set) * len(TRAIN), "development_executions": development_runs,
                    "source_sha256": hashes, "progent": gate.provenance, "model_calls": 0,
                    "synthetic_secret_sha256": hashlib.sha256(SECRET.encode()).hexdigest(),
                    "limitations": ["30 task contexts from 10 hand-written workflow implementations, not 30 independent agent tasks",
                                    "One execution per unique final case; no repeated-seed uncertainty estimate",
                                    "Trusted structured task bindings are supplied, not inferred from natural language",
                                    "Development attacks are hand-written and overlap categories with the final suite",
                                    "No AgentDojo/ASB/AgentPoison or Progent-LLM reproduction",
                                    "Sequential configuration order can affect timing; common runtime grants excluded from footprint"]}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
        write_report(output, summary)
        return summary
    finally:
        for server in active:
            server.shutdown(); server.server_close()


def poisoning_checks(task_set, training_samples, output):
    """Stress one poisoned trace per family, including an unrecognised secret name.

    This is an extra experiment, not input for final-test selection. The dangerous
    read does not contribute to the validated task result, so deletion can remove it.
    """
    results = []
    for task in task_set[:10]:
        bindings = reset(task, TRAIN[-1])
        notes = str(Path(bindings["input"]).parent / "notes.txt")
        safe_code = benign(task, bindings, "code")["args"]["code"]
        request = {"tool": "exec_python", "args": {"code": f"print(open({notes!r}).read()); " + safe_code}}
        poisoned = run(command(request), record=True, label="poisoned-large-learning")
        assert not poisoned["exit_code"] and success(task, TRAIN[-1]) and not poisoned["trace"]["skipped_split_calls"]
        evidence = {"bindings": bindings, "trace": poisoned["trace"]}
        (output / "traces" / f"{task['id']}-poisoned.json").write_text(json.dumps(evidence, indent=2))
        (output / "traces" / f"{task['id']}-poisoned.strace").write_text(poisoned["raw_trace"])
        samples = [*training_samples[task["id"]], evidence]
        bound = synthesise_bound(samples, task["id"], include_rare=True)

        def validator(profile):
            for variant in DEV:
                current = reset(task, variant)
                result = execute(benign(task, current, "structured"), compile_bound(profile, current)[0])
                if result["exit_code"] or not success(task, variant):
                    return False
            return True

        pruned = prune_stable(bound, validator)
        candidates = {"poisoned_union": synthesise([s["trace"] for s in samples], task["id"]),
                      "poisoned_bound_unpruned": bound, "poisoned_hybrid_pruned": pruned}
        for name, profile in candidates.items():
            current = reset(task, TEST[0])
            request = attack(task, current, "structured-sibling")
            grants = grants_for("candidate", profile, task, current, TEST[0])
            result = execute(request, grants)
            results.append({"task": task["id"], "configuration": name,
                            "harmful_effect": effect(task, current, "structured-sibling", result, []),
                            "exit_code": result["exit_code"], "stdout": result["stdout"], "stderr": result["stderr"],
                            "rules": profile["rules"], "pruning": profile.get("pruning", [])})
    return results


def measured(config, task, variant, bindings, request, profiles, gate, attack_case=False):
    prepare_start = time.perf_counter()
    native = not config.startswith("Progent_") or config == "Progent_exact_plus_hybrid"
    profile = profiles.get(config, profiles["hybrid_validated_k3"])
    metrics = None
    if native:
        try:
            grants = grants_for("hybrid_validated_k3" if config == "Progent_exact_plus_hybrid" else config,
                                profile, task, bindings, variant)
        except ValueError as error:
            if not attack_case:
                raise
            return {"exit_code": 126, "stdout": "", "stderr": str(error), "seconds": 0,
                    "binding_rejected": True}, None
    else:
        grants = None
    prepare_seconds = time.perf_counter() - prepare_start
    if native and not attack_case:
        metrics = footprint(grants, task, bindings, variant)
    start = time.perf_counter()
    if config.startswith("Progent_"):
        mode = ("open" if config == "Progent_manual_open_code" else "structured" if config == "Progent_manual_structured"
                else "hardened" if config == "Progent_manual_hardened" else "exact")
        code = benign(task, bindings, "code")["args"]["code"]
        gate.configure(task, bindings, code, mode)
        result = gate.call(request, lambda accepted: execute(accepted, grants))
    else:
        result = execute(request, grants)
    result["wall_seconds"] = time.perf_counter() - start
    result["prepare_seconds"] = prepare_seconds
    return result, metrics


def record(config, task, variant, case, kind, outcome, result, request):
    return {"configuration": config, "task": task["id"], "workflow": task["kind"], "variant": variant,
            "case": case, "kind": kind, "outcome": bool(outcome), "request": request,
            **{k: v for k, v in result.items() if k in {"stdout", "stderr", "exit_code", "seconds", "wall_seconds", "prepare_seconds",
                                                       "tool_gate_denied", "binding_rejected"}}}


def summarise(rows, footprints):
    result = []
    for config in dict.fromkeys(r["configuration"] for r in rows):
        subset = [r for r in rows if r["configuration"] == config]
        benign_rows = [r for r in subset if r["kind"] == "benign"]
        attacks = [r for r in subset if r["kind"] == "attack"]
        times = [r["wall_seconds"] + r.get("prepare_seconds", 0) for r in benign_rows if r["outcome"]]
        f = [m for m in footprints if m["configuration"] == config]
        result.append({"configuration": config, "benign_successes": sum(r["outcome"] for r in benign_rows),
                       "benign_total": len(benign_rows), "attack_successes": sum(r["outcome"] for r in attacks),
                       "attack_total": len(attacks), "benign_success_pct": round(100*sum(r["outcome"] for r in benign_rows)/len(benign_rows),2),
                       "attack_success_pct": round(100*sum(r["outcome"] for r in attacks)/len(attacks),2),
                       "tool_gate_denials": sum(r.get("tool_gate_denied",False) for r in subset),
                       "binding_rejections": sum(r.get("binding_rejected",False) for r in subset),
                       "mean_excess_pairs": round(statistics.mean(m["excess_pairs"] for m in f),3) if f else None,
                       "mean_missing_pairs": round(statistics.mean(m["missing_pairs"] for m in f),3) if f else None,
                       "median_successful_ms": round(1000*statistics.median(times),3) if times else None})
    return result


def write_report(output, summaries):
    lines = ["# Larger model-free comparison", "", "Thirty contexts from ten implemented workflows; controlled execution, not live-agent evaluation.", "",
             "| Configuration | Benign success | Harmful effects | Excess pairs | Missing pairs | Successful runtime ms |",
             "|---|---:|---:|---:|---:|---:|"]
    for s in summaries:
        lines.append(f"| {s['configuration']} | {s['benign_successes']}/{s['benign_total']} ({s['benign_success_pct']}%) | {s['attack_successes']}/{s['attack_total']} ({s['attack_success_pct']}%) | {s['mean_excess_pairs']} | {s['mean_missing_pairs']} | {s['median_successful_ms']} |")
    lines += ["", "Footprints apply to native policies only. Progent tool constraints are not counted as native filesystem grants.",
              "Progent rows execute unmodified upstream secure_tool_wrapper with manually supplied policies and no model.",
              "Exact-code Progent is a strong allowlist baseline; unrestricted code is only one configuration.",
              "All final test cases were run after development selection was frozen. No final-test tuning was performed."]
    (output / "summary.md").write_text("\n".join(lines)+"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--only", nargs="+")
    args = parser.parse_args()
    if not 1 <= args.limit <= 30:
        parser.error("limit must be 1..30")
    evaluate(args.output, args.limit, args.only)
