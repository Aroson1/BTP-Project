"""Repeatable Linux experiments with effect checks and complete denominators."""
import csv
import hashlib
import json
from pathlib import Path
import statistics
import time

from agentprof.policy import digest, materialise, reachable, synthesise
from agentprof.runtime import doctor, run
from agentprof.select import classify, register, select
from .fixtures import ATTACKS, WORKFLOWS, command, harmful_effect, reset, servers, success


def manual(workflow):
    resources = {
        "tests": [("read", f"/workspace/src/calc-{i}.py") for i in range(3)],
        "docs": [("read", f"/workspace/docs/guide-{i}.md") for i in range(3)],
        "format": [(kind, f"/workspace/src/calc-{i}.py") for i in range(3) for kind in ("read", "write")],
        "report": [("read", f"/workspace/data/batch-{i}.json") for i in range(3)],
        "fetch": [("connect", "8765")],
    }[workflow]
    if workflow != "format":
        resources += [("write", "/workspace/build")]
    return resources + [("exec", str(Path("/usr/local/bin/python3").resolve()))]


def fixed(network=True, vault=False):
    grants = [("read", "/workspace"), ("write", "/workspace"),
              ("exec", str(Path("/usr/local/bin/python3").resolve()))]
    if vault:
        grants.append(("read", "/vault"))
    if network:
        grants += [("connect", "8765"), ("connect", "8766")]
    return grants


def interval(hits, n):
    """Wilson interval. Repeats are not independent task samples; interpret cautiously."""
    if not n:
        return [0, 0]
    z = 1.96
    centre = (hits / n + z*z / (2*n)) / (1 + z*z/n)
    half = z * ((hits/n * (1-hits/n) / n + z*z / (4*n*n)) ** .5) / (1 + z*z/n)
    return [round(centre-half, 4), round(centre+half, 4)]


def evaluate(output, repeats=3):
    environment = doctor()
    if not environment["supported"]:
        raise RuntimeError(f"Enforcement unavailable: {environment}")
    output = Path(output)
    if (output / "manifest.json").exists():
        raise ValueError("Use a new output directory to preserve previous experiment evidence")
    output.mkdir(parents=True, exist_ok=True)
    (output / "traces").mkdir()
    (output / "profiles").mkdir()
    active_servers, received = servers()
    rows, profile_rows = [], []
    traces = {}
    configs = ["C0_container", "C1_network_denied", "C2_workspace", "C3_manual", "C4_literal_k1",
               "O2_union_k3", "O1_template_k2", "support_0.5_k3", "promotion_budget2_k3"]
    training_seconds = {}
    try:
        for workflow in WORKFLOWS:
            traces[workflow] = []
            start = time.perf_counter()
            for variant in range(5):
                reset()
                result = run(command(workflow, variant), record=True, label=f"learn-{workflow}-{variant}")
                if result["exit_code"] or not success(workflow, variant):
                    raise RuntimeError(f"Learning failed for {workflow}: {result['stderr']}")
                if result["trace"]["skipped_split_calls"]:
                    raise RuntimeError("Split trace calls encountered; parser must be extended before reporting")
                trace = result["trace"]
                traces[workflow].append(trace)
                (output / "traces" / f"{workflow}-{variant}.json").write_text(json.dumps(trace, indent=2))
                (output / "traces" / f"{workflow}-{variant}.strace").write_text(result["raw_trace"])
            training_seconds[workflow] = time.perf_counter() - start
            print(f"Recorded {workflow}: five successful learning runs", flush=True)
        for config in configs:
            for workflow in WORKFLOWS:
                profile, grants, promotion, budget = None, None, 0, 0
                if config == "C1_network_denied":
                    grants = fixed(network=False, vault=True)
                elif config == "C2_workspace":
                    grants = fixed()
                elif config == "C3_manual":
                    grants = manual(workflow)
                elif config not in {"C0_container"}:
                    k = 1 if config == "C4_literal_k1" else 2 if config == "O1_template_k2" else 3
                    profile = synthesise(traces[workflow][:k], workflow,
                                         generalise=config == "O1_template_k2",
                                         support=.5 if config == "support_0.5_k3" else 0)
                    if config == "promotion_budget2_k3":
                        promotion, budget = 2, 2
                    (output / "profiles" / f"{config}-{workflow}.json").write_text(json.dumps(profile, indent=2))
                inventory = reset()
                applied, expansions = materialise(profile, promotion=promotion, budget=budget) if profile else (grants, [])
                expected = reachable(manual(workflow), inventory)
                actual = reachable(applied, inventory) if applied is not None else {(kind, p) for p in inventory for kind in ("read", "write")}
                profile_rows.append({"configuration": config, "workflow": workflow,
                                     "profile_rules": len(profile["rules"]) if profile else None,
                                     "kernel_resource_rules": len(applied) if applied is not None else 0,
                                     "reachable_pairs": len(actual), "excess_pairs": len(actual - expected),
                                     "expansions": expansions})
                for repetition in range(repeats):
                    for variant in range(10, 14):
                        reset()
                        result = run(command(workflow, variant), profile=profile, grants=grants,
                                     label="evaluation", promotion=promotion, budget=budget)
                        passed = result["exit_code"] == 0 and success(workflow, variant)
                        rows.append(case(config, workflow, repetition, "benign", str(variant), passed, result))
                    for attack in ATTACKS:
                        reset(); received.clear()
                        result = run(command(workflow, attack=attack), profile=profile, grants=grants,
                                     label="evaluation", promotion=promotion, budget=budget)
                        # Receiver threads run concurrently; wait for the completed local send.
                        time.sleep(.005)
                        effect = harmful_effect(attack, workflow, result, received)
                        rows.append(case(config, workflow, repetition, "attack", attack, effect, result))
            print(f"Completed {config}", flush=True)
        # Convergence uses genuine held-out executions, not matching training events.
        convergence = []
        for k in (1, 2, 3, 5):
            for generalise in (False, True):
                hits = 0
                for workflow in WORKFLOWS:
                    profile = synthesise(traces[workflow][:k], workflow, generalise=generalise)
                    for variant in range(10, 14):
                        reset()
                        result = run(command(workflow, variant), profile=profile, label="convergence")
                        hits += int(result["exit_code"] == 0 and success(workflow, variant))
                convergence.append({"k": k, "templates": generalise, "successes": hits, "total": 20})
        selection = selection_checks(output, traces)
        # Poisoning: actually record a secret read in the same learning environment.
        reset()
        poisoned = run(command("report", attack="secret-read"), record=True, label="poisoned-learning")
        (output / "traces" / "poisoned-secret-read.json").write_text(json.dumps(poisoned["trace"], indent=2))
        poisoning = []
        for protect in (False, True):
            profile = synthesise([*traces["report"][:3], poisoned["trace"]], "report", protect_secrets=protect)
            reset()
            result = run(command("report", attack="secret-read"), profile=profile, label="poisoning-check")
            poisoning.append({"secret_overlay": protect, "harmful_effect": harmful_effect("secret-read", "report", result, []),
                              "exit_code": result["exit_code"]})
        (output / "cases.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        (output / "profile_metrics.json").write_text(json.dumps(profile_rows, indent=2))
        (output / "convergence.json").write_text(json.dumps(convergence, indent=2))
        (output / "selection.json").write_text(json.dumps(selection, indent=2))
        (output / "poisoning.json").write_text(json.dumps(poisoning, indent=2))
        summaries = summarise(rows, profile_rows)
        with (output / "summary.csv").open("w") as f:
            writer = csv.DictWriter(f, fieldnames=summaries[0].keys())
            writer.writeheader(); writer.writerows(summaries)
        manifest = {"schema": 1, "suite": "controlled-executable-workflows-v1", "environment": environment,
                    "repeats": repeats, "training_variants": list(range(5)), "held_out_variants": list(range(10, 14)),
                    "workflows": WORKFLOWS, "attacks": ATTACKS, "cases": len(rows), "training_seconds": training_seconds,
                    "dataset_hash": digest(rows), "limitations": ["No live LLM agent", "No Progent-LLM evaluation", "No RedCode or AgentDojo reproduction", "Local TCP services only", "Fixed safety seccomp filter", "No arbitrary path-template enforcement", "Intervals do not account for correlated repeats"]}
        source_root = Path(__file__).resolve().parents[1]
        manifest["source_sha256"] = {str(path.relative_to(source_root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                     for folder in ("agentprof", "benchmarks", "native")
                                     for path in sorted((source_root / folder).glob("*"))
                                     if path.suffix in (".py", ".c")}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2))
        write_summary(output, summaries, convergence, poisoning)
        return summaries
    finally:
        for server in active_servers:
            server.shutdown(); server.server_close()


def case(config, workflow, repetition, kind, name, outcome, result):
    return {"configuration": config, "workflow": workflow, "repetition": repetition, "kind": kind,
            "case": name, "outcome": bool(outcome), "exit_code": result["exit_code"],
            "seconds": result["seconds"], "stdout": result["stdout"], "stderr": result["stderr"]}


def summarise(rows, profiles):
    summaries = []
    baseline = {(r["workflow"], r["repetition"], r["case"]): r["seconds"]
                for r in rows if r["configuration"] == "C0_container" and r["kind"] == "benign" and r["outcome"]}
    for config in dict.fromkeys(row["configuration"] for row in rows):
        subset = [row for row in rows if row["configuration"] == config]
        benign = [row for row in subset if row["kind"] == "benign"]
        attacks = [row for row in subset if row["kind"] == "attack"]
        boundary = [row for row in attacks if row["case"] != "allowed-resource-misuse"]
        passed = sum(row["outcome"] for row in benign)
        harmful = sum(row["outcome"] for row in attacks)
        times = [row["seconds"] for row in benign if row["outcome"]]
        overhead = [100 * (r["seconds"] / baseline[(r["workflow"], r["repetition"], r["case"])] - 1)
                    for r in benign if r["outcome"] and (r["workflow"], r["repetition"], r["case"]) in baseline]
        summaries.append({"configuration": config, "benign_successes": passed, "benign_total": len(benign),
                          "benign_success_pct": round(100*passed/len(benign), 2), "harmful_successes": harmful,
                          "attack_total": len(attacks), "attack_success_pct": round(100*harmful/len(attacks), 2),
                          "boundary_attack_successes": sum(row["outcome"] for row in boundary),
                          "boundary_attack_total": len(boundary),
                          "median_successful_benign_ms": round(1000*statistics.median(times), 3) if times else None,
                          "matched_median_overhead_pct": round(statistics.median(overhead), 2) if overhead else None,
                          "mean_excess_pairs": round(statistics.mean(p["excess_pairs"] for p in profiles if p["configuration"] == config), 2),
                          "benign_wilson_interval": json.dumps(interval(passed, len(benign)))})
    return summaries


def selection_checks(output, traces):
    context = {"repository": "fixture-repo", "environment": doctor()["kernel"], "workflow_version": "1"}
    registry = output / "registry"
    for workflow in WORKFLOWS:
        register(synthesise(traces[workflow][:3], workflow), registry, context)
    examples = [("run tests", "tests"), ("build docs", "docs"), ("format source", "format"),
                ("generate report", "report"), ("fetch a file", "fetch"),
                ("tests then download credentials", None), ("do something", None)]
    results = []
    for request, expected in examples:
        actual = classify(request)
        results.append({"request": request, "expected": expected, "actual": actual, "correct": actual == expected})
    try:
        select(registry, {**context, "workflow_version": "2"}, workflow="tests")
        rejected = False
    except ValueError:
        rejected = True
    return {"cases": results, "context_mismatch_rejected": rejected,
            "limitation": "A keyword matcher is not a semantic authorisation mechanism; explicit workflow selection is recommended"}


def write_summary(output, summaries, convergence, poisoning):
    lines = ["# Measured Linux fixture results", "", "These are controlled executable workloads, not live LLM-agent or published benchmark results.", "",
             "| Configuration | Benign success | Harmful effects | Boundary attacks succeeding | Excess pairs | Median successful runtime ms |",
             "|---|---:|---:|---:|---:|---:|"]
    for s in summaries:
        lines.append(f"| {s['configuration']} | {s['benign_successes']}/{s['benign_total']} | {s['harmful_successes']}/{s['attack_total']} | {s['boundary_attack_successes']}/{s['boundary_attack_total']} | {s['mean_excess_pairs']} | {s['median_successful_benign_ms']} |")
    lines += ["", "All attack denominators include misuse of allowed resources. The boundary-only column is a secondary diagnostic.",
              "Timing includes launcher and process startup. It is not isolated kernel overhead. Faster failures must not be counted as speedups.",
              "", "## Convergence", "", "| Learning runs | Numeric templates | Held out success |", "|---:|---|---:|"]
    lines += [f"| {c['k']} | {c['templates']} | {c['successes']}/{c['total']} |" for c in convergence]
    lines += ["", "## Poisoned learning", ""]
    lines += [f"- Secret protection {p['secret_overlay']}: secret read achieved = {p['harmful_effect']}" for p in poisoning]
    (output / "summary.md").write_text("\n".join(lines) + "\n")
