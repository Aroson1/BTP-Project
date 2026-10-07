"""Verify saved evidence and produce subgroup tables; never changes policies."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentprof.bound import choose_candidate
from agentprof.policy import digest
from benchmarks.large_evaluate import summarise


def analyse(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    rows = [json.loads(line) for line in (directory / "cases.jsonl").read_text().splitlines()]
    assert len(rows) == manifest["main_executions"]
    assert len({(r["configuration"], r["task"], r["kind"], r["variant"], r["case"]) for r in rows}) == len(rows)
    assert digest(rows) == manifest["cases_hash"]
    assert not any(r["exit_code"] in (124, 125) for r in rows)
    for name, expected in manifest["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    footprints = json.loads((directory / "footprints.json").read_text())
    calculated = summarise(rows, footprints)
    with (directory / "summary.csv").open() as file:
        saved = list(csv.DictReader(file))
    for actual, expected in zip(saved, calculated):
        assert all(actual[key] == ("" if value is None else str(value)) for key, value in expected.items())
    assert len(saved) == len(calculated) == len(manifest["configurations"])
    train, dev, test = (set(manifest[key]) for key in ("train_variants", "development_variants", "test_variants"))
    assert not (train & dev or train & test or dev & test)
    tasks = manifest["tasks"]
    for config in manifest["configurations"]:
        subset = [r for r in rows if r["configuration"] == config]
        assert sum(r["kind"] == "benign" for r in subset) == len(tasks) * len(test) * 2
        assert sum(r["kind"] == "attack" for r in subset) == len(tasks) * 15 + sum(t["kind"] == "python-tests" for t in tasks)
    control = [r for r in rows if r["configuration"] == "C0_container"]
    assert all(r["outcome"] for r in control), "Invalid control task or attack"
    # Check the synthetic-secret marker against the controller's recorded hash.
    tokens = set(re.findall(r"BTP_LARGE_SYNTHETIC_SECRET_[0-9a-f]{32}", "\n".join(r["stdout"] for r in control)))
    assert len(tokens) == 1
    assert hashlib.sha256(tokens.pop().encode()).hexdigest() == manifest["synthetic_secret_sha256"]
    choices = Counter()
    pruned_rules = []
    for task in tasks:
        development = json.loads((directory / "development" / (task["id"] + ".json")).read_text())
        assert choose_candidate(development["candidates"]) == development["selected"]
        profile = json.loads((directory / "profiles" / (task["id"] + "-hybrid_validated_k3.json")).read_text())
        assert profile["selection_evidence"] == digest(development)
        samples = [json.loads((directory / "traces" / f"{task['id']}-{v}.json").read_text()) for v in sorted(train)]
        assert profile["trace_hashes"] == [digest(sample) for sample in samples]
        choices[development["selected"]] += 1
        pruned_rules += [{"task": task["id"], **entry} for entry in development["pruning"]]
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["configuration"], row["kind"], row["case"] if row["kind"] == "attack" else row["workflow"])].append(row)
    groups = [{"configuration": config, "kind": kind, "group": group,
               "successes": sum(r["outcome"] for r in values), "total": len(values)}
              for (config, kind, group), values in sorted(grouped.items())]
    with (directory / "subgroups.csv").open("w") as file:
        writer = csv.DictWriter(file, fieldnames=groups[0].keys())
        writer.writeheader(); writer.writerows(groups)
    baseline = {(r["task"], r["variant"], r["case"]): r["wall_seconds"] + r.get("prepare_seconds", 0)
                for r in control if r["kind"] == "benign" and r["outcome"]}
    matched = []
    for config in manifest["configurations"]:
        eligible = [r for r in rows if r["configuration"] == config and r["kind"] == "benign" and r["outcome"]]
        differences = [100 * ((r["wall_seconds"] + r.get("prepare_seconds", 0)) /
                             baseline[(r["task"], r["variant"], r["case"])] - 1) for r in eligible]
        matched.append({"configuration": config, "paired_successes": len(eligible),
                        "median_overhead_pct": round(statistics.median(differences), 2) if differences else None})
    poisoning = json.loads((directory / "poisoning.json").read_text())
    poisoned_groups = defaultdict(list)
    for row in poisoning:
        poisoned_groups[row["configuration"]].append(row["harmful_effect"])
    poisoned_summary = {name: {"harmful_successes": sum(values), "total": len(values)}
                        for name, values in poisoned_groups.items()}
    analysis = {"selection_counts": dict(choices), "removed_stable_rules": sum(r["removed"] for r in pruned_rules),
                "retained_stable_rules": sum(not r["removed"] for r in pruned_rules),
                "poisoning": poisoned_summary, "matched_overhead": matched}
    (directory / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
    lines = ["# Attack-family breakdown", "", "Counts are harmful effects / attempts.", "",
             "| Attack | Hybrid | Progent exact | Progent hardened | Progent + hybrid |",
             "|---|---:|---:|---:|---:|"]
    indexed = {(g["configuration"], g["group"]): g for g in groups if g["kind"] == "attack"}
    attacks = sorted({g["group"] for g in groups if g["kind"] == "attack"})
    for attack in attacks:
        cells = []
        for config in ("hybrid_validated_k3", "Progent_manual_exact_code", "Progent_manual_hardened", "Progent_exact_plus_hybrid"):
            g = indexed[(config, attack)]
            cells.append(f"{g['successes']}/{g['total']}")
        lines.append("| " + attack + " | " + " | ".join(cells) + " |")
    (directory / "attack_breakdown.md").write_text("\n".join(lines) + "\n")
    verification = {"main_executions": len(rows), "unique_case_keys": True, "source_hashes_match": True,
                    "summary_recomputed": True, "cases_hash_matches": True, "selection_evidence_verified": True,
                    "train_development_test_disjoint": True, "all_broad_control_effects_verified": True,
                    "random_secret_hash_verified": True, "launch_failures": 0, "timeouts": 0, "model_calls": 0}
    (directory / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    print(json.dumps({"verification": verification, "analysis": analysis}, indent=2))


if __name__ == "__main__":
    analyse(sys.argv[1])
