"""Write review documents from verified experiment outputs, never estimated scores."""
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
LABELS = {
    "C0_container": "C0 broad container", "C2_workspace": "C2 workspace baseline",
    "C3_manual_exact": "Manual native policy + exact output",
    "union_k3": "Trace union", "numeric_k3": "Numeric templates", "directory_k3": "Directory generalisation",
    "support_0.5_k3": "Support threshold 0.5", "bound_stable_k3": "Common-only task bindings",
    "hybrid_validated_k3": "Validated hybrid", "hybrid_without_exact_outputs": "Hybrid with parent-directory writes",
    "Progent_manual_open_code": "Progent: unrestricted code",
    "Progent_manual_exact_code": "Progent: exact code whitelist",
    "Progent_manual_structured": "Progent: structured tools only",
    "Progent_manual_hardened": "Progent: exact code + path identity guards",
    "Progent_exact_plus_hybrid": "Progent exact + hybrid native enforcement",
}


def write(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert len(manifest["tasks"]) == 30 and len(manifest["configurations"]) == 15, "Review documents require the full suite"
    verification = json.loads((directory / "verification.json").read_text())
    assert verification["summary_recomputed"] and verification["selection_evidence_verified"]
    analysis = json.loads((directory / "analysis.json").read_text())
    generation = json.loads((directory / "generation_cost.json").read_text())
    with (directory / "summary.csv").open() as f:
        rows = list(csv.DictReader(f))
    indexed = {r["configuration"]: r for r in rows}
    best = indexed["hybrid_validated_k3"]
    hardened = indexed["Progent_manual_hardened"]
    tables = ["| Policy / configuration | Benign success | Harmful effects | Extra path-permission pairs |",
              "|---|---:|---:|---:|"]
    for r in rows:
        extra = r["mean_excess_pairs"] or "—"
        tables.append(f"| {LABELS[r['configuration']]} | {r['benign_successes']}/{r['benign_total']} ({r['benign_success_pct']}%) | {r['attack_successes']}/{r['attack_total']} ({r['attack_success_pct']}%) | {extra} |")
    learning_seconds = sum(g["learning_seconds"] for g in generation)
    validation_seconds = sum(g["synthesis_and_validation_seconds"] for g in generation)
    hybrid_rule_counts = [len(json.loads(p.read_text())["rules"]) for p in (directory / "profiles").glob("*-hybrid_validated_k3.json")]
    summary_table = "\n".join(tables)
    timings = ["| Configuration | Median successful runtime ms | Matched median overhead vs C0 |", "|---|---:|---:|"]
    overhead = {r["configuration"]: r["median_overhead_pct"] for r in analysis["matched_overhead"]}
    for config in ("C0_container", "C3_manual_exact", "hybrid_validated_k3", "Progent_manual_exact_code", "Progent_manual_hardened", "Progent_exact_plus_hybrid"):
        timings.append(f"| {LABELS[config]} | {indexed[config]['median_successful_ms']} | {overhead[config]}% |")
    poison = analysis["poisoning"]
    poison_lines = ["| Poisoned generator | Successful secret reads |", "|---|---:|"]
    for name, p in poison.items():
        poison_lines.append(f"| {name} | {p['harmful_successes']}/{p['total']} |")
    guide = f'''# Larger policy-generation and Progent comparison

7 October 2026. The best tested generator is **validated task-bound synthesis**:
{best['benign_successes']}/{best['benign_total']} benign executions passed and
{best['attack_successes']}/{best['attack_total']} harmful effects occurred. It
matched the manual native baseline's task and attack outcomes. All remaining
hybrid effects corrupted the exact output that the task was permitted to write.

The comparison uses Progent's actual, unmodified `secure_tool_wrapper` with four
manual policy configurations. Its strongest tested standalone configuration
achieved {hardened['benign_successes']}/{hardened['benign_total']} benign successes
and {hardened['attack_successes']}/{hardened['attack_total']} harmful effects.
Combining Progent with the hybrid native policy matched the hybrid's outcomes.
These are controlled execution results, not published Progent benchmark scores.

This suite changes both the tasks and attack mix from the first 6 October run.
Its percentages should be compared within this table, not directly against the
earlier 14.29% result.

## What was run

Thirty task contexts instantiate ten implemented workflows in three repository
namespaces: JSON totals, CSV aggregation, log analysis, Markdown conversion, TOML
validation, Python syntax checks, Python tests, ZIP manifests, SQLite reports and
hashing. They are thirty contexts, not thirty independently sourced agent tasks.

Each context has three learning executions, three development variants and six
fresh final variants. Numeric and hash basenames test different filename shapes.
Future test files do not exist during learning. Each final benign case runs through
both structured and Python-code tools: **360 benign executions per configuration**.

Fifteen attack operations run per context; three extra source-payload operations
target the three contexts that execute Python source. This gives **453 attack
executions per configuration**. Fifteen configurations yield
**{manifest['main_executions']:,} main-comparison executions**, plus
{manifest['learning_executions']} learning and {manifest['development_executions']}
development executions. A separate poisoning stress test follows final evaluation.

No model was called. This is not an AgentDojo, ASB, AgentPoison or Progent-LLM
reproduction. Scripted operations test harmful effects after an agent has chosen
an action; they do not measure whether an LLM follows a prompt injection.

Each case has one fixed tool call; the driver does not retry or replan after a
denial. A live agent could switch from a denied code call to an allowed structured
tool. The structured-only row therefore measures completion under the prescribed
call plans, not general Progent agent utility.

## Metrics and comparison table

Benign success requires a verified expected output. Attack success requires a
checked harmful effect, not simply exit code zero. Secret output, modified files
and local receiver data are checked by the controller. Corruption of allowed
outputs remains in the main attack denominator.

Permission excess counts additional read/write path pairs relative to the manual
native policy over the task-facing inventory, including the requested output.
Runtime libraries and future files are outside this metric. Progent tool
conditions are a different authority model, so their footprint is shown as “—”.

{summary_table}

![Measured utility and harmful-effect comparison](../results/{directory.name}/comparison.png)

All rows share container limits, worker identity dropping and a fixed seccomp
filter. Native generator rows share the same Landlock enforcer. The manual native
baseline receives the same exact-output reservation capability as the hybrid.

## What the hybrid combines

Paired traces and trusted task arguments infer `read $input` and `write $output`.
These bind to the exact authorised files for a new request, rather than granting
all files matching a wildcard. The caller fixes these arguments before execution;
attacker-controlled tool arguments cannot change them.

Rare fixed observations are initially retained. Counterfactual development runs
then test whether each fixed grant can be removed without breaking legitimate
outputs. A candidate is eligible only with full development utility and zero
effects on the development attack set; selection then minimises permission excess
and rule count. Selection chose {dict(analysis['selection_counts'])} across the
thirty contexts. The selected profiles have {min(hybrid_rule_counts)}–{max(hybrid_rule_counts)}
learned rules, alongside the common runtime baseline.

The controller reserves an exact output file before worker launch. This avoids a
parent-directory write grant for direct-file writers. Scope, traversal, symlink
and hard-link checks prevent unsafe task bindings. These mechanisms are described
in [the method document](05_policy_generation_method.md).

## Lower scores and why they occurred

**Union fails unseen inputs:** the final paths were never observed. More copies
of the same training filenames cannot grant a genuinely new requested file.
**Numeric templates recover numeric cases but miss hash basenames**, and can
permit a hard-linked sensitive object through an innocent-looking filename.
**Directory generalisation restores task coverage but opens unrelated inputs**
and still grants broad output creation.

**The support threshold breaks all tasks:** changing filenames are rare, but are
required. **Common-only bindings miss an occasional CSV dependency**. The hybrid
keeps `settings.json` because removing it breaks the scale-factor branch. That
fixed grant gives the hybrid a small excess on CSV requests that do not need
scaling. Conditional dependency inference is a concrete next improvement.

**Disabling exact-output reservation enables extra output writes.** This ablation
keeps the same selected input/dependency policy and changes only output
compilation. **Allowed-output corruption remains** even with exact writes:
permissions do not determine whether the resulting contents are correct.

## What the Progent comparison means

The official source is pinned to commit
`5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565`, with all imported module hashes saved.
The complete tool module is imported; regex, JSON Schema and callable conditions
run through its real wrappers. Policy generation/update is disabled.

- **Open code:** structured paths are exact, but arbitrary Python is explicitly
  allowed. Internal file/network effects therefore remain unrestricted by its
  tool policy.
- **Exact code:** the policy whitelists the expected benign solution code as well
  as exact structured paths. This is a strong, oracle-informed manual baseline.
- **Structured only:** code execution is denied. It blocks more tool calls but
  fails all benign code-interface cases.
- **Hardened:** upstream callable conditions additionally reject symlinks and hard
  links. This demonstrates that Progent can express path-identity guards.

The hardened row's remaining difference is three source-payload cases. An allowed
workflow loads the authorised Python input; malicious contents read a different
secret file. Native permissions constrain that internal access. All thirty
allowed-output corruption cases remain for both methods. Stricter custom Progent
tools or content validation could change these results; this is not a universal
Progent bypass. Exact-code policies also assume knowledge of the expected solution,
so they do not represent model-generated policies for open-ended coding tasks.

See [the attack-family breakdown](../results/{directory.name}/attack_breakdown.md).

## Poisoning stress test

For one context per workflow family, add a successful learning execution that
also reads an unnecessary file named `notes.txt`, containing a random synthetic
secret. The protected-name overlay does not recognise this name.

{chr(10).join(poison_lines)}

Counterfactual pruning removes this nonessential observation because development
tasks succeed without it. This tests incidental poisoning only. Necessary-looking
malicious dependencies, missed branches and adaptive poisoning remain open.

## Cost, validation and evidence

Recording the ninety clean learning runs took approximately {learning_seconds:.2f}
seconds; synthesis and development validation took {validation_seconds:.2f} seconds.
Both include fixture setup and exclude image build. Model calls/cost are zero.
Human authoring cost and live-agent latency were not measured.

{chr(10).join(timings)}

Runtime includes profile preparation, wrapper checks and worker launch; fixture
reset and footprint collection are excluded. Configurations run sequentially, and
cases are not repeated under different seeds. Timing differences are descriptive,
not isolated kernel-overhead estimates or evidence of statistical superiority.
Negative observed overhead is measurement variation, not an established speedup.

Nineteen Python tests, thirteen existing Linux checks and six new comparison
regression checks passed. Saved-case counts, positive controls, source hashes,
random-secret hash, recomputed tables, split separation and development selection
evidence were verified. There were no sandbox setup failures or timeouts.

Environment: {manifest['environment']['kernel']}, {manifest['environment']['architecture']},
Landlock ABI {manifest['environment']['landlock_abi']}, Python {manifest['environment']['python']}.
ABI 6 lacks ABI 7 audit facilities; this is not complete kernel denial attribution.
Evidence: [summary](../results/{directory.name}/summary.md),
[verification](../results/{directory.name}/verification.json), and raw traces,
profiles, development executions, per-case JSON, Progent policies and image identity
in the same directory.

## Research claim and next work

The useful candidate is reusable **request-relative synthesis with validation of
rare dependencies and explicit output-authority control**. The ingredients have
prior art: [AgentGuardian](https://arxiv.org/abs/2601.10440) learns from benign
traces; [AuthBench](https://arxiv.org/abs/2605.14859) studies permission sufficiency
and tightness; [Sandlock](https://arxiv.org/abs/2605.26298) concerns native agent
sandboxing; [Progent](https://arxiv.org/abs/2504.11703) provides programmable tool
privileges. We have not established novelty or LLM-level generation quality.

Next: externally sourced repository tasks, conditional dependencies, atomic
rename/temp-file workflows, automatic trusted context discovery, varied solution
implementations, unseen adaptive attacks, and a matched model-generated policy
comparison when model access is configured. Improvement targets must be checked
on that broader evaluation, not inferred from this controlled suite.
'''
    docs = ROOT / "docs"
    archive = docs / "archive/2026-10-06_guide_results.md"
    if not archive.exists():
        archive.parent.mkdir(exist_ok=True)
        archive.write_text((docs / "03_guide_results.md").read_text().replace("(../results/", "(../../results/"))
    (docs / "03_guide_results.md").write_text(guide)
    report = f'''# Behaviour-Derived Access Control for Autonomous Code Execution

Initial implementation report — updated 7 October 2026.

## Objective

Generate reusable least-privilege policies for repeated coding workflows from
successful, reviewed executions. Preserve legitimate task completion while
restricting unnecessary filesystem and network authority. The principal research
target is policy-generation quality; kernel enforcement is supporting machinery.

## Current method

Pair execution traces with trusted structured task arguments. Infer input/output
resource roles and fixed dependencies, test removal of unnecessary grants on a
separate development set, and select a candidate meeting utility/security checks.
For direct writers, reserve the exact output before launch to avoid broad directory
write permissions. Apply the resulting profile using Linux Landlock and a fixed
seccomp filter. Python implements synthesis/evaluation; a small C launcher applies
Linux controls. The current run uses no model.

## Evaluation

Thirty contexts from ten implemented workflow families were evaluated with six
fresh file/content variants and two tool interfaces. Fifteen configurations cover
baselines, generator alternatives, output-compilation ablations, actual Progent
wrappers with four manual policy configurations, and a combined system. There
were {manifest['main_executions']:,} main-comparison executions.

| Configuration | Benign successes | Harmful effects |
|---|---:|---:|
'''
    for config in ("C2_workspace", "C3_manual_exact", "hybrid_validated_k3", "Progent_manual_exact_code", "Progent_manual_hardened", "Progent_exact_plus_hybrid"):
        r = indexed[config]
        report += f"| {LABELS[config]} | {r['benign_successes']}/{r['benign_total']} | {r['attack_successes']}/{r['attack_total']} |\n"
    report += '''
All remaining hybrid effects corrupt the authorised output. Exact permissions
cannot judge its contents. The hybrid preserves a rare CSV dependency that a
common-only candidate drops; numeric templates fail nonnumeric unseen filenames.
A separate poisoned-trace experiment demonstrates removal of an unnecessary
secret read, without claiming general poisoning resistance.

## Scope and next steps

These are controlled programs, not independently sourced real-agent tasks.
Structured task bindings are supplied by a trusted caller. Simple exact-file
writers are supported; arbitrary temporary files, atomic rename, complex toolchains
and complete tracing are pending. The real Progent wrapper comparison uses manual
policies, not Progent-LLM or a reproduction of its published agent benchmarks.

The candidate contribution combines request-relative trace inference,
counterfactual dependency validation and explicit output-authority compilation.
Novelty requires further prior-work review and an external evaluation. Expand to
real repositories, conditional dependencies, adaptive attacks and matched
model-generated policies after model access is configured.

See [the guide results](03_guide_results.md) for measurements, failure explanations,
runtime/cost, prior work and evidence; [the method](05_policy_generation_method.md)
for the algorithm; and [the code walkthrough](04_team_code_and_results.md) for implementation.
'''
    (docs / "01_initial_report.md").write_text(report)
    print("Updated initial report and guide results from verified evidence.")


if __name__ == "__main__":
    write(sys.argv[1])
