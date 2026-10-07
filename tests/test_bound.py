from pathlib import Path
import tempfile
import unittest
import sys

from agentprof.bound import choose_candidate, compile_bound, prune_stable, synthesise_bound


def samples(root):
    result = []
    for i in (0, 1, 2):
        bindings = {"input": str(root / "input" / f"source-{i}.json"),
                    "output": str(root / "out" / f"result-{i}.json")}
        events = [{"kind": "read", "path": bindings["input"]},
                  {"kind": "write", "path": bindings["output"]},
                  {"kind": "exec", "path": str(Path(sys.executable).resolve())}]
        if i == 2:
            events.append({"kind": "read", "path": str(root / "settings.json")})
        result.append({"bindings": bindings, "trace": {"events": events}})
    return result


class BoundTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ("input", "out"):
            (self.root / name).mkdir()

    def test_roles_generalise_without_granting_siblings(self):
        profile = synthesise_bound(samples(self.root), "report")
        source = self.root / "input" / "never-seen-name.json"
        source.write_text("[]")
        target = self.root / "out" / "never-seen-output.json"
        grants, metadata = compile_bound(profile, {"input": str(source), "output": str(target)})
        self.assertIn(("read", str(source)), grants)
        self.assertIn(("write", str(target)), grants)
        self.assertNotIn(("write", str(target.parent)), grants)
        self.assertEqual(metadata["reserved_outputs"], [str(target)])

    def test_swapped_source_symlink_is_rejected(self):
        profile = synthesise_bound(samples(self.root), "report")
        (self.root / ".env").write_text("synthetic")
        source = self.root / "input" / "valid.json"
        source.symlink_to(self.root / ".env")
        with self.assertRaises(ValueError):
            compile_bound(profile, {"input": str(source), "output": str(self.root / "out/result.json")})

    def test_escape_and_traversal_are_rejected(self):
        profile = synthesise_bound(samples(self.root), "report")
        for source in (str(self.root / "outside.json"), str(self.root / "input/../outside.json")):
            with self.assertRaises(ValueError):
                compile_bound(profile, {"input": source, "output": str(self.root / "out/result.json")})

    def test_output_symlink_cannot_overwrite_another_object(self):
        profile = synthesise_bound(samples(self.root), "report")
        source = self.root / "input/source.json"; source.write_text("[]")
        victim = self.root / "victim.txt"; victim.write_text("KEEP")
        target = self.root / "out/result.json"; target.symlink_to(victim)
        with self.assertRaises(ValueError):
            compile_bound(profile, {"input": str(source), "output": str(target)})
        self.assertEqual(victim.read_text(), "KEEP")

    def test_hard_linked_input_and_output_require_review(self):
        import os
        profile = synthesise_bound(samples(self.root), "report")
        source = self.root / "input/source.json"; source.write_text("[]")
        target = self.root / "out/result.json"
        os.link(source, self.root / "alias.json")
        with self.assertRaises(ValueError):
            compile_bound(profile, {"input": str(source), "output": str(target)})
        (self.root / "alias.json").unlink()
        victim = self.root / "victim.txt"; victim.write_text("KEEP")
        os.link(victim, target)
        with self.assertRaises(ValueError):
            compile_bound(profile, {"input": str(source), "output": str(target)})
        self.assertEqual(victim.read_text(), "KEEP")

    def test_rare_dependency_is_retained_in_hybrid_candidate(self):
        common = synthesise_bound(samples(self.root), "report")
        hybrid = synthesise_bound(samples(self.root), "report", include_rare=True)
        self.assertNotIn(str(self.root / "settings.json"), [r["resource"] for r in common["rules"]])
        self.assertIn(str(self.root / "settings.json"), [r["resource"] for r in hybrid["rules"]])

    def test_pruning_cannot_remove_a_validation_required_dependency(self):
        profile = synthesise_bound(samples(self.root), "report", include_rare=True)
        required = str(self.root / "settings.json")
        pruned = prune_stable(profile, lambda p: any(r["resource"] == required for r in p["rules"]))
        self.assertIn(required, [r["resource"] for r in pruned["rules"]])

    def test_selection_uses_utility_and_security_before_size(self):
        good = {"name": "good", "benign_successes": 3, "benign_total": 3, "harmful_effects": 0,
                "excess_pairs": 1, "rule_count": 4}
        overstrict = {**good, "name": "broken", "benign_successes": 0, "rule_count": 0}
        insecure = {**good, "name": "broad", "harmful_effects": 1, "rule_count": 1}
        self.assertEqual(choose_candidate([overstrict, insecure, good]), "good")
        with self.assertRaises(ValueError):
            choose_candidate([overstrict, insecure])

    def test_identical_parameter_values_cannot_be_assigned_two_roles(self):
        traces = samples(self.root)
        for sample in traces:
            sample["bindings"]["output"] = sample["bindings"]["input"]
        with self.assertRaises(ValueError):
            synthesise_bound(traces, "report")


if __name__ == "__main__":
    unittest.main()
