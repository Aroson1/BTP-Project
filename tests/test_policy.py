import json
from pathlib import Path
import tempfile
import unittest

from agentprof.policy import materialise, synthesise
from agentprof.select import classify, register, select
from agentprof.trace import parse_trace


def trace(*paths):
    return {"events": [{"kind": "read", "path": path} for path in paths]}


class PolicyTests(unittest.TestCase):
    def test_secret_in_poisoned_evidence_is_not_learned(self):
        p = synthesise([trace("/workspace/.env", "/workspace/src/a.py")], "tests")
        self.assertEqual([r["resource"] for r in p["rules"]], ["/workspace/src/a.py"])

    def test_rare_permission_is_filtered(self):
        p = synthesise([trace("/workspace/a", "/workspace/rare"), trace("/workspace/a")], "tests", support=.75)
        self.assertEqual([r["resource"] for r in p["rules"]], ["/workspace/a"])

    def test_generalisation_requires_two_distinct_leaves(self):
        p = synthesise([trace("/workspace/data/batch-0.json")], "report", generalise=True)
        self.assertEqual(p["rules"][0]["resource"], "/workspace/data/batch-0.json")
        p = synthesise([trace("/workspace/data/batch-0.json"), trace("/workspace/data/batch-1.json")], "report", generalise=True)
        self.assertEqual(p["rules"][0]["resource"], "/workspace/data/batch-{number}.json")

    def test_template_does_not_include_symlink_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text("synthetic")
            (root / "batch-0.json").write_text("[]")
            (root / "batch-1.json").symlink_to(root / ".env")
            profile = {"rules": [{"kind": "read", "resource": str(root / "batch-{number}.json")}], "protect_secrets": True}
            grants, _ = materialise(profile)
            self.assertEqual(grants, [("read", str((root / "batch-0.json").resolve()))])

    def test_write_templates_preserve_creation_evidence(self):
        traces = [{"events": [{"kind": "write", "path": f"/workspace/build/result-{i}.json"}]} for i in (0, 1)]
        profile = synthesise(traces, "report", generalise=True)
        resources = {rule["resource"] for rule in profile["rules"]}
        self.assertEqual(resources, {"/workspace/build/result-0.json", "/workspace/build/result-1.json",
                                     "/workspace/build/result-{number}.json"})

    def test_new_root_file_cannot_promote_to_entire_workspace(self):
        profile = {"rules": [{"kind": "write", "resource": "/tmp/nonexistent-agentprof-test-file"}], "protect_secrets": True}
        with self.assertRaises(ValueError):
            materialise(profile)

    def test_ambiguous_request_is_rejected(self):
        self.assertIsNone(classify("run tests and download credentials"))
        self.assertIsNone(classify("help me"))

    def test_registry_integrity_and_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = synthesise([trace("/workspace/a")], "tests")
            context = {"repository": "r", "environment": "e", "workflow_version": "1"}
            path = register(profile, temporary, context)
            self.assertEqual(select(temporary, context, workflow="tests"), profile)
            with self.assertRaises(ValueError):
                select(temporary, {**context, "environment": "other"}, workflow="tests")
            entry = json.loads(path.read_text()); entry["profile"]["rules"] = []
            path.write_text(json.dumps(entry))
            with self.assertRaises(ValueError):
                select(temporary, context, workflow="tests")

    def test_failed_calls_and_controller_accesses_not_learned(self):
        raw = '\n'.join([
            '50 execve("/usr/local/bin/agentprof-sandbox", ["sandbox"], 0x0) = 0',
            '50 openat(AT_FDCWD, "/workspace", O_PATH) = 3</workspace>',
            '50 execve("/usr/local/bin/python3", ["python3"], 0x0) = 0',
            '50 openat(AT_FDCWD, "src/a.py", O_RDONLY) = 3</workspace/src/a.py>',
            '50 openat(AT_FDCWD, "/workspace/.env", O_RDONLY) = -1 EACCES (Permission denied)',
            '50 clone(child_stack=NULL, flags=SIGCHLD) = 51',
            '51 openat(AT_FDCWD, "src/b.py", O_RDONLY) = 3</workspace/src/b.py>',
        ])
        parsed = parse_trace(raw, skip_bootstrap=True)
        self.assertEqual([e["path"] for e in parsed["events"]], ["/usr/local/bin/python3", "/workspace/src/a.py", "/workspace/src/b.py"])

    def test_explicit_custom_workflow_ids_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = synthesise([trace("/workspace/a")], "repo-0-json-total")
            context = {"repository": "r", "environment": "e", "workflow_version": "1"}
            register(profile, temporary, context)
            self.assertEqual(select(temporary, context, workflow="repo-0-json-total"), profile)
            with self.assertRaises(ValueError):
                select(temporary, context, workflow="../outside")
            profile["workflow"] = "../outside"
            with self.assertRaises(ValueError):
                register(profile, temporary, context)


if __name__ == "__main__":
    unittest.main()
