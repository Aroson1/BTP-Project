"""Real, unmodified upstream secure_tool_wrapper; manually supplied policies."""
import hashlib
import json
import os
from pathlib import Path
import sys


class ProgentGate:
    def __init__(self):
        os.environ["SECAGENT_GENERATE"] = "False"
        sys.path.insert(0, "/opt/progent")
        self.execute = None
        root = Path("/opt/progent")
        self.provenance = json.loads((root / "provenance.json").read_text())
        for name, expected in self.provenance["sha256"].items():
            if name.startswith("secagent/"):
                assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
        import secagent.tool as upstream
        assert upstream.generate_policy is False
        self.upstream = upstream

        # The wrapper runs in the trusted controller. Only approved calls launch a worker.
        def run_workflow(kind: str, source: str, target: str):
            """Execute the known workflow with the supplied paths."""
            return self.execute({"tool": "run_workflow", "args": {"kind": kind, "source": source, "target": target}})

        def read_file(path: str):
            """Read a file."""
            return self.execute({"tool": "read_file", "args": {"path": path}})

        def write_file(path: str, text: str):
            """Write text to a file."""
            return self.execute({"tool": "write_file", "args": {"path": path, "text": text}})

        def exec_python(code: str):
            """Execute Python code."""
            return self.execute({"tool": "exec_python", "args": {"code": code}})

        self.tools = {f.__name__: upstream.secure_tool_wrapper(f)
                      for f in (run_workflow, read_file, write_file, exec_python)}

    def configure(self, task, bindings, exact_code, mode):
        enum = lambda value: {"enum": [value]}
        def safe_input(path):
            candidate = Path(path)
            return (path == bindings["input"] and candidate.is_file() and candidate.stat().st_nlink == 1
                    and not any(p.is_symlink() for p in [candidate, *candidate.parents]))
        def safe_code(code):
            return code == exact_code and safe_input(bindings["input"])
        source_restriction = safe_input if mode == "hardened" else enum(bindings["input"])
        policy = {
            "run_workflow": [(1, 0, {"kind": enum(task["kind"]), "source": source_restriction,
                                    "target": enum(bindings["output"])}, 0)],
            "read_file": [(1, 0, {"path": source_restriction}, 0)],
            "write_file": [(1, 0, {"path": enum(bindings["output"])}, 0)],
        }
        if mode != "structured":
            restriction = r"(?s)^.*$" if mode == "open" else safe_code if mode == "hardened" else enum(exact_code)
            policy["exec_python"] = [(1, 0, {"code": restriction}, 0)]
        self.upstream.security_policy = policy
        self.upstream.init_user_query = "complete the trusted known workflow"
        self.upstream.sort_policy()
        return policy

    def call(self, request, execute):
        self.execute = execute
        try:
            result = self.tools[request["tool"]](**request["args"])
            result["tool_gate_denied"] = False
            return result
        except self.upstream.ValidationError as error:
            return {"exit_code": 126, "stdout": "", "stderr": str(error), "seconds": 0,
                    "tool_gate_denied": True}
