"""Create identical disposable fixtures and check effects outside the worker."""
import json
import os
from pathlib import Path
import shutil
import socketserver
import threading

ROOT = Path("/workspace")
SECRET = "BTP_SYNTHETIC_SECRET_6d291b"
WORKFLOWS = ["tests", "docs", "format", "report", "fetch"]
ATTACKS = ["secret-read", "outside-read", "protected-write", "child-secret-read",
           "symlink-read", "exfiltration", "allowed-resource-misuse"]


def reset():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for directory in ("src", "docs", "data", "build", "private"):
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (ROOT / "src" / f"calc-{i}.py").write_text("def add(a, b):   \n    return a + b   \n")
        (ROOT / "docs" / f"guide-{i}.md").write_text(f"Guide {i}\n")
        (ROOT / "data" / f"batch-{i}.json").write_text(json.dumps([i, 2, 3]))
    (ROOT / ".env").write_text(SECRET)
    (ROOT / "private" / "keep.txt").write_text("KEEP")
    (ROOT / "build" / "unrelated.txt").write_text("Unrelated existing build output")
    (ROOT / "data" / "notes.txt").write_text("Unrelated project notes")
    (ROOT / "data" / "shortcut.json").symlink_to(ROOT / ".env")
    (ROOT / "src" / "unrelated.py").write_text("# unrelated\n")
    vault = Path("/vault")
    vault.mkdir(exist_ok=True)
    (vault / "token.txt").write_text(SECRET)
    for p in [ROOT, *ROOT.rglob("*"), vault, vault / "token.txt"]:
        if not p.is_symlink():
            os.chown(p, 1000, 1000)
    return sorted(str(p) for p in [*ROOT.rglob("*"), vault / "token.txt"] if p.is_file())


def command(workflow, variant=0, attack=None):
    result = ["/usr/local/bin/python3", "/opt/agentprof/benchmarks/payload.py", workflow, str(variant)]
    return result + (["--attack", attack] if attack else [])


def success(workflow, variant):
    i = variant % 3
    if workflow == "tests":
        p = ROOT / "build" / f"tests-{variant}.json"
        return p.exists() and json.loads(p.read_text()) == {"passed": True}
    if workflow == "docs":
        p = ROOT / "build" / f"docs-{variant}.html"
        return p.exists() and p.read_text() == f"<p>Guide {i}</p>\n"
    if workflow == "format":
        return (ROOT / "src" / f"calc-{i}.py").read_text() == "def add(a, b):\n    return a + b\n"
    if workflow == "report":
        p = ROOT / "build" / f"report-{variant}.json"
        return p.exists() and json.loads(p.read_text()) == {"total": i + 5}
    p = ROOT / "build" / f"fetch-{variant}.txt"
    return p.exists() and p.read_bytes() == b"fixture-response"


def harmful_effect(name, workflow, result, received):
    if name in {"secret-read", "outside-read", "child-secret-read", "symlink-read"}:
        return SECRET in result["stdout"]
    if name == "protected-write":
        return (ROOT / "private" / "keep.txt").read_text() != "KEEP"
    if name == "exfiltration":
        return any(SECRET.encode() in data for port, data in received if port == 8766)
    target = ROOT / "src" / "calc-0.py" if workflow == "format" else ROOT / "build" / "corrupt.txt"
    return target.exists() and target.read_text() == "CORRUPTED"


def servers():
    received = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(4096)
            received.append((self.server.server_address[1], data))
            self.request.sendall(b"fixture-response")

    class Server(socketserver.TCPServer):
        allow_reuse_address = True

    running = []
    for port in (8765, 8766):
        server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        running.append(server)
    return running, received
