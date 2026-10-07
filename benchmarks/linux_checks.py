"""Security regression checks with real kernel enforcement, not policy replay."""
from pathlib import Path
import sys

from agentprof.runtime import doctor, run
from .evaluate import manual
from .fixtures import reset, servers


def main():
    assert doctor()["supported"]
    reset()
    grants = manual("tests")
    checks = [
        ("read allowed file", "print(open('/workspace/src/calc-0.py').read())", True),
        ("deny workspace secret", "print(open('/workspace/.env').read())", False),
        ("deny outside secret", "print(open('/vault/token.txt').read())", False),
        ("deny direct symlink to secret", "print(open('/workspace/data/shortcut.json').read())", False),
        ("deny inherited child read", "import subprocess,sys; subprocess.run([sys.executable,'-c',\"print(open('/workspace/.env').read())\"],check=True)", False),
        ("deny unapproved executable", "import subprocess; subprocess.run(['/usr/bin/id'],check=True)", False),
        ("deny raw socket", "import socket; socket.socket(socket.AF_INET,socket.SOCK_RAW,1)", False),
        ("deny UDP socket", "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM)", False),
        ("deny protected write", "open('/workspace/private/keep.txt','w').write('CORRUPTED')", False),
        ("permit output creation", "open('/workspace/build/new.txt','w').write('ok')", True),
    ]
    for label, code, allowed in checks:
        result = run(["/usr/local/bin/python3", "-c", code], grants=grants)
        assert (result["exit_code"] == 0) == allowed, (label, result)
        assert result["exit_code"] != 125, ("launcher failure is not a successful security block", label)
        print("PASS:", label)
    active, _ = servers()
    try:
        for port, allowed in ((8765, True), (8766, False)):
            code = f"import socket; s=socket.create_connection(('127.0.0.1',{port})); s.sendall(b'probe'); s.recv(100); s.close()"
            result = run(["/usr/local/bin/python3", "-c", code], grants=manual("fetch"))
            assert (result["exit_code"] == 0) == allowed, result
            if not allowed:
                assert "PermissionError" in result["stderr"], result
            print("PASS: TCP port", port, "allowed =", allowed)
    finally:
        for server in active:
            server.shutdown(); server.server_close()
    # An exact leaf read must not become permission to read all sibling files.
    assert (Path("/workspace/private/keep.txt").read_text() == "KEEP")
    original = Path("/workspace/src/calc-0.py").read_text()
    rollback_grants = manual("format")
    code = "open('/workspace/src/calc-0.py','w').write('CORRUPTED'); open('/workspace/.env').read()"
    result = run(["/usr/local/bin/python3", "-c", code], grants=rollback_grants, rollback=True)
    assert result["rolled_back"] and Path("/workspace/src/calc-0.py").read_text() == original
    print("PASS: restore earlier permitted write after a failed run")
    print(f"{len(checks) + 3} Linux checks passed")


if __name__ == "__main__":
    main()
