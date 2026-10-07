"""Linux controller. The child runs as uid 1000; controller state is root-only."""
import json
import os
from pathlib import Path
import subprocess
import signal
import glob
import shutil
import time

from .policy import materialise
from .trace import parse_trace

SANDBOX = "/usr/local/bin/agentprof-sandbox"
CONTROL = Path("/run/agentprof")
BASE_READ = ["/usr", "/lib", "/lib64", "/opt/agentprof", "/etc/ld.so.cache",
             "/etc/localtime", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
             "/dev/null", "/dev/urandom", "/dev/random"]


def doctor():
    if not Path(SANDBOX).exists():
        return {"supported": False, "reason": "Run doctor inside the Docker image", "platform": os.uname().sysname}
    result = subprocess.run([SANDBOX, "--probe"], capture_output=True, text=True)
    return {**json.loads(result.stdout), "kernel": os.uname().release,
            "architecture": os.uname().machine, "python": os.sys.version.split()[0]}


def run(command, *, profile=None, grants=None, record=False, label="run", promotion=0, budget=0, rollback=False, bindings=None):
    CONTROL.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONTROL.chmod(0o700)
    expansions = []
    reserved_outputs = []
    if profile is not None:
        if profile["schema"] == 2:
            from .bound import compile_bound
            if bindings is None:
                raise ValueError("Request-bound profiles require trusted task bindings")
            grants, metadata = compile_bound(profile, bindings)
            expansions, reserved_outputs = metadata["expansions"], metadata["reserved_outputs"]
        else:
            grants, expansions = materialise(profile, promotion=promotion, budget=budget)
    lines = [("read", str(Path(p).resolve())) for p in BASE_READ if Path(p).exists()]
    # Executing a dynamically linked binary also executes its ELF loader.
    loaders = glob.glob("/lib/*/ld-linux*.so*") + glob.glob("/lib64/ld-linux*.so*")
    lines += [("exec", str(Path(p).resolve())) for p in loaders]
    lines += grants or []
    policy_file = CONTROL / (label + ".tsv")
    if any("\t" in path or "\n" in path for _, path in lines):
        raise ValueError("Tab/newline in resource name")
    policy_file.write_text("".join(kind + "\t" + path + "\n" for kind, path in sorted(set(lines))))
    policy_file.chmod(0o600)
    args = [SANDBOX, str(policy_file), "enforce" if profile is not None or grants is not None else "baseline", "--", *command]
    trace_file = CONTROL / (label + ".strace")
    if record:
        args = ["strace", "-f", "-qq", "-s", "4096", "-yy", "-e", "trace=%file,%network,%process", "-o", str(trace_file), *args]
    snapshot = CONTROL / (label + "-snapshot")
    owners = {}
    if rollback:
        if snapshot.exists():
            shutil.rmtree(snapshot)
        workspace = Path("/workspace")
        for path in [workspace, *workspace.rglob("*")]:
            stat = path.lstat()
            owners[str(path.relative_to(workspace))] = (stat.st_uid, stat.st_gid)
        shutil.copytree(workspace, snapshot, symlinks=True)
    start = time.perf_counter()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               start_new_session=True,
                               env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": "/opt/agentprof",
                                    "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C.UTF-8"})
    try:
        stdout, stderr = process.communicate(timeout=15)
        code = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        code, stdout, stderr = 124, "", "Execution timed out"
    # Background descendants are not allowed to outlive a supervised run.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    elapsed = time.perf_counter() - start
    if code == 125:
        if rollback:
            shutil.rmtree(snapshot)
        raise RuntimeError(f"Sandbox setup/launch failed; not a containment result: {stderr}")
    output = {"exit_code": code, "stdout": stdout, "stderr": stderr, "seconds": elapsed,
              "grants": grants, "expansions": expansions, "reserved_outputs": reserved_outputs}
    if rollback:
        if code != 0:
            shutil.rmtree("/workspace")
            shutil.copytree(snapshot, "/workspace", symlinks=True)
            for name, owner in owners.items():
                os.chown(Path("/workspace") / name, *owner, follow_symlinks=False)
        output["rolled_back"] = code != 0
        shutil.rmtree(snapshot)
    if record:
        output["trace"] = parse_trace(trace_file.read_text(), skip_bootstrap=True)
        output["raw_trace"] = trace_file.read_text()
    return output
