"""Parse completed strace calls into a small, reviewable event format."""
import ast
import re
from pathlib import Path

CALL = re.compile(r"^\s*(?:\[pid\s+)?(?P<pid>\d+)\]?\s+(?P<name>\w+)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$")
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def parse_trace(text, cwd="/workspace", *, skip_bootstrap=False):
    events, skipped = [], 0
    directories = {}
    active = set()
    for line in text.splitlines():
        match = CALL.match(line)
        if not match:
            if "unfinished ..." in line or "resumed>" in line:
                skipped += 1
            continue
        pid, name, args, result = (match[k] for k in ("pid", "name", "args", "result"))
        if skip_bootstrap:
            if name == "execve" and "agentprof-sandbox" not in args and not result.startswith("-1"):
                active.add(pid)
            if pid not in active:
                continue
            if name in {"clone", "clone3", "fork", "vfork"} and result.split()[0].isdigit():
                child = result.split()[0]
                active.add(child)
                directories[child] = directories.get(pid, cwd)
        if result.startswith("-1") and not (name == "connect" and "EINPROGRESS" in result):
            continue  # A failed attempt is not evidence that the task needs authority.
        strings = QUOTED.findall(args)
        if name in {"open", "openat", "openat2", "execve", "execveat", "chdir"} and strings:
            raw = ast.literal_eval(strings[0])
            base = directories.get(pid, cwd)
            fd_path = re.match(r"\d+<([^>]+)>", args)
            if fd_path:
                base = fd_path[1]
            path = str(Path(raw) if raw.startswith("/") else Path(base) / raw)
            path = str(Path(path).resolve())
            if name == "chdir":
                directories[pid] = path
                continue
            kind = "exec" if name.startswith("exec") else "read"
            if kind == "read" and any(flag in args for flag in ("O_WRONLY", "O_RDWR")):
                kind = "write"
            if kind == "read" and ("O_DIRECTORY" in args or Path(path).is_dir()):
                kind = "list"
            events.append({"kind": kind, "path": path, "pid": int(pid), "syscall": name})
            if kind == "write" and "O_RDWR" in args:
                events.append({"kind": "read", "path": path, "pid": int(pid), "syscall": name})
        if name == "connect":
            port = re.search(r"sin6?_port=htons\((\d+)\)", args)
            if port:
                events.append({"kind": "connect", "port": int(port[1]), "pid": int(pid), "syscall": name})
    # Explicitly expose incompleteness; this parser supports the controlled fixtures.
    return {"events": events, "skipped_split_calls": skipped, "format": "strace-fixtures-v1"}
