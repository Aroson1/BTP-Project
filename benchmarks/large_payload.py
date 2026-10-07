"""Ten small executable workflows, with both structured and code tool entrypoints."""
import json
from pathlib import Path
import sys


def transform(kind, source, target):
    source, target = Path(source), Path(target)
    if kind == "json-total":
        result = {"total": sum(json.loads(source.read_text()))}
    elif kind == "csv-total":
        import csv
        rows = list(csv.DictReader(source.read_text().splitlines()))
        factor = 1
        if rows[0].get("scaled") == "yes":
            factor = json.loads((source.parent.parent / "settings.json").read_text())["factor"]
        result = {"total": sum(int(r["amount"]) for r in rows) * factor}
    elif kind == "log-count":
        result = {"errors": sum(" ERROR " in line for line in source.read_text().splitlines())}
    elif kind == "markdown":
        import html
        result = {"html": "<p>" + html.escape(source.read_text().strip()) + "</p>"}
    elif kind == "config-check":
        import tomllib
        result = {"name": tomllib.loads(source.read_text())["project"]["name"]}
    elif kind == "python-check":
        import ast
        tree = ast.parse(source.read_text())
        result = {"functions": [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]}
    elif kind == "python-tests":
        namespace = {}
        exec(compile(source.read_text(), str(source), "exec"), namespace)
        assert namespace["add"](2, 3) == 5
        result = {"passed": True}
    elif kind == "archive-manifest":
        import zipfile
        with zipfile.ZipFile(source) as archive:
            result = {"files": sorted(archive.namelist())}
    elif kind == "sqlite-report":
        import sqlite3
        with sqlite3.connect("file:" + str(source) + "?mode=ro", uri=True) as db:
            result = {"total": db.execute("select sum(amount) from records").fetchone()[0]}
    elif kind == "hash":
        import hashlib
        result = {"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    else:
        raise ValueError(kind)
    target.write_text(json.dumps(result, sort_keys=True))


def dispatch(request):
    tool, args = request["tool"], request["args"]
    if tool == "run_workflow":
        transform(args["kind"], args["source"], args["target"])
    elif tool == "read_file":
        print(Path(args["path"]).read_text())
    elif tool == "write_file":
        Path(args["path"]).write_text(args["text"])
    elif tool == "exec_python":
        exec(args["code"], {"__name__": "__main__"})
    else:
        raise ValueError(tool)


if __name__ == "__main__":
    dispatch(json.loads(sys.argv[1]))
