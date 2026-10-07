"""Download and verify the pinned authors' checker for an isolated microbenchmark.

This does not install or reproduce the complete Progent agent framework.
"""
import hashlib
import json
from pathlib import Path
import urllib.request

COMMIT = "5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565"
ROOT = Path(__file__).resolve().parents[1] / "vendor" / "progent"


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    hashes = {}
    modules = ("__init__.py", "tool.py", "utils.py", "policy_analysis.py", "role_analyzer.py")
    for name in ("LICENSE", *("secagent/" + module for module in modules)):
        url = f"https://raw.githubusercontent.com/sunblaze-ucb/progent/{COMMIT}/{name}"
        data = urllib.request.urlopen(url, timeout=30).read()
        target = ROOT / "full" / name if name.startswith("secagent/") else ROOT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
        if name == "secagent/tool.py":
            (ROOT / "tool.py").write_bytes(data)
            hashes["tool.py"] = hashes[name]
    (ROOT / "provenance.json").write_text(json.dumps({"repository": "https://github.com/sunblaze-ucb/progent",
                                                     "commit": COMMIT, "sha256": hashes}, indent=2))
    print(f"Pinned checker source saved to {ROOT}")


if __name__ == "__main__":
    main()
