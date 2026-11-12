"""Print the pip dependencies (deps_pip) of the active BBoT modules that are missing from the current environment.

Scans run with --no-deps, and `uv sync` removes packages that are not in uv.lock (asyncpg for crt_db, aiosqlite for
gowitness...), so bin/osint checks them before every scan and installs what is missing. Module files are parsed with
ast (no BBoT import), which keeps the check at ~100 ms.

Usage: python -I tools/module_deps.py <modules dir>   -> one missing requirement per line
"""

import ast
import sys
from importlib import metadata
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement


def declared(modules_dir):
    deps = set()
    for path in Path(modules_dir).rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "deps_pip" for t in node.targets):
                try:
                    value = ast.literal_eval(node.value)
                except ValueError:
                    continue
                deps.update(str(d) for d in value or [])
    return sorted(deps)


def missing(deps):
    out = []
    for dep in deps:
        try:
            req = Requirement(dep)
        except InvalidRequirement:
            continue  # VCS URLs etc. cannot be checked
        if req.marker is not None and not req.marker.evaluate():
            continue
        try:
            version = metadata.version(req.name)
        except metadata.PackageNotFoundError:
            out.append(dep)
            continue
        if req.specifier and not req.specifier.contains(version, prereleases=True):
            out.append(dep)
    return out


if __name__ == "__main__":
    print("\n".join(missing(declared(sys.argv[1]))))
