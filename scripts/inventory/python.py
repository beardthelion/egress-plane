#!/usr/bin/env python3
"""Generate data/inventory/python.toml.

Usage:
    python3 scripts/inventory/python.py --python /path/to/python3.11 \
        --python /path/to/python3.12 ... [--check]

The orchestrating interpreter must be 3.11 or later (it reads TOML with
tomllib). Each `--python` interpreter is probed in a subprocess, and the
results are merged as a union:

- `stdlib_modules`: `sys.stdlib_module_names` from every probed interpreter,
  plus the modules in REMOVED_BEFORE_3_11 for versions of the declared range
  that predate `sys.stdlib_module_names` (3.8 and 3.9) or that removed a module
  before 3.11. Those names come from the CPython "What's New" removal notes,
  not from probing, and the output header says so.
- `members`: the full `dir()` of every module classified `egress` in
  data/primitives/python.toml and of every deny-list module, minus the
  standard module metadata dunders, plus the immediate submodules of packages.
  A module covered wholly by an `egress` or `blind-spot` entry whose ID is the
  module itself is skipped, since that entry classifies every member.

Versions of the declared range (3.8 to 3.13) without a `--python` are listed in
`not_generated`. With `--check`, the script exits 1 if the output would differ
from the checked-in file instead of writing it.

This is a development tool run outside the scanner binary.
"""

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PRIMITIVES = REPO / "data" / "primitives" / "python.toml"
OUT = REPO / "data" / "inventory" / "python.toml"

RANGE = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"]

# Deny list. A module here may never be wholly inert and always gets an
# inventory. The data guard test holds its own copy.
DENY = [
    "asyncio", "logging.config", "logging.handlers", "multiprocessing",
    "concurrent.futures", "pkgutil", "runpy", "importlib", "importlib.abc",
    "importlib.machinery", "importlib.metadata", "importlib.resources",
    "importlib.util", "site", "sys", "builtins", "tkinter", "sqlite3",
    "platform", "ctypes.util", "webbrowser", "pydoc", "ensurepip", "venv",
    "xml.sax", "xml.dom", "timeit", "code", "codeop", "pdb", "bdb", "cProfile",
    "profile", "trace", "doctest", "marshal", "types", "gc", "inspect",
]

# Standard library modules present in part of the range but absent from every
# interpreter that has sys.stdlib_module_names (3.10 and later), per the
# CPython What's New removal notes.
REMOVED_BEFORE_3_11 = {
    "_dummy_thread": "removed in 3.9",
    "dummy_threading": "removed in 3.9",
    "_bootlocale": "removed in 3.10",
    "_peg_parser": "present in 3.9 only",
    "formatter": "removed in 3.10",
    "parser": "removed in 3.10",
    "symbol": "removed in 3.10",
    "binhex": "removed in 3.11",
}

# Modules with import side effects that must never be imported by the probe.
NEVER_IMPORT = {"antigravity", "this", "__hello__", "__phello__", "idlelib.idle"}

PROBE = r"""
import importlib, json, pkgutil, sys, warnings
warnings.simplefilter("ignore")
req = json.load(sys.stdin)
STD_DUNDERS = {"__all__", "__builtins__", "__cached__", "__doc__", "__file__",
               "__loader__", "__name__", "__package__", "__path__", "__spec__"}
out = {"version": "%d.%d.%d" % sys.version_info[:3],
       "stdlib": sorted(getattr(sys, "stdlib_module_names", [])),
       "members": {}, "failed": {}}
for name in req["modules"]:
    try:
        mod = importlib.import_module(name)
    except BaseException as e:
        out["failed"][name] = type(e).__name__
        continue
    names = set(n for n in dir(mod) if n not in STD_DUNDERS)
    path = getattr(mod, "__path__", None)
    if path is not None:
        for info in pkgutil.iter_modules(path):
            names.add(info.name)
    out["members"][name] = sorted(names)
json.dump(out, sys.stdout)
"""


def wanted_modules():
    data = tomllib.loads(PRIMITIVES.read_text())
    covered = set()
    for e in data.get("entry", []):
        if e.get("kind") in ("egress", "blind-spot"):
            covered.add(e["id"].split(":", 1)[1])
    mods = {m["name"] for m in data.get("module", []) if m.get("class") == "egress"}
    mods |= set(DENY)
    return sorted(m for m in mods if m not in covered and m not in NEVER_IMPORT)


def probe(python, modules):
    r = subprocess.run(
        [python, "-I", "-c", PROBE],
        input=json.dumps({"modules": modules}),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(r.stdout)


def toml_str(s):
    return json.dumps(s, ensure_ascii=False)


def render(results, modules):
    versions = sorted(r["version"] for r in results)
    have = {".".join(v.split(".")[:2]) for v in versions}
    not_generated = [f"{v}: no interpreter supplied" for v in RANGE if v not in have]
    stdlib = set()
    for r in results:
        stdlib |= set(r["stdlib"])
    supplemented = sorted(set(REMOVED_BEFORE_3_11) - stdlib)
    stdlib |= set(REMOVED_BEFORE_3_11)
    members = {}
    failed = {}
    for r in results:
        for m, names in r["members"].items():
            members.setdefault(m, set()).update(names)
        for m, why in r["failed"].items():
            failed.setdefault(m, []).append(f"{r['version']} {why}")
    for m in modules:
        if m not in members:
            not_generated.append(
                f"module {m}: not importable on this host ({'; '.join(failed.get(m, []))})"
            )

    lines = [
        "# Generated by scripts/inventory/python.py. Do not edit by hand.",
        f"# Probed interpreters: {', '.join(versions)}.",
        "# Versions of the declared range 3.8 to 3.13 without an interpreter are",
        "# listed in not_generated; their members are not inventoried.",
        "# Modules added to stdlib_modules from the CPython What's New removal notes",
        f"# rather than by probing: {', '.join(f'{m} ({REMOVED_BEFORE_3_11[m]})' for m in supplemented)}.",
        "",
        'language = "python"',
        f"generated_from = [{', '.join(toml_str(v) for v in versions)}]",
        "not_generated = [",
        *[f"    {toml_str(x)}," for x in not_generated],
        "]",
        "stdlib_modules = [",
        *[f"    {toml_str(x)}," for x in sorted(stdlib)],
        "]",
        "",
        "[members]",
    ]
    for m in sorted(members):
        lines.append(f"{toml_str(m)} = [")
        lines.extend(f"    {toml_str(x)}," for x in sorted(members[m]))
        lines.append("]")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", action="append", required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    modules = wanted_modules()
    results = [probe(p, modules) for p in args.python]
    text = render(results, modules)
    if args.check:
        if OUT.read_text() != text:
            print(f"{OUT} is out of date", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
