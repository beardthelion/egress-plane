#!/usr/bin/env python3
"""Emit data/inventory/go.toml by walking $GOROOT/src at source level.

With no --goroot the script asks `go env GOROOT` and refuses unless
`go version` reports go1.26.8. A directory is a package when it holds at
least one non-_test.go file whose package clause is not main, outside
internal, vendor, testdata, and cmd path elements and outside
src/builtin; build constraints are ignored. Members are the exported
top-level names (types, functions, variables, constants) plus exported
methods written Type.Method, emitted for the modules that
data/primitives/go.toml marks class = "egress".

  python3 scripts/inventory/go.py            # writes data/inventory/go.toml
  python3 scripts/inventory/go.py --check    # compares without writing
"""

import argparse
import os
import re
import subprocess
import sys
import tomllib
from itertools import zip_longest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
OUT = REPO / "data" / "inventory" / "go.toml"
PRIMITIVES = REPO / "data" / "primitives" / "go.toml"

EXPECTED_VERSION = "1.26.8"

# Directory path elements a package cannot live under (KTD9), plus the
# whole of src/builtin; `.`- and `_`-prefixed elements are skipped the
# way the toolchain skips them.
SKIP_DIRS = {"internal", "vendor", "testdata", "cmd", "builtin"}

# A token that can end a declaration entry: a name, a literal, or a
# closing bracket. Anything else (`=`, `+`, `,`, an open bracket, a
# keyword) means the next line continues the entry.
ENTRY_ENDING = {"id", "num", "str", ")", "]", "}"}

# A `func` preceded at top level by one of these is a literal or a
# statement keyword's operand, never a declaration.
FUNC_OPERAND = {"=", ",", "(", "[", ":", "go", "defer", "return"}


def die(msg):
    sys.exit(f"go.py: {msg}")


def goroot(arg):
    """The GOROOT to walk: --goroot (checked against its VERSION file),
    else `go env GOROOT` with `go version` pinned."""
    if arg:
        root = Path(arg)
        version_file = root / "VERSION"
        if not version_file.is_file():
            die(f"{version_file}: not found; cannot confirm the Go version")
        report = version_file.read_text().split()[0]
    else:
        try:
            out = subprocess.run(
                ["go", "env", "GOROOT"], check=True, capture_output=True, text=True
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as e:
            die(f"go env GOROOT failed: {e}")
        root = Path(out)
        try:
            report = subprocess.run(
                ["go", "version"], check=True, capture_output=True, text=True
            ).stdout.split()[2]
        except (OSError, subprocess.CalledProcessError, IndexError) as e:
            die(f"go version failed: {e}")
    if report != f"go{EXPECTED_VERSION}":
        die(
            f"expected go{EXPECTED_VERSION}, found {report}; "
            "point --goroot at a matching toolchain"
        )
    return root


def package_clause(text):
    m = re.search(r"^package\s+([A-Za-z_]\w*)", text, re.MULTILINE)
    return m.group(1) if m else None


def lex(text):
    """A Go token stream: (kind, value, line). Kind is `id`, `num`,
    `str` (interpreted, rune, or raw literal), or the single punctuation
    character. Comments are skipped; an unterminated construct runs to
    the end of the file."""
    i, n = 0, len(text)
    line = 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "/" and text[i + 1 : i + 2] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and text[i + 1 : i + 2] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                return
            line += text[i : j + 2].count("\n")
            i = j + 2
        elif c == '"' or c == "'":
            start = i
            i += 1
            while i < n and text[i] not in (c, "\n"):
                i += 2 if text[i] == "\\" else 1
            line += text[start:i].count("\n")
            yield ("str", text[start:i], line)
            i += 1
        elif c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                yield ("str", text[i:], line)
                return
            line += text[i : j + 1].count("\n")
            yield ("str", text[i : j + 1], line)
            i = j + 1
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            yield ("id", text[i:j], line)
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_."):
                j += 1
            yield ("num", text[i:j], line)
            i = j
        else:
            yield (c, c, line)
            i += 1


def receiver_type(inner):
    """The receiver's type name from the tokens inside `func ( ... )`:
    the ident after a `*`, else the second ident when several appear
    (the first is the parameter name), else the only ident."""
    for j, (kind, _, _) in enumerate(inner):
        if kind == "*" and j + 1 < len(inner) and inner[j + 1][0] == "id":
            return inner[j + 1][1]
    ids = [v for k, v, _ in inner if k == "id"]
    if len(ids) == 1:
        return ids[0]
    if len(ids) >= 2:
        return ids[1]
    return None


def leading_names(toks, start):
    """The comma-separated identifier list a declaration opens with on
    one line (`var a, b = ...`); returns (names, next index)."""
    names = []
    i = start
    line = toks[i][2]
    while i < len(toks) and toks[i][0] == "id" and toks[i][2] == line:
        names.append(toks[i][1])
        i += 1
        if i < len(toks) and toks[i][0] == "," and toks[i][2] == line:
            i += 1
        else:
            break
    return names, i


def block_names(toks, i, decl, out):
    """Reads a `type (`/`var (`/`const (` block starting just after the
    `(`: each entry opens on a new line or after `;` at the block's own
    depth, and every entry's leading name list is collected. A line
    whose previous top token is not entry-ending continues the entry.
    Returns the index after the closing `)`."""
    n = len(toks)
    pdepth = 1
    bdepth = 0
    prev = None
    while i < n:
        k, _, line = toks[i]
        if k == "(":
            pdepth += 1
        elif k == ")":
            pdepth -= 1
            prev = toks[i]
            i += 1
            if pdepth == 0:
                break
            continue
        elif k == "{":
            bdepth += 1
            prev = toks[i]
            i += 1
            continue
        elif k == "}":
            bdepth = max(0, bdepth - 1)
            prev = toks[i]
            i += 1
            continue
        if pdepth == 1 and bdepth == 0:
            new_entry = (
                prev is None
                or prev[0] == ";"
                or (line != prev[2] and prev[0] in ENTRY_ENDING)
            )
            if new_entry and k == "id":
                names, nxt = leading_names(toks, i)
                take = names[:1] if decl == "type" else names
                out.update(nm for nm in take if nm[:1].isupper())
                prev = toks[nxt - 1]
                i = nxt
                continue
        prev = toks[i]
        i += 1
    return i


def file_members(text):
    """The exported top-level names one file declares: types, functions,
    variables, constants, and methods written `Type.Method`."""
    toks = list(lex(text))
    out = set()
    i, n = 0, len(toks)
    bdepth = 0
    prev = None
    while i < n:
        kind, val, _ = toks[i]
        if kind == "{":
            bdepth += 1
            prev = toks[i]
            i += 1
            continue
        if kind == "}":
            bdepth = max(0, bdepth - 1)
            prev = toks[i]
            i += 1
            continue
        if bdepth == 0 and kind == "id" and val == "func":
            if prev is not None and prev[0] in FUNC_OPERAND:
                # A function literal in an expression or a go/defer
                # statement, not a declaration.
                prev = toks[i]
                i += 1
                continue
            j = i + 1
            if j < n and toks[j][0] == "(":
                # A method: the receiver group, then the method name.
                inner = []
                p = j + 1
                while p < n and toks[p][0] != ")":
                    inner.append(toks[p])
                    p += 1
                p += 1
                if p < n and toks[p][0] == "id" and toks[p][1][:1].isupper():
                    ty = receiver_type(inner)
                    if ty:
                        out.add(f"{ty}.{toks[p][1]}")
                prev = toks[i] if p <= i else toks[p - 1]
                i = p + 1
            elif j < n and toks[j][0] == "id" and toks[j][2] == toks[i][2]:
                if toks[j][1][:1].isupper():
                    out.add(toks[j][1])
                prev = toks[j]
                i = j + 1
            else:
                prev = toks[i]
                i = j
            continue
        if bdepth == 0 and kind == "id" and val in ("type", "var", "const"):
            j = i + 1
            if j < n and toks[j][0] == "(":
                prev = toks[j]
                i = block_names(toks, j + 1, val, out)
                continue
            if j < n and toks[j][0] == "id" and toks[j][2] == toks[i][2]:
                names, nxt = leading_names(toks, j)
                take = names[:1] if val == "type" else names
                out.update(nm for nm in take if nm[:1].isupper())
                prev = toks[nxt - 1]
                i = nxt
                continue
            prev = toks[i]
            i = j
            continue
        if bdepth == 0:
            prev = toks[i]
        i += 1
    return out


def packages(goroot_dir):
    """Import path -> member set for every package directory under
    $GOROOT/src. Only directories passing the path-element rules and
    holding a non-main, non-test file count."""
    src = Path(goroot_dir) / "src"
    found = {}
    for dirpath, dirnames, filenames in os.walk(src):
        rel = Path(dirpath).relative_to(src)
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if d not in SKIP_DIRS and not d.startswith((".", "_"))
        ]
        if any(e in SKIP_DIRS for e in rel.parts):
            dirnames[:] = []
            continue
        members = set()
        pkg = None
        for f in sorted(filenames):
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            text = (Path(dirpath) / f).read_text(errors="replace")
            name = package_clause(text)
            if name is None or name == "main":
                continue
            if pkg is None:
                pkg = name
            members |= file_members(text)
        if pkg is not None:
            path = "/".join(rel.parts)
            if not path:
                die(f"{dirpath}: a package cannot live directly in $GOROOT/src")
            found[path] = members
    return found


def egress_modules():
    """The module paths data/primitives/go.toml marks `class = "egress"`."""
    raw = tomllib.loads(PRIMITIVES.read_text())
    if raw.get("language") != "go":
        die(f"{PRIMITIVES}: language is not go")
    return {m["name"] for m in raw.get("module", []) if m.get("class") == "egress"}


def toml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(stdlib, members):
    out = [
        f"# Generated by scripts/inventory/go.py from Go {EXPECTED_VERSION}. Do not edit.",
        'language = "go"',
        f'generated_from = ["{EXPECTED_VERSION}"]',
        "not_generated = []",
        "stdlib_modules = [",
    ]
    out += [f"    {toml_str(m)}," for m in stdlib]
    out.append("]")
    out.append("")
    out.append("[members]")
    for mod in sorted(members):
        out.append(f"{toml_str(mod)} = [")
        out += [f"    {toml_str(m)}," for m in sorted(members[mod])]
        out.append("]")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goroot", help="GOROOT to walk instead of `go env GOROOT`")
    ap.add_argument(
        "--check", action="store_true", help="compare against the file without writing"
    )
    args = ap.parse_args()
    root = goroot(args.goroot)

    found = packages(root)
    egress = egress_modules()
    missing = sorted(egress - set(found))
    if missing:
        die(f"{PRIMITIVES}: egress module {missing[0]} is not a package under $GOROOT/src")
    members = {p: found[p] for p in sorted(egress)}

    stdlib = sorted(found)
    text = render(stdlib, members)
    if args.check:
        try:
            existing = OUT.read_text()
        except FileNotFoundError:
            die(f"{OUT}: not found; run without --check")
        if existing != text:
            stale = None
            try:
                old = tomllib.loads(existing)
                new = tomllib.loads(text)
                for a, b in zip_longest(
                    new["stdlib_modules"], old["stdlib_modules"]
                ):
                    if a != b:
                        stale = a or b
                        break
                if stale is None:
                    om, nm = old["members"], new["members"]
                    for mod in sorted(set(om) | set(nm)):
                        if om.get(mod) != nm.get(mod):
                            stale = mod
                            break
            except Exception:
                pass
            die(
                f"{OUT}: out of date"
                + (f" (first difference: {stale})" if stale else "")
                + "; run scripts/inventory/go.py"
            )
        print("go.py: data/inventory/go.toml is up to date")
        return
    OUT.write_text(text)
    print(f"go.py: wrote {OUT} ({len(stdlib)} packages)")


if __name__ == "__main__":
    main()
