#!/usr/bin/env python3
"""Regenerate hash records inside dependency corpus fixtures.

Usage:
    python3 scripts/fixtures/dependency_hashes.py [--check]

For every case directory under fixtures/corpus/<language>/dependencies/:

- Each `.cargo-checksum.json` (a vendored crate's install record) is
  rewritten: `files` maps every file under the crate directory, relative
  with `/` separators, to its lowercase hex SHA-256, and `package` holds
  the crate's `checksum` from a `Cargo.lock` under the case's `tree/`, or
  null when no lock lists the crate or the locked checksums disagree.
- Each `*.dist-info/RECORD` keeps its authored path list but recomputes
  every row's `sha256=<urlsafe base64, no padding>` and size columns from
  the file, relative to the `*.dist-info` parent. `RECORD` itself and
  `*.pyc` rows stay hashless.

A case's `hash-overrides.toml` (`paths = [...]`) lists record paths kept
exactly as written, so modified-package cases can hold a stale record on
purpose. A Cargo override keeps the path's existing recorded hash, or a
zero hash when the record has none; a RECORD override keeps the whole row.

With `--check`, nothing is written: each stale record prints its path and
the script exits 1.

This is a development tool run outside the scanner binary; standard
library only, no network.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "fixtures" / "corpus"

ZERO_SHA256 = "0" * 64


def cases():
    """Every case directory under a `dependencies` category, sorted."""
    out = []
    for lang in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        deps = lang / "dependencies"
        if not deps.is_dir():
            continue
        out.extend(sorted(p for p in deps.iterdir() if p.is_dir()))
    return out


def overrides(case_dir):
    """Record-relative paths kept as written, from hash-overrides.toml."""
    f = case_dir / "hash-overrides.toml"
    if not f.is_file():
        return set()
    data = tomllib.loads(f.read_text())
    return set(data.get("paths", []))


def lock_checksums(case_dir):
    """package name -> checksum for every Cargo.lock under the case.

    A name locked twice with different checksums maps to None.
    """
    sums = {}
    for lock in sorted(case_dir.glob("tree/**/Cargo.lock")):
        data = tomllib.loads(lock.read_text())
        for pkg in data.get("package", []):
            name, checksum = pkg.get("name"), pkg.get("checksum")
            if name is None:
                continue
            if name in sums and sums[name] != checksum:
                sums[name] = None
            else:
                sums[name] = checksum
    return sums


def cargo_checksum(crate_dir, locked_checksum, keep):
    """Render the .cargo-checksum.json for a vendored crate directory."""
    record = crate_dir / ".cargo-checksum.json"
    old = {}
    if record.is_file():
        try:
            old = json.loads(record.read_text()).get("files", {})
        except (ValueError, AttributeError):
            old = {}
    files = {}
    for f in sorted(crate_dir.rglob("*")):
        if not f.is_file() or f.name == ".cargo-checksum.json":
            continue
        rel = f.relative_to(crate_dir).as_posix()
        if rel in keep:
            files[rel] = old.get(rel, ZERO_SHA256)
        else:
            files[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
    obj = {"files": files, "package": locked_checksum}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"


def b64sha256(data):
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def record_text(record, keep):
    """Render a RECORD, recomputing hash and size for each listed path."""
    import_root = record.parent.parent
    rows_out = []
    reader = csv.reader(io.StringIO(record.read_text()))
    for row in reader:
        if not row:
            continue
        path = row[0]
        name = Path(path).name
        if path in keep:
            rows_out.append(row)
            continue
        if name == "RECORD" or path.endswith(".pyc"):
            rows_out.append([path, "", ""])
            continue
        target = import_root / path
        if not target.is_file():
            raise ValueError(f"{record}: RECORD lists {path}, which does not exist")
        data = target.read_bytes()
        rows_out.append([path, f"sha256={b64sha256(data)}", str(len(data))])
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows_out)
    return buf.getvalue()


def refresh(case_dir, check):
    """Rewrite or verify every hash record under one case directory.

    Returns the list of stale (or, without --check, rewritten) paths.
    """
    keep = overrides(case_dir)
    checksums = lock_checksums(case_dir)
    stale = []
    for record in sorted(case_dir.rglob(".cargo-checksum.json")):
        text = cargo_checksum(record.parent, checksums.get(record.parent.name), keep)
        if check:
            if record.read_text() != text:
                stale.append(record)
        elif record.read_text() != text:
            record.write_text(text)
            stale.append(record)
    for record in sorted(case_dir.rglob("RECORD")):
        if not record.parent.name.endswith(".dist-info"):
            continue
        text = record_text(record, keep)
        if check:
            if record.read_text() != text:
                stale.append(record)
        elif record.read_text() != text:
            record.write_text(text)
            stale.append(record)
    return stale


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    stale = []
    for case_dir in cases():
        stale.extend(refresh(case_dir, args.check))
    for p in stale:
        what = "is stale" if args.check else "rewrote"
        print(f"{p.relative_to(REPO)}: {what}", file=sys.stderr)
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
