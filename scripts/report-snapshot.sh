#!/usr/bin/env bash
# Report snapshot harness (KTD4): dump the JSON report and exit code of
# every corpus case into target/report-snapshot/<name>/, and compare two
# dumps byte for byte or with only the additive Go keys allowed.
#
# Modes:
#   dump <name>
#       Build the CLI with `cargo build --locked -p egress-cli`, then run
#       `target/debug/egress-plane scan <case>/tree --format json` for every
#       case directory under fixtures/corpus/<lang>/<category>/<case>/
#       (pending cases included; directories without a tree/ are skipped).
#       stdout goes to target/report-snapshot/<name>/<lang>/<category>/<case>.json
#       and the exit code to the sibling <case>.exit. Refuses when
#       target/report-snapshot/<name> already exists, so a baseline cannot
#       be overwritten.
#
#   compare <base> <head> [--additive-go]
#       Byte-for-byte comparison of the two named snapshot trees, .exit
#       files included. Fails on a file present on one side only (listed)
#       and on any byte difference (unified diff printed).
#
#       With --additive-go, the go member of tool.runtime_range and of
#       completeness.coverage is stripped from each head report, and
#       tool.data_digest is replaced with a fixed placeholder on both
#       sides (the digest hashes every embedded data file, so adding Go
#       data changes it in every report), then bytes are compared. The
#       strip is scoped to those two members plus the digest; a go key
#       anywhere else still fails.
#
#   selftest
#       Build small report pairs under target/report-snapshot-selftest/
#       and assert each expected compare outcome, then delete the
#       directory. Exits 0 only when every scenario behaves.
#
# Environment overrides, used by selftest:
#   REPORT_SNAPSHOT_CORPUS   corpus root (default fixtures/corpus)
#   REPORT_SNAPSHOT_OUT      snapshot root (default target/report-snapshot)
#   REPORT_SNAPSHOT_BIN      scanner binary; when set, the cargo build is
#                            skipped (default target/debug/egress-plane)

set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<'EOF'
usage: scripts/report-snapshot.sh dump <name>
       scripts/report-snapshot.sh compare <base> <head> [--additive-go]
       scripts/report-snapshot.sh selftest
EOF
    exit 2
}

valid_name() {
    [[ $1 =~ ^[A-Za-z0-9._-]+$ ]]
}

do_dump() {
    local name=$1 corpus=${REPORT_SNAPSHOT_CORPUS:-fixtures/corpus}
    local out=${REPORT_SNAPSHOT_OUT:-target/report-snapshot}
    local bin=${REPORT_SNAPSHOT_BIN:-target/debug/egress-plane}
    local dest=$out/$name
    valid_name "$name" || {
        echo "dump: bad snapshot name '$name'" >&2
        return 2
    }
    if [[ -e $dest ]]; then
        echo "dump: refusing to overwrite existing snapshot $dest" >&2
        return 1
    fi
    [[ -d $corpus ]] || {
        echo "dump: corpus root $corpus does not exist" >&2
        return 1
    }
    if [[ -z ${REPORT_SNAPSHOT_BIN:-} ]]; then
        cargo build --locked -p egress-cli
    fi
    local count=0 case_dir rel json code
    while IFS= read -r case_dir; do
        [[ -d $case_dir/tree ]] || continue
        rel=${case_dir#"$corpus"/}
        json=$dest/$rel.json
        mkdir -p "$(dirname "$json")"
        code=0
        "$bin" scan "$case_dir/tree" --format json >"$json" || code=$?
        printf '%s\n' "$code" >"$dest/$rel.exit"
        count=$((count + 1))
    done < <(find "$corpus" -mindepth 3 -maxdepth 3 -type d | LC_ALL=C sort)
    echo "dumped $count cases to $dest"
}

# Rewrite one report for --additive-go comparison: placeholder the digest
# (both sides) and drop the go member of tool.runtime_range and
# completeness.coverage (head only, $3 = 1). A document that does not
# parse or lacks the report shape is copied verbatim.
normalize_json() {
    python3 - "$1" "$2" "$3" <<'PY'
import json
import shutil
import sys

src, dst = sys.argv[1], sys.argv[2]
strip_go = sys.argv[3] == "1"

try:
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    data["tool"]["data_digest"] = "<data-digest>"
    if strip_go:
        data["tool"]["runtime_range"].pop("go", None)
        data["completeness"]["coverage"].pop("go", None)
except Exception:
    shutil.copyfile(src, dst)
    sys.exit(0)

with open(dst, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

# Copy a snapshot tree, running normalize_json on each .json file.
normalize_tree() {
    local src=$1 dst=$2 strip=$3 f
    while IFS= read -r f; do
        f=${f#./}
        mkdir -p "$dst/$(dirname "$f")"
        case $f in
            *.json) normalize_json "$src/$f" "$dst/$f" "$strip" ;;
            *) cp "$src/$f" "$dst/$f" ;;
        esac
    done < <(cd "$src" && find . -type f | LC_ALL=C sort)
}

# Byte-for-byte comparison of two file trees. Prints each file found on
# one side only and a unified diff for each pair that differs.
compare_trees() {
    local b=$1 h=$2 blabel=$3 hlabel=$4 rc=0 f
    local files_b files_h
    files_b=$(cd "$b" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
    files_h=$(cd "$h" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        echo "only in $blabel: $f"
        rc=1
    done < <(comm -23 <(printf '%s\n' "$files_b") <(printf '%s\n' "$files_h"))
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        echo "only in $hlabel: $f"
        rc=1
    done < <(comm -13 <(printf '%s\n' "$files_b") <(printf '%s\n' "$files_h"))
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        if ! cmp -s "$b/$f" "$h/$f"; then
            echo "differs: $f"
            diff -u -L "$blabel/$f" -L "$hlabel/$f" "$b/$f" "$h/$f" || true
            rc=1
        fi
    done < <(comm -12 <(printf '%s\n' "$files_b") <(printf '%s\n' "$files_h"))
    return $rc
}

do_compare() {
    local base=$1 head=$2 additive=${3:-0}
    local out=${REPORT_SNAPSHOT_OUT:-target/report-snapshot}
    local b=$out/$base h=$out/$head
    [[ -d $b ]] || {
        echo "compare: no snapshot '$base' at $b" >&2
        return 1
    }
    [[ -d $h ]] || {
        echo "compare: no snapshot '$head' at $h" >&2
        return 1
    }
    local td='' keep=0
    if [[ $additive == 1 ]]; then
        td=$(mktemp -d "${TMPDIR:-/tmp}/report-snapshot.XXXXXX")
        normalize_tree "$b" "$td/base" 0
        normalize_tree "$h" "$td/head" 1
        b=$td/base
        h=$td/head
    fi
    compare_trees "$b" "$h" "$base" "$head" || keep=1
    [[ -n $td ]] && rm -rf "$td"
    return $keep
}

SELF=target/report-snapshot-selftest

# Emit one <prefix>.json report of the given variant and a <prefix>.exit
# holding the given code. Variant "none" writes only the .exit file.
self_report() {
    mkdir -p "$(dirname "$1")"
    python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

prefix, variant, code = sys.argv[1], sys.argv[2], int(sys.argv[3])


def counts(scanned):
    return {"scanned": scanned, "skipped": 0}


def report():
    return {
        "schema_version": 1,
        "tool": {
            "name": "egress-plane",
            "version": "0.1.0",
            "data_digest": "digest-base",
            "runtime_range": {
                "python": "3.9-3.13",
                "node": "18-22",
                "rust": "1.75-1.90",
            },
        },
        "completeness": {
            "state": "complete",
            "budget_exceeded": [],
            "coverage": {
                "python": counts(1),
                "javascript": counts(0),
                "rust": counts(0),
                "unsupported": counts(0),
            },
        },
        "caveats": [{"id": "example", "text": "example"}],
        "sites": [],
        "blind_spots": [],
        "unscanned_dependencies": [],
        "excluded": [],
    }


def v_order(r):
    c = r["completeness"]
    r["completeness"] = {
        "budget_exceeded": c["budget_exceeded"],
        "state": c["state"],
        "coverage": c["coverage"],
    }


def v_count(r):
    r["completeness"]["coverage"]["python"]["scanned"] = 9


def v_json(r):
    r["caveats"][0]["text"] = "changed"


def add_go(r):
    r["tool"]["runtime_range"]["go"] = "1.18-1.26"
    c = r["completeness"]["coverage"]
    r["completeness"]["coverage"] = {
        "python": c["python"],
        "javascript": c["javascript"],
        "rust": c["rust"],
        "go": counts(0),
        "unsupported": c["unsupported"],
    }
    r["tool"]["data_digest"] = "digest-head"


def v_additive(r):
    add_go(r)


def v_stray_go(r):
    add_go(r)
    r["caveats"][0]["go"] = "stray"


def v_reorder(r):
    add_go(r)
    c = r["completeness"]["coverage"]
    r["completeness"]["coverage"] = {
        "rust": c["rust"],
        "javascript": c["javascript"],
        "python": c["python"],
        "go": c["go"],
        "unsupported": c["unsupported"],
    }


variants = {
    "base": lambda r: None,
    "order": v_order,
    "count": v_count,
    "json": v_json,
    "additive": v_additive,
    "stray-go": v_stray_go,
    "reorder": v_reorder,
}

if variant != "none":
    r = report()
    variants[variant](r)
    with open(prefix + ".json", "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=2)
        f.write("\n")
with open(prefix + ".exit", "w", encoding="utf-8") as f:
    f.write(f"{code}\n")
PY
}

SELF_CHECKS=0
SELF_FAILS=0

check_rc() {
    SELF_CHECKS=$((SELF_CHECKS + 1))
    if [[ $2 -eq $3 ]]; then
        echo "ok: $1"
    else
        SELF_FAILS=$((SELF_FAILS + 1))
        echo "FAIL: $1 (wanted exit $2, got $3)"
    fi
}

check_true() {
    SELF_CHECKS=$((SELF_CHECKS + 1))
    if [[ $2 -eq 0 ]]; then
        echo "ok: $1"
    else
        SELF_FAILS=$((SELF_FAILS + 1))
        echo "FAIL: $1"
    fi
}

check_has() {
    SELF_CHECKS=$((SELF_CHECKS + 1))
    case $3 in
        *"$2"*) echo "ok: $1" ;;
        *)
            SELF_FAILS=$((SELF_FAILS + 1))
            echo "FAIL: $1 (output missing '$2')"
            printf '%s\n' "$3" | sed 's/^/    /'
            ;;
    esac
}

# Build a report pair under $SELF/pairs/<name>/{base,head}/python/ordinary/.
mk_pair() {
    local d=$SELF/pairs/$1 bvariant=$2 hvariant=$3 bexit=${4:-0} hexit=${5:-0}
    self_report "$d/base/python/ordinary/case" "$bvariant" "$bexit"
    self_report "$d/head/python/ordinary/case" "$hvariant" "$hexit"
}

# Run compare on pair $1 (optional $2 = --additive-go); sets CMP_RC/CMP_OUT.
run_pair() {
    local add=0
    [[ ${2:-} == --additive-go ]] && add=1
    CMP_RC=0
    CMP_OUT=$(REPORT_SNAPSHOT_OUT="$SELF/pairs/$1" \
        do_compare base head "$add" 2>&1) || CMP_RC=$?
}

do_selftest() {
    local rc out before after
    rm -rf "$SELF"
    mkdir -p "$SELF"
    trap 'rm -rf "$SELF"' EXIT

    mk_pair identical base base
    mk_pair order base order
    mk_pair count base count
    mk_pair missing base none
    mk_pair json-only base json
    mk_pair exit-only base base 2 3
    mk_pair additive base additive
    mk_pair stray-go base stray-go
    mk_pair reorder base reorder

    # extra: head gets a second case file base lacks.
    mk_pair extra base base
    self_report "$SELF/pairs/extra/head/python/ordinary/added" base 0

    run_pair identical
    check_rc "identical trees pass" 0 "$CMP_RC"

    run_pair order
    check_rc "swapped completeness keys fail" 1 "$CMP_RC"
    check_has "swap failure prints a diff" "@@" "$CMP_OUT"

    run_pair count
    check_rc "changed scanned count fails" 1 "$CMP_RC"

    run_pair missing
    check_rc "file only in base fails" 1 "$CMP_RC"
    check_has "missing file is named" "only in base: python/ordinary/case.json" "$CMP_OUT"

    run_pair extra
    check_rc "file only in head fails" 1 "$CMP_RC"
    check_has "extra file is named" "only in head: python/ordinary/added.json" "$CMP_OUT"

    run_pair json-only
    check_rc "same .exit, different json fails" 1 "$CMP_RC"

    run_pair exit-only
    check_rc "same json, different .exit fails" 1 "$CMP_RC"

    run_pair additive
    check_rc "plain compare rejects go additions" 1 "$CMP_RC"

    run_pair additive --additive-go
    check_rc "--additive-go passes allowed additions" 0 "$CMP_RC"

    run_pair stray-go --additive-go
    check_rc "--additive-go rejects a go member elsewhere" 1 "$CMP_RC"

    run_pair reorder --additive-go
    check_rc "--additive-go does not hide a reorder" 1 "$CMP_RC"

    # dump scenarios: a stub corpus and a stub scanner, so selftest stays
    # fast and deterministic. The stub exits 1 with empty stdout for the
    # `err` case and writes a small report with exit 2 otherwise.
    mkdir -p "$SELF/corpus/stub/ordinary/ok/tree" \
        "$SELF/corpus/stub/ordinary/err/tree" \
        "$SELF/corpus/stub/ordinary/notree"
    cat >"$SELF/stub-scan.sh" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
    case $a in
        */err/tree) exit 1 ;;
    esac
done
printf '{"selftest": true}\n'
exit 2
EOF
    chmod +x "$SELF/stub-scan.sh"

    dump_env() {
        REPORT_SNAPSHOT_CORPUS="$SELF/corpus" \
        REPORT_SNAPSHOT_OUT="$SELF/dumps" \
        REPORT_SNAPSHOT_BIN="$SELF/stub-scan.sh" "$@"
    }

    rc=0
    out=$(dump_env do_dump st 2>&1) || rc=$?
    check_rc "dump of stub corpus runs" 0 "$rc"

    [[ -f $SELF/dumps/st/stub/ordinary/ok.json && $(cat "$SELF/dumps/st/stub/ordinary/ok.exit") == 2 ]]
    check_true "dump records report and exit 2" $?
    [[ -f $SELF/dumps/st/stub/ordinary/err.json && ! -s $SELF/dumps/st/stub/ordinary/err.json && $(cat "$SELF/dumps/st/stub/ordinary/err.exit") == 1 ]]
    check_true "tool error records empty report and exit 1" $?
    [[ ! -e $SELF/dumps/st/stub/ordinary/notree.json ]]
    check_true "case without tree/ is skipped" $?

    before=$(cd "$SELF/dumps/st" && find . -type f -exec sha256sum {} + | LC_ALL=C sort)
    rc=0
    out=$(dump_env do_dump st 2>&1) || rc=$?
    check_rc "second dump into same name refuses" 1 "$rc"
    check_has "refusal says why" "refusing to overwrite existing snapshot" "$out"
    after=$(cd "$SELF/dumps/st" && find . -type f -exec sha256sum {} + | LC_ALL=C sort)
    [[ $before == "$after" ]]
    check_true "refused dump leaves the first untouched" $?

    # compare treats the exit-1 case like any other file.
    cp -r "$SELF/dumps/st" "$SELF/dumps/st-copy"
    rc=0
    out=$(REPORT_SNAPSHOT_OUT="$SELF/dumps" do_compare st st-copy 2>&1) || rc=$?
    check_rc "dump compares equal to its copy" 0 "$rc"
    printf '9\n' >"$SELF/dumps/st-copy/stub/ordinary/err.exit"
    rc=0
    out=$(REPORT_SNAPSHOT_OUT="$SELF/dumps" do_compare st st-copy 2>&1) || rc=$?
    check_rc "changed .exit in a dump fails" 1 "$rc"
    check_has ".exit difference is named" "err.exit" "$out"

    echo "selftest: $SELF_CHECKS checks, $SELF_FAILS failures"
    [[ $SELF_FAILS -eq 0 ]]
}

case ${1:-} in
    dump)
        [[ $# -eq 2 ]] || usage
        do_dump "$2"
        ;;
    compare)
        [[ $# -eq 3 || $# -eq 4 ]] || usage
        if ! valid_name "$2" || ! valid_name "$3"; then
            usage
        fi
        if [[ $# -eq 4 ]]; then
            [[ $4 == --additive-go ]] || usage
            do_compare "$2" "$3" 1
        else
            do_compare "$2" "$3"
        fi
        ;;
    selftest)
        [[ $# -eq 1 ]] || usage
        do_selftest
        ;;
    *)
        usage
        ;;
esac
