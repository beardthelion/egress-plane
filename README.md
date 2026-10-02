# egress-plane

egress-plane scans the first-party source of a Rust, Python, or JavaScript/TypeScript repository (or a mix of them) and reports every route by which that code can send data out of the process: network calls, process spawning, foreign-function and native code loads, and the equivalent routes each runtime offers. Where it cannot prove the account, it says so with a blind spot and a reason. The exit code tells you whether the account is complete.

It is one static binary. It parses Python with ruff's parser, JavaScript and TypeScript with oxc, and Rust with syn, all in-process. It never runs the code it scans, spawns no subprocess (no `cargo`, `rustc`, `node`, `python`, `tsc`, or `git`), opens no network connection, and reads nothing outside the scan root.

## Usage

```sh
egress-plane scan <root>                 # text report (the default)
egress-plane scan <root> --format json   # JSON report
egress-plane scan <root> --format=json
```

The report goes to stdout. Errors go to stderr, and when the tool fails it writes nothing to stdout, so a JSON consumer never sees a partial document.

The text report starts with a header: the completeness state and exit code, per-language coverage counts (files scanned and skipped), any exhausted global budget, and the supported runtime range. Then come these sections:

- Caveats: fixed notes about known uncovered routes (see below).
- Egress sites, grouped by destination. Each line gives `file:line:column`, the enclosing symbol, the mechanism (a data entry ID such as `python:requests.post`), the bucket (`primitive` or `catalogued`), and any labels (`vendored`, `generated`, `minified`, `test`, `build-hook`).
- Blind spots, grouped by kind, with coverage gaps first.
- Unscanned dependencies: each imported package that is not in the egress catalog, listed once with the files that import it.
- Excluded: paths the scan did not enter, with the reason.

Every string taken from the scanned repository (paths, symbols, literals, package names, construct text) is escaped before it is printed: control characters, bidi and other format characters, and line and paragraph separators render as `\u{..}`. A crafted file name or string literal cannot emit terminal escape sequences or forge a report line.

## What the result means

Every import, member reference, and ambient global in first-party code that can be classified statically is classified at member level into one of four buckets: egress primitive, catalogued egress library, unscanned dependency, or inert. Every call that reaches a primitive or a catalogued library is a site with a destination. A destination is a literal when one can be resolved, and otherwise symbolic: `env:NAME` for an environment read (the scan never reads your environment), `param:N:<function>` for a wrapper's parameter, a template with symbolic holes such as `{env:BASE}/v1`, `exec:<program>`, `lib:<library>`, `host:port`, or `expr:<source text>` for anything assembled at run time.

Anything whose mechanism cannot be resolved statically is a blind spot rather than a silent omission: `eval` and its relatives, dynamic imports, reflective access, monkeypatching, raw FFI, macro-generated code, build and install hooks, and so on. Files the scanner cannot read, parse, or does not support are whole-file blind spots.

A blind spot is a coverage gap when it means part of the code was not examined at all: a whole-file blind spot, code loaded from outside the scan root or from an excluded directory, an excluded directory that holds supported code but lacks the marker that confirms it as install output, or an exhausted global budget. Any coverage gap makes the state `incomplete`. Construct-level blind spots (such as `dynamic-code` or `reflective-access`) are findings to review and do not change the state.

The account is exactly as good as the primitive lists and catalog under `data/`. Those lists are tested against the fixture corpus, one fixture per entry, but a route the lists do not know about is not reported.

### Filtering `reflective-unknown`

`reflective-unknown` marks computed or reflective member access on a value whose origin the scanner does not track (for example `obj[name](...)` on an arbitrary parameter). It can be noisy in some codebases. It never changes the completeness state, so filtering it out of a JSON report is safe for triage:

```sh
egress-plane scan . --format json \
  | jq '.blind_spots |= map(select(.kind != "reflective-unknown"))'
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `complete`: every supported first-party file was scanned and no coverage gap was found. |
| 2 | `incomplete`: at least one coverage gap. The report is still written in full. |
| 3 | `empty`: no supported first-party file was found (for example a Go-only tree). |
| 1 | Tool error: the root does not exist or is not a directory, the command line is wrong, or an internal failure occurred. Nothing is written to stdout. |

A tool error outranks `empty`, which outranks `incomplete`, which outranks `complete`. A file that fails to parse, a manifest that fails to parse, and a frontend crash on one file are all per-file coverage gaps (exit 2), never a tool error. Caveats never change the exit code.

## JSON output and schema versioning

The JSON report is described by `schema/egress-report.v1.json`. Its top-level `schema_version` is an integer, currently 1. Adding an optional field keeps the version; removing or renaming a field, or changing what a field means, increments it. Consumers should ignore fields they do not recognize.

The output is deterministic. Scanning the same tree twice gives byte-identical JSON, regardless of worker count or where the tree sits on disk. Paths are repo-relative with `/` separators, collections are sorted by identity components rather than by line, and nothing time-dependent or host-dependent is recorded. Each site and blind spot has an `id` derived from its file, enclosing symbol, kind, mechanism, and redacted destination, not from its position, so inserting a line above a call changes only that finding's `location`. `location` is the only field that carries a position.

`display` fields and `construct` are escaped as in the text report. Structured fields (`value`, `file`, `package`) carry the exact string under standard JSON escaping. A path that is not valid UTF-8 is emitted with an escaped display form in `file` and the raw bytes as lowercase hex in `file_bytes`.

## Supported runtimes and hosts

The primitive lists and catalog describe CPython 3.8 to 3.13, Node 18 to 22, and the Rust toolchain pinned in `rust-toolchain.toml` (1.97.1). The range is recorded in every report as `tool.runtime_range`. The scanner does not detect which runtime a repository targets, so code written for a runtime outside this range is scanned against these lists and the completeness state does not reflect the mismatch.

Supported host operating systems are Linux and macOS. Windows is not supported yet.

## Global budgets

To bound run time on hostile or enormous repositories, the scan charges four deterministic counters. The defaults live in `data/budgets.toml`:

| Budget | Default | Reason reported when exhausted |
|---|---|---|
| Supported source files parsed | 500,000 | `budget-files` |
| Source bytes parsed | 2 GiB | `budget-bytes` |
| Findings kept (sites, blind spots, unscanned dependencies) | 1,000,000 | `budget-findings` |
| Alias-resolution steps | 100,000,000 | `budget-resolver-steps` |

Each budget is a count, not a time limit, so the result never depends on host speed. Files and bytes are charged in byte-wise path order; files past the limit are counted as skipped. An exhausted budget is listed in `completeness.budget_exceeded` and makes the state `incomplete`. Per-file limits also apply: oversized files, files nested too deeply to parse safely, and files that are not regular files are whole-file blind spots.

## Caveats

Whenever any JavaScript or TypeScript file is scanned, the report carries the `browser-dom` caveat: browser DOM-mediated requests (assigning `src`, `href`, or `action` on elements, and form submission) are not covered. The caveat appears in the JSON `caveats` list and in the text report. It does not change the completeness state or the exit code.

## Secrets in output

Destinations and construct text are redacted before they are printed or hashed. The recognized classes are URL userinfo, values of listed query and fragment keys, runs that start with a known token prefix, provider-specific path secrets, keyword DSN values, and secrets split across a template's literal parts and holes. Each match is replaced by `<redacted>`.

A secret that matches none of these classes is not recognized and can appear in the output. Treat reports from repositories that may hold credentials as sensitive.

## Limitations

- Scope is first-party source only. Dependency source, what build or install steps do at run time, and CI or container configuration are not analyzed. Build and install hooks are reported as blind spots without analyzing their contents.
- The evasive and closure fixture corpus categories are not yet authored. They are deferred, and `fixtures/corpus/deferred.toml` lists the data entries whose fixtures wait on them. The ordinary, tricky, primitives, and completeness categories are in place and gate every change.
- CommonJS re-exports through `module.exports` are not followed across files. When `lib.js` sets `module.exports = require("https")` and another file calls `require("./lib").get(url)`, that call is not reported as a site. An object export such as `module.exports = { get: https.get }` is reported where the export is written, with an `expr:` destination, but not at the importer's call.
- Destination resolution stays inside one function, plus module-level constants in the same file and constants imported from a first-party module. Anything further becomes a symbolic or `expr:` destination.
- See also the runtime range, host, budget, caveat, and secret limits above.

## Building and testing

```sh
cargo build --release --locked -p egress-cli     # binary: target/release/egress-plane
cargo test --workspace --locked
cargo test -p egress-corpus --locked             # corpus gate; prints the false-positive count
```
