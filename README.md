# egress-plane

egress-plane scans the first-party source of a Rust, Python, JavaScript/TypeScript, or Go repository (or a mix of them) and reports every route by which that code can send data out of the process: network calls, process spawning, foreign-function and native code loads, and the equivalent routes each runtime offers. Where it cannot prove the account, it says so with a blind spot and a reason. The exit code tells you whether the account is complete.

It is one static binary. It parses Python with ruff's parser, JavaScript and TypeScript with oxc, Rust with syn, and Go with gosyn and go, all in-process. It never runs the code it scans, spawns no subprocess (no `cargo`, `rustc`, `node`, `python`, `tsc`, `go`, or `git`), opens no network connection, and reads nothing outside the scan root. Those guarantees describe `scan`; the `probe` subcommand below has its own, narrower ones.

## Usage

```sh
egress-plane scan <root>                 # text report (the default)
egress-plane scan <root> --format json   # JSON report
egress-plane scan <root> --format=json
```

The report goes to stdout. Errors go to stderr, and when the tool fails it writes nothing to stdout, so a JSON consumer never sees a partial document.

The text report starts with a header: the completeness state and exit code, per-language coverage counts (files scanned and skipped), any exhausted global budget, and the supported runtime range. Then come these sections:

- Caveats: fixed notes about known uncovered routes (see below).
- Egress sites, grouped by destination. Each line gives `file:line:column`, the enclosing symbol, the mechanism (a data entry ID such as `python:requests.post`), the bucket (`primitive` or `catalogued`), and any labels (`vendored`, `generated`, `minified`, `test`, `build-hook`). A derived site (one carrying `via` in JSON) adds `through` naming the wrapper chain it came through, outermost first.
- Blind spots, grouped by kind, with coverage gaps first.
- Unscanned dependencies: each imported package that is not in the egress catalog, listed once with the files that import it.
- Excluded: paths the scan did not enter, with the reason.

Every string taken from the scanned repository (paths, symbols, literals, package names, construct text) is escaped before it is printed: control characters, bidi and other format characters, and line and paragraph separators render as `\u{..}`. A crafted file name or string literal cannot emit terminal escape sequences or forge a report line.

## What the result means

Every import, member reference, and ambient global in first-party code that can be classified statically is classified at member level into one of four buckets: egress primitive, catalogued egress library, unscanned dependency, or inert. Every call that reaches a primitive or a catalogued library is a site with a destination. A destination is a literal when one can be resolved, and otherwise symbolic: `env:NAME` for an environment read (the scan never reads your environment), `param:N:<function>` for a wrapper's parameter, a template with symbolic holes such as `{env:BASE}/v1`, `exec:<program>`, `lib:<library>`, `host:port`, or `expr:<source text>` for anything assembled at run time.

A `param:N:<function>` destination names a wrapper: the value leaving the process is whatever callers pass as that parameter's argument. A derived-site pass then walks each in-tree call whose callee resolves to the wrapper's definition and reports a derived site at the caller: the inner site's mechanism, the caller's concrete or symbolic destination, and a `via` field naming the inner site, the argument index, and the ordered wrapper chain back to it. A caller that forwards its own parameter becomes the next hop, so a chain of wrappers reports one site per concrete caller. Chains are capped at `hop_limit` (8, from `data/wrappers.toml`); a chain cut there reports the caller with `cut` `hop-limit`, and a walk that returns to a `(file, function, parameter)` already in the chain reports `recursion`. Derived sites are additive: every direct site and its id are unchanged whether or not callers are found, and the findings budget drops derived sites before direct ones.

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
| 3 | `empty`: no supported first-party file was found (for example a Haskell-only tree). |
| 1 | Tool error: the root does not exist or is not a directory, the command line is wrong, or an internal failure occurred. Nothing is written to stdout. |

A tool error outranks `empty`, which outranks `incomplete`, which outranks `complete`. A file that fails to parse, a manifest that fails to parse, and a frontend crash on one file are all per-file coverage gaps (exit 2), never a tool error. Caveats never change the exit code.

## JSON output and schema versioning

The JSON report is described by `schema/egress-report.v1.json`. Its top-level `schema_version` is an integer, currently 1. Adding an optional field keeps the version; removing or renaming a field, or changing what a field means, increments it. Consumers should ignore fields they do not recognize.

The output is deterministic. Scanning the same tree twice gives byte-identical JSON, regardless of worker count or where the tree sits on disk. Paths are repo-relative with `/` separators, collections are sorted by identity components rather than by line, and nothing time-dependent or host-dependent is recorded. Each site and blind spot has an `id` derived from its file, enclosing symbol, kind, mechanism, and redacted destination, not from its position, so inserting a line above a call changes only that finding's `location`. `location` is the only field that carries a position.

`display` fields and `construct` are escaped as in the text report. Structured fields (`value`, `file`, `package`) carry the exact string under standard JSON escaping. A path that is not valid UTF-8 is emitted with an escaped display form in `file` and the raw bytes as lowercase hex in `file_bytes`.

## Supported runtimes and hosts

Python source files follow PEP 263: a `coding:` cookie on the first line, or on the second line when the first is blank or a comment, picks the decoder. Accepted codecs are UTF-8 (including `utf-8-*` names), Latin-1 (including `iso-8859-1` variants), and ASCII. A UTF-8 BOM is fine alongside a UTF-8 cookie. A cookie naming anything else, an unknown name, or a non-UTF-8 cookie combined with a BOM is a whole-file `unsupported-encoding` coverage gap: the bytes are never parsed as UTF-8. Every other language decodes UTF-8 only.

The primitive lists and catalog describe CPython 3.8 to 3.13, Node 18 to 22, the Rust toolchain pinned in `rust-toolchain.toml` (1.97.1), and Go 1.18 to 1.26. The range is recorded in every report as `tool.runtime_range`. The scanner does not detect which runtime a repository targets, so code written for a runtime outside this range is scanned against these lists and the completeness state does not reflect the mismatch.

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

## Scanning dependencies

`--deps <path>` names a dependency root to scan, and may be repeated. Roots are always named; the tool never discovers them.

```sh
egress-plane scan . --deps node_modules
egress-plane scan . --deps .venv/lib/python3.12/site-packages
egress-plane scan . --deps vendor --deps ~/.cargo/registry/src/index.crates.io-1949cf8c
```

Each root is detected by shape: an npm `node_modules`, a Python `site-packages` or venv layout, a Cargo `vendor` directory, a Cargo registry cache (`registry/src/<index>`), or a Cargo git checkout (`git/checkouts`). For a registry cache, name the `registry/src` directory that holds the index, not the index itself. Rejected paths fail before scanning with exit 1 and a fixed message.

Imported packages are resolved against the named roots in breadth-first closure order and scanned with the same mechanism classification, under a separate set of dependency budgets (`data/dependency-budgets.toml`). The dependency findings land in a `dependencies` section: scanned packages with their own sites, blind spots, and per-package completeness state; `imports_unscanned` for closure entries that stayed out; `auto_run` for Python `*.pth`, `sitecustomize.py`, and `usercustomize.py` files; lockfile `diagnostics`; and exhausted dependency budgets. The top-level state, exit code, sites, and blind spots stay first-party only.

Each package shows its verification strength: `checksum-verified` when every file hashed by `RECORD`, `package-lock.json` integrity fields, or `.cargo-checksum.json` matches; `version-matched` when the install is governed by a lockfile that has no per-file hashes; `unlocked` when no lockfile governs. These hashes are install integrity data, not signatures: a `RECORD` match proves the file as installed matches the file the installer wrote, not that the installer fetched a trustworthy package. `modified: true` marks a package whose hashes did not match.

A closure entry that stays unscanned carries a reason: `no-source-in-named-root` (nothing installed by that name), `version-mismatch` (installed, but not the locked version), `archive-only-install` (a Yarn PnP or zip-shaped install the scanner cannot read), `unsupported-layout` (a pnpm store, an `egg-info` directory, or other recognized-but-unreadable shape), `dependency-budget-exhausted`, `lockfile-unreadable`, or `unlocked-shared-cache` (registry or git cache without a `Cargo.lock`, which is never scanned: the cache is shared across projects).

Dependency names also carry `mark`: `non-ascii-name` for an npm or Cargo name with a non-ASCII character, `mixed-script` for a Python name that mixes scripts, and `confusable-skeleton` when a name's confusable skeleton equals a catalogued package, a standard-library module, or another dependency name in the report. Marks never change the state or the exit code. The Unicode tables are version 16.0, from the pinned `unicode-security` crate, and the version is recorded in `data/name-signals.toml`.

Package identity is the kind, root label, locator, and name, not the installed version, so bumping a locked version moves the `version` field only. Identity still shifts when the locator shifts: the same name held by two roots, or under two registry index hashes, reports as two entries.

Limits: pnpm's symlinked store layout and Yarn's archive-only PnP installs are detected but not scanned (`unsupported-layout`, `archive-only-install`). `exports` maps are not read inside dependency code (the section carries `dependency-exports-not-read`). Conditional `cfg` code is scanned as written (`dependency-conditional-code-included`).

The `dependencies` section is an optional JSON field and is absent when no root is named. The schema stays at version 1, but a strict v1 consumer needs the updated `schema/egress-report.v1.json` because it rejects unknown fields. `tool.data_digest` changes with this release regardless of flags: the embedded data files grew, and every report hashes all of them.

## Caveats

Whenever any JavaScript or TypeScript file is scanned, the report carries the `browser-dom` caveat: browser DOM-mediated requests (assigning `src`, `href`, or `action` on elements, and form submission) are not covered. The caveat appears in the JSON `caveats` list and in the text report. It does not change the completeness state or the exit code.

Two caveats attach to Go scans. When a parsed `go.mod` or `go.work` `go` directive names a release newer than the supported range, the report carries `go-version-newer-than-supported`; files using newer syntax become parse errors. When a Go package-level string `var` supplies a resolved destination, the report carries `go-var-ldflags`: a link-time `-ldflags -X` override can change that value without a source change. Neither caveat changes the completeness state or the exit code.

Whenever a Python, JavaScript, TypeScript, or Rust file is scanned, the report carries the `local-io` caveat: filesystem reads and writes, FIFO and shared-memory creation, and anonymous pipes are not counted as egress. The caveat appears in the JSON `caveats` list and in the text report, and does not change the completeness state or the exit code.

## Secrets in output

Destinations and construct text are redacted before they are printed or hashed. The recognized classes are URL userinfo, values of listed query and fragment keys, runs that start with a known token prefix, provider-specific path secrets, keyword DSN values, and secrets split across a template's literal parts and holes. Each match is replaced by `<redacted>`.

A positional entropy pass runs last: an alphanumeric run of 20 or more characters that mixes at least two of lowercase, uppercase, and digits and reaches 3.5 Shannon bits per character is redacted in query and fragment values under unlisted keys, URL path segments, keyword-DSN values under unlisted keys, string-literal bodies inside construct and `expr:` text, and env defaults. Hosts, schemes, all-hex runs such as commit hashes, UUIDs, and kebab or snake_case pieces stay. The thresholds live in `data/redaction.toml` under `[entropy]`; changing them re-keys every site identity whose destination text they touch.

A secret that matches none of these classes is not recognized and can appear in the output. Treat reports from repositories that may hold credentials as sensitive.

## Limitations

- Scope is first-party source only. Dependency source, what build or install steps do at run time, and CI or container configuration are not analyzed. Build and install hooks are reported as blind spots without analyzing their contents.
- The evasive and closure fixture corpus categories are authored for Python, JavaScript, and Rust. For Go they remain deferred, as do a band of `go/primitives` data fixtures; `fixtures/corpus/deferred.toml` lists them with reasons. The ordinary, tricky, primitives, and completeness categories are in place and gate every change.
- CommonJS exports are followed across files only in the direct forms written at module level: `module.exports = X`, `exports.name = X`, `module.exports.name = X`, and `module.exports = { name: X }`, where `X` is a `require` call, an imported module, or a member of one. Other forms, such as `Object.assign(module.exports, require("https"))`, a spread into the export object, a computed key, an export made inside a function, or an export object built in a local first, are reported only where the export is written: a module exported this way is an escape site there, but an importer's call through it is not reported as its own site. Exports are not ordered, so a later `module.exports = ...` is not taken to discard earlier `exports.name` assignments.
- Go build constraints are not evaluated: every file of a package is scanned, whatever its `//go:build` tag or file-name suffix says. `//go:generate` directives are reported as build-hook blind spots and `go.mod` `tool` directives are skipped; neither is ever run. Assembly, cgo, and other native source files in a Go package directory are listed as native-code blind spots and are never opened or analyzed. Go 1.27 generic method syntax is a parse error, and a deliberately invalid Go file under a scanned `testdata` directory (analyzer and parser fixtures) stays a `parse-error` coverage gap and holds the state `incomplete`.
- Destination resolution stays inside one function, plus module-level constants in the same file, constants imported from a first-party module, and Go constants in the other files of the same package. Anything further becomes a symbolic or `expr:` destination. The derived-site pass resolves each caller's argument under the same rule.
- A call produces a derived site only when its callee resolves to a first-party definition: a direct call to a function defined or imported in the scanned tree. A wrapper invoked through `self.`/`this.` (a method), through an alias or re-export the resolver does not classify as the definition itself, through `functools.partial` or `.bind`, or passed as a value gets none. A wrapper with no callers, and callers reached only past a hop-limit or recursion cut, add nothing.
- A `tsconfig.json` `extends` naming a package resolves only inside the scanned tree, through `package.json` `name` declarations; a bare name whose package is not in the tree, or that is declared by more than one in-tree `package.json`, is left unresolved. A package in `node_modules` or any excluded directory is never followed; following it is the dependency source scan's job.
- See also the runtime range, host, budget, caveat, and secret limits above.

## Probing the environment

`egress-plane probe` runs inside a container, agent sandbox, CI runner, or cloud VM and reports what a process there can see: egress routes (ways data can leave), escape routes (ways code can gain reach it should not have), and an explicit list of what it could not see.

```sh
egress-plane probe                          # text report (the default)
egress-plane probe --format json            # JSON report
egress-plane probe --nonce 5f3a             # echo a nonce into the report
egress-plane probe --active --allow 10.0.0.8:443 --allow '[fd00::1]:53'
```

The default run is passive: it reads local state only and opens no socket, including no unix socket, and it never touches a path on a network or user-space filesystem, so it sends no traffic of any kind. `--active` adds bounded reachability checks and requires at least one `--allow` (`--allow` requires `--active`). A passive `probe` opens no network connection and spawns no subprocess; it does read environment variable *names* (never values), which is why the scan's no-environment-read guarantee does not extend to it.

Exit codes match the scan report: 0 `complete`, 2 `incomplete`, 3 `empty` (no set could be enumerated at all), 1 tool error with nothing on stdout. The JSON schema is `schema/egress-probe.v1.json`, versioned like the scan schema, with `kind` `environment-probe`. The text report's sections, in order: Layers, Egress routes, Escape routes, Unknowns, Tamper indicators, Not observable, Not applicable, Unclassified, Inert counts, Active checks, Caveats.

- An **unknown** is a source the probe tried to read and could not; each unknown makes the run incomplete. An **unclassified** member is one no declared rule matched; it is listed and does not change the state.
- **Not observable** is a fixed list of sources no unprivileged process can read by design (seccomp filter contents, the current Landlock domain, firewall rules, the macOS bootstrap namespace). They are reported every run and do not change the state. **Not applicable** names the finite sets that do not exist on the host platform (Linux sets on macOS and vice versa); a macOS host has no process filesystem, and that is not a failure to read.
- **Tamper indicators** come in two strengths. Strong (the probe is being traced, a kernel filesystem is not the expected type, the process filesystem describes another process) also produce an unknown, so the run is incomplete. Weak (loader variables such as `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, or an `/etc/ld.so.preload` file, which the static Linux build never consults) are listed only.

### Trusting a probe report

A report describes the probe's own context as that context presents itself; every report carries the `self-reported-context` caveat. No inside check can prove the launcher did not hand the probe a fabricated context (`unshare -rmn` with a crafted bind-mounted `/proc` produces an honest report of the wrong context), so a report is authentic only when the launch is trusted: the binary is supplied from outside and its hash checked, it is started through the same launch chain as the agent it stands in for (same wrapper, same sandbox arguments, same uid, same inherited descriptors), and stdout is captured outside. `docker exec` or `kubectl exec` reproduces the agent's context only when the agent is the container's direct process; an agent started under `bwrap`, a seatbelt profile, or another wrapper inside the container needs the probe started under that same wrapper.

To check a report from outside, compare the probe's view with the agent's. The layer attributes carry the probe's namespace inode numbers (display-only; they never enter identity) and the `Seccomp`, `NoNewPrivs`, `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`, and `Uid` values the probe read from `proc/self/status`. Compare them with `/proc/<agent pid>/ns/*` and `/proc/<agent pid>/status` on the host. `--nonce HEX` (1 to 64 lowercase hex characters) is echoed into the `nonce` field and the text header so a captured report can be tied to one launch. The `source` field (`live` or `snapshot`) is informational only; it is not proof of a live run.

Detected environments are listed as layers ordered by a fixed family rank (cloud VM, CI runner, container, sandbox), reported as `layer_order_basis: "family-rank"`. The order is a convention, not a measurement: a process inside cannot measure nesting, and a CI layer detected from environment names may in fact sit inside a container.

### Reading the details

- On Linux, home-relative credential checks resolve the home directory from the account file (`etc/passwd`), never from `HOME` or a name service; every Linux report carries the `home-from-account-database` caveat. A credential that lives under a `HOME` differing from the account's home is not checked. On macOS, v1 resolves no home directory, so every home-relative signal is an unknown with reason `no-account-home`.
- A path on a network or user-space filesystem is never touched, not even for a metadata or access check: a `stat` or a directory read on NFS, CIFS, or FUSE is itself a remote call. The affected source reports an unknown with `network-filesystem-not-touched`; the mount itself is still listed from the mount table.
- Identity uses stable fields only: process ids, descriptor numbers, ports, device numbers, mount ids, inode numbers, and counters are display-only and never enter an id.
- Environment variable names, and file names inside credential directories, are emitted, but a name that matches a token-prefix class is redacted to `<redacted>`. Values never cross the reader.

### Active mode

`--allow` takes `IP:port` literals only: IPv4 `a.b.c.d:port` or IPv6 `[addr]:port`. Domain names are usage errors and are never resolved (resolving one is itself egress). Port 0, duplicate entries, and more than 16 entries are usage errors. Cloud metadata and other credential-bearing endpoints (the `169.254.0.0/16` block and the provider IPv6 metadata addresses, Azure WireServer, Alibaba metadata) plus unspecified, broadcast, and multicast addresses are always refused: the check is recorded as `refused-metadata-address` or `refused-special-address` and no socket is created. IPv4-mapped, IPv4-compatible, NAT64, and tunnel-embedded forms are canonicalized and refused the same way. Each remaining target gets one sequential non-blocking TCP connect bounded at 3 seconds, closed at once, with no payload; results are `connected`, `refused`, `timed-out`, `unreachable`, or `error:<errno name>`, recorded without timing values. Active checks never change the completeness state. Address translation inside the environment (a proxy or VPN carrying the connection elsewhere) cannot be prevented from inside; the exposure is bounded because a check sends no payload.

### Build and scope notes

The Linux release probe is a static `<arch>-unknown-linux-musl` build with no interpreter program header, so the dynamic loader never runs and `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, or a replaced libc cannot inject code; their names show up only as weak tamper indicators. A report is point-in-time: it describes what the probe observed at run time, not a standing guarantee about the environment.

## Building and testing

An advisory benchmark lives outside the shipped binary:

```
cargo build --release --locked -p egress-cli
cargo run --release --locked -p egress-bench -- --sizes 1000,10000,50000
```

It generates fixed-seed synthetic monorepos under `target/bench/trees/` and writes `target/bench/results.json` with per-run wall time, files per second, and peak RSS per child. The seed and the content mix are constants recorded in the results file. The benchmark is never run by the test suite or CI; its numbers are advisory and compare runs, not absolute targets.

```sh
cargo build --release --locked -p egress-cli     # binary: target/release/egress-plane
cargo test --workspace --locked
cargo test -p egress-corpus --locked             # corpus gate; prints the false-positive count
```

`docs/adding-a-language.md` is the recipe for adding a language; each mechanical step names the test or conformance finding that enforces it.
