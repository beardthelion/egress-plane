# Adding a language

The recipe for adding a language to the scan, written from what the Go port
(plan P8, units U1 to U11) actually needed. Work the steps in order; the
early ones exist so every later step has something to be checked against.

Each step is mechanical or marked `(judgment)` in its heading. A mechanical
step carries a `Fails when skipped:` line naming what turns red without it:
a conformance finding from `crates/egress-core/tests/conformance.rs`, a
test function in the workspace's test sources, or a compile-forced
exhaustive match. The conformance test reads this file and fails when a
finding is named in no step, when a mechanical step loses its line, or when
a line cites a test that does not exist, so the document cannot silently
drop a step's enforcement. Judgment steps say what was decided for Go as
the worked example; a judgment step may still carry a `Fails when skipped:`
line for whatever tripwires exist.

### Step 1: Record the snapshot baseline

Before the first language-table change, dump a baseline of every corpus
report and exit code with scripts/report-snapshot.sh dump baseline. Each
later unit runs the additive compare against it, which tolerates the new
language's runtime-range and coverage keys and the placeholder
tool.data_digest that new data files change. Skipping the step leaves every
later diff with nothing to compare against.

Fails when skipped: the additive snapshot compare gate in the plan's
verification contract cannot run without a baseline; no Rust test stands in
for it, and scripts/report-snapshot.sh selftest covers only the compare
itself.

### Step 2: Add the variant and the spec row

`Language` gains a variant, `Language::ALL` an entry, `as_str` an arm, and
`Language::spec` a row: the `as_str` name, the `runtime_key` under which
`tool.runtime_range` reports (`node` for javascript, so not always the
name), the source extensions, the shebang rule, the manifest file names,
and the member separator used in data entry IDs. Until the frontend lands,
the name goes in `FRONTEND_PENDING` in the conformance test, which allows a
listed language exactly one missing-frontend finding and fails a stale
entry once a frontend registers.

Fails when skipped: `frontend-missing` while the language sits in the
table with no registered frontend and no FRONTEND_PENDING entry, and
`spec_names_match_as_str` when the row name disagrees with as_str.

### Step 3: Fill the compile-forced matches

Adding the variant turns every exhaustive match over `Language` into a
compile error until the arm exists. That is the point of the language-table
refactor: the places that must decide per-language behavior are forced, not
convention. For Go the sites were module path splitting, import visibility,
scope and leaf naming, and star-module behavior in
crates/egress-core/src/resolve.rs, the reference-head and tracked-value
arms in crates/egress-core/src/classify.rs, and the depth prescan in
crates/egress-core/src/prescan.rs. Decide each arm; a copied arm is the
usual source of a silent misroute.

Fails when skipped: compile errors, not a test; the exhaustive matches
over the enum in crates/egress-core/src/resolve.rs and
crates/egress-core/src/classify.rs have no arm for the new variant.

### Step 4: Extend the report schema

schema/egress-report.v1.json: add the enum value under `$defs/language`, a
property under `completeness.coverage` named for the language, and a
property under `tool.runtime_range` named for the runtime key. The check
reads `properties`, not `required`, so listing the name under `required`
does not stand in for the property.

Fails when skipped: `schema-enum-missing`,
`schema-coverage-property-missing`, and
`schema-runtime-range-property-missing`.

### Step 5: Add the labels entry

data/labels.toml needs a per-language table under at least one label rule,
empty when the language adds nothing; Go's `[test.go]` adds the `*_test.go`
name glob and the `testdata` directory rule. The table key is the `as_str`
name, and an unknown key fails data loading.

Fails when skipped: `label-entry-missing`.

### Step 6: Generate the inventory and seed the data files

scripts/inventory/<language>.py reads the standard library of the pinned
runtime and writes data/inventory/<language>.toml; rerunning it with
--check is the drift gate. data/primitives/<language>.toml declares the
language key, the supported `runtime_range`, and a provisional class per
module; the inventory is real from the start because the data guards reject
an empty one. data/catalog/<language>.toml starts empty. All three join the
`EMBEDDED` list in crates/egress-core/src/data.rs so the loader picks them
up and `data_digest` covers them; a file absent from the list fails
`Data::embedded` at load and takes every data guard with it. Per-language
fixed caveats go in data/caveats.toml, also embedded; a caveat never
changes the state or exit code.

Fails when skipped: `data-file-missing` for each absent file,
`data-language-mismatch` for a wrong language key,
`loader_reads_every_embedded_file_with_a_stable_digest` for a stale
embed, and `runtime_range_matches_the_declared_range` for a range that
disagrees with the pin.

### Step 7: Route discovery and manifests

The spec row's extensions and shebang rule route source files. Each
manifest name needs a `ManifestKind` with a file name, a language arm, and
a parser arm in the manifest parse dispatch; path-routed kinds (Go's
vendor/modules.txt) belong to the same enum even when no spec row names
them.

Fails when skipped: `manifest_kinds_route_through_the_language_table`
fails when a spec-listed manifest name resolves to no kind or to another
language's kind, `unrouted_extensions_stay_other_and_shebangs_route`
pins the source routing, and the manifest parse dispatch is a
compile-forced match.

### Step 8: Create the frontend crate and pin the parser

crates/egress-<language> joins the workspace members in the root
Cargo.toml; the parser is pinned to an exact version under
workspace.dependencies; advisories against the new dependency go in
deny.toml with a reason each, verified by the advisory gate (cargo deny
check advisories sources, or the cargo audit fallback where deny is
absent). The frontend implements the registry trait and registers in
`Registry::builtin`, which drops the name from `FRONTEND_PENDING`. A trap
test plants fake toolchain binaries on PATH to prove the scan never spawns
them; Go's covers go, gofmt, and gopls.

Fails when skipped: `frontend-missing` until registration,
`every_language_in_the_table_is_fully_wired` for a FRONTEND_PENDING entry
left stale, and `must_not_spawn_tools_or_read_host_environment` for the
no-subprocess guarantee. The advisory gate is a script, not a test.

### Step 9: Prescan bounds and the panic guard (judgment)

The parser's recursion and re-parse shapes get token-level prescan bounds
plus a source byte cap, and every parse runs behind a panic guard that maps
errors and panics to parse-error or too-deeply-nested coverage gaps, never
a crash or abort. The shared depth cap in crates/egress-core/src/prescan.rs
covers some languages; Go needed its own prescan because the bound shapes
are parser-specific: prefix unary runs, else-if chains, consecutive labels,
nested func literals, bracketed array lengths, and statement runs under the
semicolon-insertion rule, with the byte cap sized off the measured peak RSS
multiplier (about 280x for gosyn 0.2.15). Choosing the shapes and values is
the judgment part; once chosen they are pinned by per-language bound tests
and a standard-library sweep.

Fails when skipped: the authored bound tests
(`prefix_unary_run_at_the_bound`, `func_literals_nested_past_the_bound`,
`source_over_the_byte_cap_is_too_deep` for Go) and the ignored sweeps
`stdlib_files_pass_the_go_prescan` and
`stdlib_files_survive_the_full_lower_path` are the tripwires; a new port
writes its own equivalents.

### Step 10: Positions

Parser position helpers that panic on some nodes are never called; sites
get positions only from panic-safe helpers or from scalar-offset spans
computed directly. Go's policy avoids the gosyn position methods that panic
on list and field-list nodes. BOM and CRLF inputs keep correct lines and
columns, covered by a corpus case.

Fails when skipped: `stdlib_files_survive_the_full_lower_path` fails on a
panic escape, and `corpus` gates the positions fixture.

### Step 11: Lower to the shared IR

One source file lowers to imports under the language's local-name rules
(Go drops version elements and go- prefixes, lets aliases win, treats a dot
as a star import and an underscore as a value use), member-qualified
references classified call, construct, type-position, value-escape, or
assignment-target, constructor sites, module constants and
single-assignment locals for destination resolution, and symbol paths
(Type.Method, closure ordinals, init ordinals, the module scope). The
walker runs behind its own depth counter on top of the prescans.

Fails when skipped: `corpus` gates the ordinary cases, and
`every_corpus_mechanism_is_a_data_entry` fails when an expected mechanism
names no data entry.

### Step 12: Link and resolve modules

The link hook groups lowered files into packages, rewrites sibling-file
references through synthetic bindings, and resolves import paths in
toolchain order: the standard library, a governing module path with
in-root replace, a vendored tree, then an external module. The
`SpecifierRules` seam gained `package_key` and `replaced` for the Go
re-keying, one mechanism the original outline had not foreseen. Ambiguity
across build variants or undeclared roots becomes a resolution-limit
construct, never a silent binding, and the link runs under the
resolver_steps budget and the panic guard, degrading to unresolved-module
rules and a frontend-failure blind spot.

Fails when skipped: `corpus` gates the module-resolution cases.

### Step 13: Curate the data (judgment)

Replace the provisional module classes with member-level curation: egress
entries for the members that send data out, blind-spot entries for the ones
that might, inert rows with justifications for the rest, catalog seeds for
the common third-party packages, and the closure families the language
needs. This is judgment. The Go worked example put the net tree minus its
parse-only packages plus the process, code-loading, and
runtime-introspection packages on the deny list with member-level entries,
gave unsafe, runtime/cgo, and syscall/js module-level native-code blind
spots, and asserted `package_name` on import paths whose last element
cannot be the clause (nats.go becomes nats). Every curated entry names the
corpus fixture that labels it or a deferred-ledger entry.

Fails when skipped: `every_stdlib_module_is_classified_exactly_once`,
`no_deny_list_module_is_wholly_inert`,
`every_inventory_member_is_classified`,
`every_entry_names_a_fixture_that_labels_it_or_is_deferred`, and
`members_named_by_the_member_inert_rule_are_never_inert`.

### Step 14: Native code, reflection, and build hooks

Assembly, cgo, and other native sources in a scanned package are listed as
native-code blind spots and never opened. Reflective access on a tracked
value (reflect.Value.Call on a resolved function) got its own arm in the
classify match, another mechanism the outline had not foreseen, and the
build-hook construct family covers generation directives (`//go:generate`
lines and the manifest's tool directives), reported or skipped and never
run. Which construct kinds a port needs is judgment, sized on the
language's real escape routes.

Fails when skipped: `every_hook_family_yields_one_blind_spot` keeps the
hook families honest, and `corpus` gates the native-code and directive
cases.

### Step 15: The corpus and the ledgers

fixtures/corpus/<language>/<category>/<case>/ holds a tree and an
expected.toml per case; each of the seven categories holds at least one
case or a categories entry in fixtures/corpus/deferred.toml with a reason.
Cases not yet passing sit in fixtures/corpus/pending.toml, and a pending
case that starts passing fails the run, so the ledgers drive the work
forward instead of hiding it. Cases are authored with their sidecars before
the detector that passes them.

Fails when skipped: `corpus-dir-missing`, `category-uncovered`,
`category-deferral-stale`, and `corpus`, with
`every_entry_names_a_fixture_that_labels_it_or_is_deferred` tying data
entries to fixtures.

### Step 16: README (judgment)

The language joins the README language list, the caveats paragraph, and the
limitations entries. No automated check reads the prose, which is why the
step is marked judgment. Go added the newer-release caveat in the same
terms as the browser-dom one, the -ldflags -X caveat for package-level var
destinations, the build-constraint and generate limitations, the
generic-method parse-error note, and the same-package constants line under
destination resolution.

## The next language: Java

Java is next. It is mostly static: imports and qualified names resolve
without running the code, so its blind-spot set is bounded and nameable:
reflection, Class.forName with a non-literal name, ServiceLoader, JNI and
System.loadLibrary, custom class loaders, javax.script, and JNDI lookups.
It is also the largest enterprise supply-chain surface the tool does not
yet cover. Kotlin follows on the same JVM model once Java is in.

The parser question the Java plan must settle: tree-sitter-java 0.23.5
brings a C runtime and error-recovered trees, which the code plan already
declined as a frontend base; no mature pure-Rust Java parser was found on
crates.io as of 2026-10-03; writing one is the third option. The Java plan
decides among these and how the chosen parser is made stack-safe.
