# Proof-gated JavaScript deobfuscation

`deobfuscate_javascript_source` / `deobfuscate-javascript-source` applies
conservative static rewrites to one explicitly selected UTF-8 JavaScript file.
It is intended for captured, bundled or obfuscated scripts where readability can
be improved without executing target code.

This capability is distinct from [JavaScript source recovery](javascript-recovery.md).
Wakaru extracts and rewrites module structure; js-redox instead emits one
semantics-preserving-by-design transformed file plus a proof report describing
which rewrite classes actually fired. REA keeps the contracts separate rather
than pretending those results have the same meaning.

## Caller-supplied engine

The adapter currently targets js-redox `deobfuscate-safe` **0.1.0** on Linux
x64. Repository unit and MCP tests exercise the protocol and lifecycle with
controlled fixtures; they do not build or attest a real external js-redox
binary. The pinned revision below is the audited reference build used for manual
real-provider qualification. Set `REA_JS_REDOX_COMMAND` to an absolute path to
that executable. The private runtime filesystem must permit execution: set
`TMPDIR` to a writable exec-capable filesystem when the host's default temporary
directory is mounted `noexec`. REA checks executable access to its fingerprinted
snapshot before launching it and reports this missing prerequisite as a
capability error.

The adapter uses util-linux `prlimit` (default `/usr/bin/prlimit`; override with
absolute `REA_JAVASCRIPT_PRLIMIT_COMMAND`). REA installs neither tool and checks
the configuration only when deobfuscation is requested. The selected limiter is
fingerprinted independently of the engine. Each engine phase executes through a
fresh verified private copy so a worker cannot mutate the limiter pathname used
by the next phase.

The audited source revision is
`cfb9bc0788d326e6020568b298aa48135eb323d1` from
`codeandsolder/js-redox`. The result separately records the caller-supplied
executable's configured path, canonical resolved path and SHA-256. REA rechecks the configured selection before publication, including symlink retargeting. `executed_source_revision` remains `null`:
the version string and executable hash identify the bytes REA ran but do not
prove which source tree produced them.

The audited revision adds only the standard `--version` surface required for
producer admission; it does not alter deobfuscation semantics.

## Build js-redox

Build the audited source with Rust 1.99:

```sh
git clone https://github.com/codeandsolder/js-redox.git
cd js-redox
git checkout cfb9bc0788d326e6020568b298aa48135eb323d1
cargo +1.99.0 build --release -p jsvm-lift --bin deobfuscate-safe
export REA_JS_REDOX_COMMAND="$PWD/target/release/deobfuscate-safe"
```

`deobfuscate-safe --version` must report `jsvm-lift 0.1.0`.

## Deobfuscate and analyze

```sh
rea deobfuscate-javascript-source /tmp/web-scripts/app.js /tmp/deobfuscated-app --json
rea analyze-javascript-application /tmp/deobfuscated-app/deobfuscated --json
```

MCP input:

```json
{
  "path": "/tmp/web-scripts/app.js",
  "output_directory": "/tmp/deobfuscated-app",
  "max_iterations": 16
}
```

The output directory must be absent and absolute. REA takes a stable snapshot of
the selected input in a private workspace, fingerprints the engine, executes the
worker under its owned-process boundary, validates the machine-readable proof
report against the exact input and output digests, rechecks the original and
engine bytes, and only then commits an exclusively owned output tree. Failure
rolls the tree back.

Published contents:

- `inputs/source.js`: exact original source snapshot.
- `deobfuscated/source.js`: the proof-gated unformatted output.
- `reports/js-redox.json`: exact `js-safe-deobfuscate/v1` producer report.
- `manifest.json`: source, output, report, engine and option identities, plus
  the limiter's configured/canonical identity and per-phase private snapshot
  path, digest, size and exact effective argv.
- `diagnostics/`: retained version and transformation stdout/stderr. Evidence
  includes file paths, hashes, retained and observed byte counts, exit status
  and truncation state; diagnostic text stays in these files.

The inline provider-neutral `proof` contains only the selected source SHA-256
(`input_sha256`) and published output SHA-256 (`output_sha256`). Provider-specific
rewrite counts, iteration details, arithmetic/alias proof information and safety
flags remain in `reports/js-redox.json`; read that published report when those
js-redox details are needed rather than expecting them in CLI/MCP Evidence.

## Semantics and limits

REA deliberately does **not** pass js-redox `--format-output`. The admitted
report must say `safe_static_only: true`, `presentation_formatted: false` and
`runtime_semantics_preserved_by_design: true`; its input, output and analysis
source digests must match the bytes REA observed. A rewrite whose proof
preconditions do not hold stays unchanged.

That contract does not mean the output is original source. It does not recover
original identifier names, source maps or runtime inputs, and it does not claim
complete deobfuscation. It says only that the emitted unformatted rewrite was
produced by js-redox's fail-closed static transform set under the validated
report contract. Target JavaScript is never executed.

The current adapter gives the owned worker a single-thread hint plus per-process
ceilings of at most 1 GiB virtual address space, 64 MiB file size and 120 CPU
seconds; each ceiling is clamped so REA never raises the process's inherited
soft or hard limit. The version probe and transform share one 120-second launch
deadline. Input and transformed output are limited to 64 MiB each; the report
and diagnostic streams are limited to 8 MiB. The manifest records the exact
per-phase `prlimit` argv after inherited-limit clamping. There is no aggregate
process-count or cgroup memory limit. Other host platforms are not claimed by
this adapter.
