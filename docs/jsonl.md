# JSONL for pipelines

[Quick start](../README.md) · [CLI usage](usage.md) · [Operations](operations.md) · [Result API](library.md)

`--jsonl` writes **one complete result object per nonblank input target** to stdout as each result finishes. It is not a JSON array, and it is not a replayable response capture. Use only authorized targets.

## First commands

Classify the shipped synthetic examples with no network requests:

```sh
wafmeow --evidence assets/demo/captures.jsonl --jsonl --silent |
  jq --unbuffered -c '{
    target,
    classification: .outcome.state,
    products: [.outcome.matches[]?.product],
    diagnostics: [.outcome.diagnostics[]?.code],
    generic_mode: .generic.mode
  }'
```

This is a **readable projection**, not a different wafmeow output schema. The synthetic inputs cover a named match, a complete no-match, and a match with incomplete evidence. Full JSONL retains supporting evidence and provenance.

To return URLs with named matches:

```sh
set -o pipefail
wafmeow --target-file authorized-urls.txt --fast --jsonl --silent |
  jq --unbuffered -r '
    select(((.outcome.matches // []) | length) > 0)
    | .target
  '
```

This deliberately retains positives even when other fingerprint checks remain incomplete. An evidence-backed match is not proof that a probe caused blocking.

To save a final report while rejecting an empty job:

```sh
wafmeow --target-file authorized-urls.txt --fast \
  --output results.jsonl --silent --strict --require-results
```

`--require-results` exits 1 on zero processed targets and preserves any previous named report; it counts occurrences, not successful HTTP responses. It does not replace `--strict`. Without it, empty input succeeds, even with `--strict`.

## Understand each result

Classification, named matches, HTTP diagnostics, generic anomalies, and browser collection are **separate dimensions**.

| JSON path | Interpretation |
| --- | --- |
| `schema_version` | Report schema (currently 1), not Go module major or a matched fingerprint index |
| `target` | Input label/URL; repeated target occurrences remain separate results |
| `outcome.state` | `complete`, `incomplete`, or `failed` classification; **not** a WAF-present boolean |
| `outcome.matches[]` | Named products supported by fingerprint evidence, even when some checks remain unresolved |
| `outcome.incomplete_products[]` | Products with unresolved fingerprint checks |
| `outcome.diagnostics[]` | Structured codes and evidence indices (zero-based, or -1) |
| `generic.mode` | An independent unusual HTTP signal; empty string means no generic signal was recorded |
| `evidence[]` | Per-check body-free statuses, redirect metadata, and optional channel availability |
| `browser` | Optional separate browser/acquisition/export outcome |
| `provenance` | Program version, catalogue digest, scan mode, settings and optional import attribution |

| Classification | Named matches | Meaning |
| --- | --- | --- |
| `complete` | One or more | Positive named fingerprint evidence; catalogue-relative classification settled |
| `incomplete` | One or more | At least one positive; other product checks unresolved |
| `complete` | None | No named fingerprint satisfied by the observed evidence |
| `incomplete` | None | No named positive, but insufficient evidence for a negative conclusion |
| `failed` | Any | Evaluation failed; inspect diagnostics |

**Never treat an empty match list as proof of WAF absence.** Even `complete` means only that classification of the available evidence against the catalogue resolved. A generic anomaly remains distinct from a named match. `--no-generic` disables generic checks, so an empty mode under that setting is not a negative signal.

The collections `outcome.matches`, `outcome.diagnostics` and `outcome.incomplete_products` are **omitted rather than encoded as empty arrays**. Normalize with `// []` or use optional array iteration:

```sh
# Safe for no-match rows:
jq --unbuffered -c '[.outcome.matches[]?.product]'

# Complete classification with no named match:
jq --unbuffered -c \
  'select(.outcome.state == "complete" and ((.outcome.matches // []) | length) == 0)'

# Incomplete/failed or diagnosed:
jq --unbuffered -c \
  'select(.outcome.state != "complete" or ((.outcome.diagnostics // []) | length) > 0)'

# Generic anomalies, not generic-object presence:
jq --unbuffered -c 'select(.generic.mode != "")'
```

### Indices, ordering and units

Match `fingerprints[].evidence` and diagnostic `evidence` references use **zero-based** indices into `evidence[]`. Matched catalogue `schema` and `fingerprint` identifiers are **one-based**. Human output uses probe names and concise supporting HTTP statuses instead of internal indexes.

Live results arrive in **completion order** and may differ from input order; native/httpx offline records emit in input order. Eight HTTP observations do **not** guarantee eight wire requests: redirects and retries can send additional requests. The human display therefore says **HTTP checks**, not "requests made."

`provenance.settings.request_timeout` and `target_timeout` encode Go durations in integer **nanoseconds**: default 5s and 30s become `5000000000` and `30000000000`. The human run plan prints explicit seconds and "request"/"target" labels. Current `provenance.scan_mode` values are `deep`, `fast`, `baseline` and `passive`; historical schema-1 output may contain `active` instead of `deep`. See [schema versioning](library.md#versioning).

## Stdout and named reports

`--jsonl` selects **stdout only**. `--output` independently writes a final report selected by extension.

| Flags | Stdout | Final report |
| --- | --- | --- |
| `--jsonl` | Incremental JSONL | None |
| `--jsonl --silent` | The same JSONL | None; routine stderr messages suppressed |
| `--output results.jsonl` | Human output, unless `--silent` | Final JSONL |
| `--jsonl --output results.json` | JSONL | JSON array |
| `--jsonl --output results.csv` | JSONL | CSV |
| `--jsonl --output results.ndjson` | JSONL | JSONL (`.ndjson` alias) |
| `--jsonl > results.jsonl` | Redirected by the shell | Incremental, **not** atomic |

Allowed suffixes: `.json`, `.jsonl`, `.ndjson`, `.csv`, `.txt`, case-insensitively. An extensionless filename selects TXT; an unknown extension now fails early with recovery guidance instead of silently selecting TXT. `--output -` is rejected: use `--jsonl` for stdout, or `--output ./-` to create a literal file named `-`.

Machine stdout is JSON-only with `--jsonl` by itself. The human run plan and summary are sent to **stderr**; `--silent` hides that routine prose, but not fatal errors or explicitly requested `--debug` lines. Separate the two:

```sh
wafmeow --evidence assets/demo/captures.jsonl --jsonl \
  > results.jsonl 2> run.log
```

Normal human output puts the target first, reports WAF names and brief supporting evidence, records the number of HTTP checks, groups blocked redirect **origins** without query payloads, and ends incomplete targets with a plain-English explanation. Full redirect URLs, raw probe details, diagnostic codes and evidence availability remain in JSONL and `--debug`.

## Completion, failure and recovery

JSONL stdout is **incremental**, not a completion certificate. Earlier valid records can survive a later malformed input, downstream error or cancellation. A result file has no guaranteed final footer; **check the process exit status**. Use `set -o pipefail` for pipelines.

| Exit | Meaning |
| --- | --- |
| 0 | Run completed without fatal failure; inspect result states unless using `--strict` |
| 1 | Configuration/input/output failure, or empty input when `--require-results` was selected |
| 2 | `--strict` found incomplete/failed/diagnosed results or browser/artifact failures |
| 130 | Cancelled |

`--strict` checks evidence quality, **not** whether a named WAF matched. Generic anomalies alone do not necessarily trigger strict. The supported httpx import profile records limitations, so strict usually exits 2 for such imports; see [httpx import](usage.md#httpx-response-import).

Named reports are staged and atomically replaced only after processing succeeds. If processing fails before publication, the previous report is preserved. A later summary/journal-close error can exit 1 **after publication**; CLI error guidance reports the known publication state. An early-closing downstream consumer such as `head -n 1` can cause a broken pipe and prevent a named report from being published. For a preview that drains the input instead:

```sh
wafmeow --target-file authorized-urls.txt --fast \
  --jsonl --output results.json |
  sed -n '1p'
```

Three different JSONL artifacts have distinct contracts:

| Artifact | Purpose | Input to `--evidence`? |
| --- | --- | --- |
| Result report (`--jsonl` / `--output`) | Classified results and body-free evidence summaries | No |
| Native capture | Recorded HTTP observations including available response bodies | Yes |
| Diagnostics journal | Durable result/diagnostic envelopes for recovery | No |

Reports and journals can contain sensitive target URLs, redirects and metadata. Apply appropriate permissions and retention. Fingerprints are advisory evidence—not proof of enforcement or absence.
