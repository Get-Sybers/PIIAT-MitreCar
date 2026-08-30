# PIIAT-MitreCar

**Turn raw DFIR processor output into finished MITRE CAR.**

Point it at what your forensic tooling already produces — EvtxECmd JSON,
log2timeline (Plaso) JSONL, Zeek logs, a [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem)
memory `car.db` — and each evidence **source** becomes its own self-contained
[MITRE CAR](https://car.mitre.org/) database plus per-object JSON export:

```
input source ──▶ artefact map(s) ──▶ normalize ──▶ its own car.db ──▶ enrich
   (a file        (object/action/      (raw row →     (SQLite, one     (self-
    or a dir)      property rules)      CAR event)     table/object)    contained)
                                                                          │
                                                        JSON out ◀────────┘
                                                   car_<object>.jsonl → your store
```

```
python -m piiat_mitrecar --in <file-or-dir> --out <dir>       # one source
python -m piiat_mitrecar --batch <processed_dir>              # every source, isolated
```

## The goal

This is a **timelining enrichment / normalisation tool for ALL the CAR objects
available in a data source** — not an analytic-event timeliner. The trap this
tool exists to avoid: extracting only the events some detection cares about.
Every record that carries a valid CAR **object** performing a valid **action**
with canonical **properties** is normalised — file MAC times and browser visits
as much as process creations and injected threads. What a record honestly
cannot supply stays **null** (never a near-miss); a record with no valid CAR
action stays raw (never an action-less phantom). Detection is downstream's
job; this tool's job is the complete, faithful model.

## Principles

- **Artefact ≠ processor.** Maps are keyed to the *artefact* (the Windows
  event log, the filesystem, a flow) — never to the tool that parsed it.
  EvtxECmd and log2timeline share one set of event-log maps via a format
  adapter (`piiat_mitrecar/adapters/`), verified to produce byte-identical CAR
  from the same evidence. A new processor for a mapped artefact is a new
  *adapter*, never a second map set.
- **One source → one database.** Enrichment is self-contained within a source;
  no source ever depends on another being present. Cross-source correlation
  belongs downstream.
- **The model is data, not code.** The authoritative
  [mitre-attack/car](https://github.com/mitre-attack/car) repo is vendored as
  the `third_party/car` submodule; the packaged `car_data_model.json` (13
  objects, every action and property) is a verified exact match to it. The
  **relationships are data too**: `piiat_mitrecar/relationships.yml` declares
  what may be inherited, how identities join, and what makes two rows the same
  event — the engine implements mechanics, the YAML declares rules, and
  `docs/CAR-Relations.md` holds the reasoning (the MITRE wording grounding
  every rule, the definitive-vs-heuristic tier arguments, the
  must-never-assert limits).
- **Grab maximally, never fake.** Honest nulls, canonical actions only,
  forgeable values recorded-not-trusted, and every enrichment link tagged with
  its confidence (`definitive` — a natively-carried guid; `heuristic` — a
  pid + create-time-window match).

## What's inside

| | |
|---|---|
| `piiat_mitrecar/carmodel.py` | loads the 13-object model (single source of truth) |
| `piiat_mitrecar/mappings/` | declarative per-artefact maps (auto-discovered, one file per family) |
| `piiat_mitrecar/normalize.py` | the marker engine: raw record → CAR event |
| `piiat_mitrecar/adapters/` | format adapters (Plaso winevt(x) → EvtxECmd shape; l2t container splitting) |
| `piiat_mitrecar/relationships.yml` | the relationship & inheritance rules, as data |
| `piiat_mitrecar/enrich.py` | the cascade: identity, two-tier owner/parent links, LUID auth↔session join, null-only inheritance, dedupe |
| `piiat_mitrecar/store.py` | one SQLite table per CAR object + `car_<object>.jsonl` export |
| `piiat_mitrecar/pipeline.py` | source discovery, routing, batch mode |
| `docs/` | how it works (`CAR-Pipeline.md`) and the per-object rules (`CAR-Relations.md`) |

## Coverage

| artefact | CAR objects filled |
|---|---|
| Windows event logs (EvtxECmd **and** Plaso — same maps) | authentication, user_session, process, service, http (BITS), and Sysmon's process/flow/file/registry/module/driver/thread |
| Zeek | flow, http, email (content-gated), file |
| Plaso execution artefacts (prefetch/amcache/appcompatcache/userassist/bam/cron) | process |
| Plaso filesystem + sessions (filestat/mft/usnjrnl/utmp/ssh) | file, user_session |
| Plaso browser/download (IE, Firefox, Java idx) + lnk + recycle bin | http, file |
| memory (PIIAT-Mem `car.db`) | passthrough — all ten memory objects, links preserved |

Tables with no CAR object (Zeek dns/ssl/x509/…, Plaso pe/olecf/…) are routed
to nothing **explicitly** — known, not unknown; their rows stay raw.

## The PIIAT family

Standalone public tooling, consumed by pipelines via the CLI: PIIAT-Mem
(memory → CAR), PIIAT-l2t-plugins (log2timeline parsers), PIIAT-MitreCar
(processor output → CAR).
