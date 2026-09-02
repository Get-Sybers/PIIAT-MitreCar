# Architecture

## Principles

- **Artefact ≠ processor.** Maps are keyed to the *artefact* (the Windows event
  log, the filesystem, a flow), never to the tool that parsed it. EvtxECmd and
  log2timeline share one set of event-log maps via a format adapter
  (`piiat_mitrecar/adapters/`), verified to produce byte-identical CAR from the
  same evidence. A new processor for a mapped artefact is a new *adapter*, never
  a second map set.
- **One source → one database.** Enrichment is self-contained within a source;
  no source ever depends on another being present. Cross-source correlation is a
  separate, later, scope-gated stage.
- **Grab maximally, never fake.** Every record that carries a valid CAR object +
  a canonical action is normalised (file MAC times and browser visits as much as
  process creations); nulls and duplicates are fine. What a record cannot supply
  stays **null** (never a near-miss); a record with no canonical action stays raw
  (never an action-less phantom). The only floor is that the object must exist in
  the model.
- **Everything is data, reconstructed from source.** The object model and the
  relationship vocabulary are reconstructed **live from pinned submodules**, never
  hand-copied (see [DataModel.md](DataModel.md)). The cascade rules, source
  manifests, and relationship-verb bridge are generated/declared as data, with
  drift-guarding tests — the engine implements mechanics, data declares rules.
- **Confidence is explicit.** Every enrichment link is tagged `definitive` (a
  natively-carried guid) or `heuristic` (a pid + create-time-window match).

## Two stores per source

- **`car.db`** — the CAR **object** events: one SQLite table per CAR object, one
  row per finished CAR event, plus `car_<object>.jsonl` exports.
- **`superset.db`** — the CAR + ATT&CK **superset model** (as reference data) and
  the **relationship instances** the cascade produces between the car.db events —
  `source → relationship → target` edges, timestamped, linking car.db rows by
  guid: a second, more granular *relationship* timeline (`car_relationships.jsonl`).

## Components

| | |
|---|---|
| `piiat_mitrecar/carmodel.py` | the 13 CAR objects, reconstructed live from the pinned car submodule |
| `piiat_mitrecar/build_data_model.py` | reconstructs CAR (13) and the CAR+ATT&CK superset (38) + the ATT&CK relationship catalogue from the pinned submodules |
| `piiat_mitrecar/mappings/` | declarative per-artefact maps (auto-discovered, one file per family) |
| `piiat_mitrecar/normalize.py` | the marker engine: raw record → CAR event |
| `piiat_mitrecar/adapters/` | format adapters (Plaso winevt(x) → EvtxECmd shape; l2t container splitting; jump lists) |
| `piiat_mitrecar/relationships.yml` | the within-source cascade & inheritance rules, as data |
| `piiat_mitrecar/cascade_relationships.yml` | the CAR-action → ATT&CK-verb bridge for relationship instances |
| `piiat_mitrecar/enrich.py` | the cascade: identity, two-tier owner/parent links, LUID auth↔session join, file→process, null-only inheritance, dedupe |
| `piiat_mitrecar/superset.py` | builds `superset.db`: seeds the superset model + edge-types, materialises relationship instances |
| `piiat_mitrecar/sources_model.py` + `gen_sources.py` | generates the per-source manifests (objects/actions/properties + provenance) from the maps |
| `piiat_mitrecar/store.py` | the car.db store + JSONL export |
| `piiat_mitrecar/pipeline.py` | source discovery, routing, batch mode |

## Coverage

| artefact | CAR objects filled |
|---|---|
| Windows event logs (EvtxECmd **and** Plaso — same maps) | authentication, user_session, process, service, http (BITS), file/module/flow (audit + WMI + SMB), and Sysmon process/flow/file/registry/module/driver/thread |
| Zeek | flow, http, email (content-gated), file |
| Plaso execution artefacts (prefetch/amcache/appcompatcache/userassist/bam/cron) | process (shimcache rows labelled `execution_inferred`; the amcache Link Time row is a timestamp-less file record carrying `compile_time`) |
| Plaso filesystem + sessions (filestat/mft/usnjrnl/utmp/ssh/fsevents) | file, user_session |
| Plaso registry, shell items, PE, OLE | registry, file |
| Plaso browser/download (IE, Firefox, Java idx) + lnk + recycle bin | http, file |
| RECmd (registry), SRUM | registry, flow, process |
| memory (PIIAT-Mem `car.db`) | passthrough — all memory objects, links preserved |

Records with no canonical CAR object/action are routed to nothing **explicitly**
(known, not unknown); their rows stay raw. Unvalidated inference specs live in
`to-be-validated/` until confirmed against real evidence.
