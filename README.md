# PIIAT-MitreCar

**Turn raw DFIR evidence into one MITRE-aligned timeline — normalise every
artefact into MITRE CAR, relate the objects through proven relationships, and
(roadmap) flag adversary TTP behaviours — automatically.**

An analyst points it at what their forensic tooling already produces and gets
back a timeline that is **CAR-normalised**, **relationship-enriched**, and
heading toward **TTP-flagged** — the complete, faithful model of what happened,
not just the events a single detection cares about.

## What it does

- **Normalises** processor output — EvtxECmd, log2timeline (Plaso), Zeek, RECmd,
  SRUM, [PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem) memory — into
  finished [MITRE CAR](https://car.mitre.org/) objects. Every record carrying a
  valid CAR object + canonical action is mapped; honest nulls, nothing faked.
- **Relates** those objects — owning process, parent, auth↔session (LUID),
  file→process, thread injection — as a granular relationship timeline, typed
  against the MITRE ATT&CK data-sources relationship vocabulary.
- **Flags TTPs** (roadmap, [#12](https://github.com/Get-Sybers/PIIAT-MitreCar/issues/12)):
  CAR/ATT&CK analytics over the objects and relationships surface adversary
  behaviours on the same timeline.

## Quickstart

```
git submodule update --init --recursive          # the model comes from pinned submodules
python -m piiat_mitrecar --in <file-or-dir> --out <dir>   # one source
python -m piiat_mitrecar --batch <processed_dir>          # every source, isolated
```

Each evidence **source** becomes two self-contained SQLite stores:

- **`car.db`** — the CAR object events (one table per object) + `car_<object>.jsonl`.
- **`superset.db`** — the CAR + ATT&CK superset model and the relationship-instance
  timeline linking the car.db rows (`car_relationships.jsonl`).

## Documentation

| doc | what |
|---|---|
| [docs/Architecture.md](docs/Architecture.md) | principles, components, coverage, the two-store model |
| [docs/DataModel.md](docs/DataModel.md) | CAR (13) + the CAR+ATT&CK superset (38), reconstructed live from pinned submodules |
| [docs/CAR-Pipeline.md](docs/CAR-Pipeline.md) | how the pipeline works end to end |
| [docs/CAR-Relations.md](docs/CAR-Relations.md) | per-object rules and the enrichment-cascade reasoning |

The north-star goal (evidence → CAR → superset relationships → flagged MITRE
TTPs) and its workstreams are tracked in
[#12](https://github.com/Get-Sybers/PIIAT-MitreCar/issues/12).

## Contributing

Setup (submodules + dev install), commands, code style, and the branch/release
flow are in [CONTRIBUTING.md](CONTRIBUTING.md).

## The PIIAT family

Standalone public tooling, consumed by pipelines via the CLI:
[PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem) (memory → CAR),
PIIAT-l2t-plugins (log2timeline parsers), PIIAT-MitreCar (processor output → CAR).
