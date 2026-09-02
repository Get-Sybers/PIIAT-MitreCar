# `model/` — the materialized data model

A **human-navigable, human-readable** snapshot of the two models this project
runs on, materialized as static YAML (plus the SQL schema snapshots) so the shape
of the model is reviewable without checking out the submodules or running the
pipeline. Everything here is **generated from the project's own model code** at
the pinned submodules — never hand-written — and is fully regenerable.

This implements the intent of issue #33: keep the static relationship/data-source
model as YAML, co-located with a generator and this README.

## Source of truth

The live source of truth is **not** this directory — it is the pinned submodules
and the code that reconstructs the models from them:

| Submodule | Pinned commit |
|-----------|---------------|
| [`third_party/car`](../third_party/car) (MITRE CAR data model) | `1b922fe1527d956e222a99473472e594f10f610b` |
| [`third_party/attack-datasources`](../third_party/attack-datasources) (ATT&CK data sources) | `5d50f731de441eb09078623a2c29cc3420a01949` |

The files under `model/` are a **materialized snapshot of that pinned model**
(materialized 2026-09-02). A model refresh is a **submodule-pin bump** followed by
re-running the generator — never a hand edit here. This is consistent with the
repo's guiding principle: *everything is data, reconstructed from source* (the
CAR/superset models are otherwise built on demand and nothing generated is
normally committed; see [`docs/DataModel.md`](../docs/DataModel.md)).

## Layout

```
model/
├── generate.py                      the ONE generator — reproduces everything below
├── car/
│   └── objects/<object>.yml         one file per CAR object (13)
├── superset/
│   ├── model-objects.yml            the CAR + ATT&CK object catalogue (38)
│   ├── relationship-types.yml       the ATT&CK relationship vocabulary (243 edge-types)
│   └── relationship-schema.yml      the relationship-instance table shape
└── sql/
    ├── car.sql                      schema-only dump of a fresh car.db
    └── superset.sql                 schema + reference-model seed of superset.db
```

### `car/objects/<object>.yml` — the 13 CAR objects

One file per canonical MITRE CAR object (`authentication`, `driver`, `email`,
`file`, `flow`, `http`, `module`, `process`, `registry`, `service`, `socket`,
`thread`, `user_session`). Each file carries the object's name and description,
its `car_action` list (from the superset `model_object.actions`), and its
`properties`, **clearly separated** into:

- **`common_header`** — the eight fields every CAR event row shares
  (`timestamp`, `car_action`, `guid`, `owning_guid`, `link_confidence`,
  `source_artefact`, `source_host`, `native`), defined by
  [`piiat_mitrecar/store.py`](../piiat_mitrecar/store.py) (`HEADER`); and
- **`object_fields`** — the object's MITRE CAR fields, with the description and
  example the CAR data model provides for each.

### `superset/` — the CAR + ATT&CK superset

- **`model-objects.yml`** — the 38-object catalogue: each object's `name`,
  `source` (`car` | `attack` | `car+attack`), `actions`, and `definition`
  (the ATT&CK data-source definition, `null` for CAR-only objects).
- **`relationship-types.yml`** — the 243 identified ATT&CK relationships, each a
  `source --relationship--> target` edge, grouped by source element for
  navigability. This is the cascade *vocabulary*.
- **`relationship-schema.yml`** — the column shape of the `relationship`
  instance table in `superset.db` (`id`, `timestamp`, `source_host`,
  `relationship`, `source_object`, `source_guid`, `target_object`,
  `target_guid`, `confidence`, `method`).

### `sql/` — the SQL schema snapshots

Frozen `.sql` dumps of the pipeline's two SQLite databases, produced by invoking
the **same store classes the pipeline uses** and dumping with `sqlite3`'s
`iterdump()` — no schema is re-implemented.

| File | What it holds |
|------|---------------|
| `car.sql` | **Schema only** — the 13 CAR-object tables, each with its canonical property columns plus `guid`/`timestamp` indexes. No event rows: CAR events only exist after evidence ingestion. |
| `superset.sql` | Schema (`model_object`, `relationship_type`, `relationship` + indexes) **plus the reference model seed**: `model_object` (38 rows) and `relationship_type` (243 rows), reconstructed from the pinned CAR + ATT&CK model. The `relationship` instance table is empty (those rows are cascaded from evidence). |

These committed snapshots are a **deliberate exception** to the repo's "nothing
generated is committed" convention — a point-in-time record kept for safekeeping
and easy inspection, not a live artifact. The live source of truth remains the
pinned submodules and the store code.

## Regenerating

One command, from the repo root, after the submodules are checked out and the
package is installed:

```sh
git submodule update --init --recursive third_party/car third_party/attack-datasources
pip install -e .
python model/generate.py
```

[`model/generate.py`](generate.py) reproduces **every** file above — the
per-object YAML, the superset YAML, and both SQL dumps — deterministically from
the pinned submodules. It re-uses the project's own model code rather than
re-implementing anything:

- [`piiat_mitrecar/carmodel.py`](../piiat_mitrecar/carmodel.py) — loads the 13
  CAR objects (fields + actions) from the pinned car submodule.
- [`piiat_mitrecar/build_data_model.py`](../piiat_mitrecar/build_data_model.py) —
  builds the CAR + ATT&CK superset (objects) and the relationship catalogue.
- [`piiat_mitrecar/store.py`](../piiat_mitrecar/store.py) — the `CarStore`
  schema (common header + per-object columns) and `car.sql`.
- [`piiat_mitrecar/superset.py`](../piiat_mitrecar/superset.py) — the
  `SupersetStore` schema, the model/relationship-type seed, and `superset.sql`.

## Inputs that feed the model

Two **hand-authored** input files (kept under `piiat_mitrecar/`, not here) drive
the relationship layer and are *not* regenerated by this directory — they are the
inputs the materialized superset is built against:

- [`piiat_mitrecar/relationships.yml`](../piiat_mitrecar/relationships.yml) — the
  CAR inheritance / dedupe / identity / join rules the enrichment cascade applies.
- [`piiat_mitrecar/cascade_relationships.yml`](../piiat_mitrecar/cascade_relationships.yml)
  — maps each cascade edge (owning-process, parent, auth↔session, file→process,
  thread injection) to a verb in the ATT&CK relationship vocabulary materialized
  in `superset/relationship-types.yml`.
