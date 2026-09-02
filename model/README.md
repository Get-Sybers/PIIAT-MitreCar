# `model/` — the materialized data model

A **human-navigable, human-readable** snapshot of the two models this project
runs on, materialized as static YAML (plus the SQL schema snapshots) so the shape
of the model is reviewable without checking out the submodules or running the
pipeline. Everything here is **generated from the project's own model code** at
the pinned submodules — never hand-written — and is fully regenerable. The one
deliberate exception is [`projection/`](projection/) (the hand-authored CAR → ECS
boundary contract, see below), which is validated *against* the generated model.

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
├── sql/
│   ├── car.sql                      schema-only dump of a fresh car.db
│   └── superset.sql                 schema + reference-model seed of superset.db
├── spindle/
│   ├── identity.yml                 the spindle row-identity registry, resolved against the maps
│   ├── record.yml                   the shape of a spindle — a minted-identity CAR row
│   └── golden.yml                   the golden vectors: the guid the engine mints per entry's sample
└── projection/                      HAND-AUTHORED: the CAR -> ECS boundary contract
    ├── conventions.yml              common header, data-stream shape, car.* namespace, rules
    ├── objects/<object>.yml         every object_field -> ECS 8.x field, or native (13)
    └── validate.py                  drift check against car/objects/*.yml (pyyaml only)
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

> **Descriptions and examples are copied verbatim from the upstream MITRE CAR
> data model** (the pinned `third_party/car` submodule). They are intentionally
> *not* edited here — this directory is a faithful snapshot — so they may carry
> upstream typos or imperfect example values (e.g. a `flow.dest_port` example
> that shows an IP address). Corrections belong upstream in the car data model,
> not in this snapshot; a submodule-pin bump + regenerate then brings them in.

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

> **Identifier note.** `relationship-types.yml` uses the upstream ATT&CK
> *data-element labels* (spaced, lower-case — e.g. `application log`), whereas
> `model-objects.yml` and the object filenames use the normalized object *keys*
> (underscored — e.g. `application_log`). They correspond one-to-one but are
> **not string-identical**, so don't join the two files on the raw label.

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

### `spindle/` — the spindle row identity

A disk-image row (log2timeline / Plaso) carries no sensor-minted id, so its
`guid` is **minted**: `uuid5(SPINDLE_NS, canonical_json({"_obj": <object>,
"_v": <version>, <name>: <value>, …}))` over the record's own stable-identity
fields — the same recipe the STIX projection mints §2.9 ids with
([`piiat_mitrecar/ids.py`](../piiat_mitrecar/ids.py); `ids.mint` is the one
seam). *Which* fields identify each artefact's row is a rule, declared as data
in [`piiat_mitrecar/spindle.yml`](../piiat_mitrecar/spindle.yml) (a map only
names its entry): per entry the CAR object, the `kind` (`record` — a
record-numbered / journal key asserting the *same record*; `entity` — a
content-like key asserting records that *coincide*), the `scope` (`intrinsic`;
`positional` is the per-record fallback), the identity-key `version` (hashed
as `_v`), what it is `validated_against` (`[plaso]` — cross-run within the
tool — until a second tool's map renders the same key on a real record), what
it is `stable_across`, the ordered `identity` and a `golden` sample. The
registry also declares the **external forms** every other map carries
verbatim (a sensor's or tool's own id) and the cross-source **equality** rule
(#41). This directory is that registry's materialized snapshot:

- **`identity.yml`** — every registry entry resolved against the live maps:
  `name`, `map`, `variants`, `car_object`, `car_action`, `kind`, `scope`,
  `version`, `validated_against`, `stable_across`, the ordered `identity`
  (`name ← source path on the event`), the positional `fallback`
  (`SourceImage`, `RecordId`) — plus the external forms with the maps that
  carry them, the equality rule, the literal namespaces (`STIX_NS`, `CAR_NS`,
  `SPINDLE_NS`), the mint rule and the scope / kind vocabularies.
- **`record.yml`** — the shape of a spindle: what a minted-identity CAR row
  *is* (the common header, `native.spindle_key`, `native.spindle_scope`,
  `native.spindle_ref` — the record's provenance, outside the key — the
  linkage back to its artefact) and its invariants, in the `car/objects`
  convention.
- **`golden.yml`** — the golden vectors: per entry the key and the guid the
  engine mints for its sample at the entry's version, the positional vector,
  one vector per external form, and the recipe vector. It is the **change
  protocol's evidence**: an entry's guid may move only together with its
  version; the recipe vector never moves.

All three are generated by `python model/generate.py` (or
`python -m piiat_mitrecar.spindle`) from
[`piiat_mitrecar/spindle.py`](../piiat_mitrecar/spindle.py) — the code the
engine mints with — and drift is caught by `python -m piiat_mitrecar.spindle
--check` (CI) and `tests/test_spindle_model.py`: registry ↔ maps ↔ engine,
committed snapshot ↔ fresh rendering, and the golden gate. **Changing an
identity** follows the protocol in `spindle.yml`: edit the entry → bump its
`version` → `python model/generate.py` → commit `model/spindle/` (golden.yml
included) → rebuild the stores (`--batch --force`; a remint tool follows). The
check — and the generator itself — refuse an identity whose guid moved without
its version. See `docs/CAR-Pipeline.md` §7.1.

### `projection/` — the CAR → ECS boundary contract (hand-authored)

The static YAML contract that decides how each CAR object and field lands in
**ECS 8.x** when DX_DFIR loads CAR into Elastic as `logs-car.<object>-*` data
streams: `conventions.yml` (the common header — `guid → event.id`,
`owning_guid → process.entity_id`, `native → car.native` …, the data-stream
shape, the `car.*` custom namespace) and `objects/<object>.yml` (every
`object_field` → an ECS field, or `native: true` with a rationale where ECS has
no honest home). It is **not generated** — projections are decisions — but it
is **validated against** `car/objects/*.yml` by `python model/projection/validate.py`,
which fails on any drift (a CAR field without a decision, an entry naming a
field that does not exist). See [`projection/README.md`](projection/README.md).

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
- [`piiat_mitrecar/spindle.py`](../piiat_mitrecar/spindle.py) — the spindle
  registry resolved against the maps, and the spindle record shape (`spindle/`).

## Inputs that feed the model

Three **hand-authored** input files (kept under `piiat_mitrecar/`, not here) drive
the relationship and identity layers and are *not* regenerated by this directory
— they are the inputs the materialized models are built against:

- [`piiat_mitrecar/relationships.yml`](../piiat_mitrecar/relationships.yml) — the
  CAR inheritance / dedupe / identity / join rules the enrichment cascade applies.
- [`piiat_mitrecar/cascade_relationships.yml`](../piiat_mitrecar/cascade_relationships.yml)
  — maps each cascade edge (owning-process, parent, auth↔session, file→process,
  thread injection) to a verb in the ATT&CK relationship vocabulary materialized
  in `superset/relationship-types.yml`.
- [`piiat_mitrecar/spindle.yml`](../piiat_mitrecar/spindle.yml) — the spindle
  row-identity registry: per artefact, the fields a disk-image row's guid is
  minted from, materialized in `spindle/identity.yml`.
