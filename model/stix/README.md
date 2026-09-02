# `model/stix/` — the CAR → STIX 2.1 projection contract

**Hand-authored. Validated by `validate.py`. Engine: `piiat_mitrecar/stix.py`.**

This directory is the one place that decides *how the finished stores become
STIX 2.1 at export*. The projection is **derived from CAR** — `car.db` (the
object events), `superset.db` (both relationship classes, the reconstructed
nodes, the content-keyed attribution layer) and the `native` bag — and from
nothing else. There is no parser-side STIX and no second extraction path: a
re-export of the same stores reproduces the same bundle, byte for byte. OpenCTI
(or any STIX consumer) is an **exchange interface only**; the stores stay the
truth.

Like `model/projection/` (CAR → ECS), nothing here is generated: a projection
is a *decision* (is a Windows service a `process` with `windows-service-ext`,
or nothing? — a process), and decisions are authored, reviewed and versioned by
hand. What is mechanical is keeping them in step with the generated CAR model
and with the engine — that is `validate.py` plus `tests/test_stix.py`.

## Layout

```
model/stix/
├── README.md          this file
├── conventions.yml    the id-derivation rules (global vs case-scoped), the identity conventions
│                      mirrored from CAR -> ECS, observation / relationship / inferred-node shape,
│                      and the three engine declarations
├── objects.yml        one entry per CAR object (13): its SCO, its SRO end, its hash subject, its
│                      acting-process columns, and every object_field's home
└── validate.py        the drift check (pyyaml only) — exit 1 on any problem
```

## What a bundle holds

| STIX object | from | one per |
|---|---|---|
| SCOs (`process`, `file`, `directory`, `windows-registry-key`, `network-traffic`, `user-account`, `ipv4-addr`/`ipv6-addr`, `domain-name`, `url`, `email-addr`, `email-message`, `x-car-thread`) | car.db rows | entity a row observes (superset-filled across rows) |
| content SCOs (`file` by hash, `user-account` by real SID) | superset `content_node` (derive's content pass over the same events) | content |
| `observed-data` | car.db rows | row — the observation, `x_car_*` header, `x_car_native` verbatim, `x_car_fields` for what no SCO property homed |
| `relationship` | superset `relationship` | row, both classes, labelled `car:declared` / `car:derived` + `car:<method>` |
| `x-car-inferred-node` | superset `inferred_node` | reconstructed node — flagged, never an SCO, never inside an observation |
| `identity` | — | bundle (the producer) |

## Ids — the two scopes

- **Content-keyed → global, spec-deterministic.** A file by hash, an account by
  real SID, an IP, a domain, a URL, an e-mail address get the STIX 2.1 §2.9 id:
  UUIDv5 over the STIX namespace and the canonical JSON of the ID-contributing
  properties. For a file *one* hash contributes (MD5, SHA-1, SHA-256, SHA-512 —
  the first present), and the hash nodes one record co-references are unioned
  first so the file carries all its hashes. `name` would contribute, so the
  content file carries none — names, paths and signers ride in `x_car_*`.
  The same content is the same object in every case, for every consumer.
- **Instance / observation → case-scoped.** A process, a file at a path, a key,
  a connection, every `observed-data`, every SRO get UUIDv5 under a per-case
  namespace (`--case`, default the car directory's name). A re-export of the
  same case is idempotent; two cases never collide; the same path on two hosts
  never collapses into one object. This deliberately deviates from the spec's
  UUIDv4-for-process and spec-UUIDv5-for-directory/key/traffic — see
  `conventions.yml id_derivation.case_scoped.deviation`.

## Identity conventions (mirrored from CAR → ECS)

`guid → x_car_event_id` (event.id) and, on a process row without `owning_guid`,
the process SCO key; `owning_guid → x_car_process_entity_id` (process.entity_id)
and the acting process the observation references; `parent_guid → parent_ref`;
`native → x_car_native` (car.native), verbatim; `link_confidence` verbatim on the
observation and as STIX `confidence` (100 / 50 / 20) on the SRO.

## The three engine declarations

1. **`hash_subject` per leaf** — what a row's `md5/sha1/sha256_hash` hash:
   `process → image_path`, `file → file_path`, `module → module_path`,
   `driver → image_path`. The hashes land on that file instance and bind it to
   the global content file (`x_car_content_ref`).
2. **The inheritance trace is kept in native.** The cascade's null-only
   inheritance writes into the spoke's columns with no marker; the only trace of
   what the cascade / derived pass did is the keys they wrote into `native`
   (`executed_as_process_guid`, `flow_guid`, `target_session_guid`,
   `target_process_guid`, `coalesced_sources`, `coalesced_conflicts`, …). The
   projection carries them verbatim and never re-derives an SRO or a `_ref` from
   them — every SRO comes from superset.db. A spoke never mints its owner: its
   acting-process columns fill the owning process SCO only when the cascade
   resolved `owning_guid`; an unresolved owner is derive's inferred node.
3. **The two native-only join keys** — `http.native.resp_fuids` (→ `file.guid`,
   the Zeek fuid; rule `http_file_transfer`) and `thread.native.TargetProcessGuid`
   (→ `process.guid`, the Sysmon 8 target; rule `injection_target`). They have no
   CAR column, live in native only, and the projection reads them from nowhere:
   the derived SROs they yield come from superset.db.

## Inferred ends are flagged, never asserted

A derived relationship may end on a node no source observed (antiforensics,
partial recovery). That end is an `x-car-inferred-node` — `x_car_inferred: true`,
`x_car_asserted: false`, `confidence: 20`, `labels: [car:inferred,
car:reconstructed]`, carrying what the observed records said about it and the
`observed-data` that corroborate it. It is never a `process` SCO, never in an
`observed-data.object_refs`, never a `car_<object>` row.

## Validating and running

```sh
python model/stix/validate.py                         # the drift check
pytest -q tests/test_stix.py                          # + the engine/contract lock-step and the smoke export
python -m piiat_mitrecar.stix export <car-dir> [--out FILE] [--case ID] [--as-of ISO]
python -m piiat_mitrecar --in <src> --out <dir> --derive --stix   # export as a pipeline step
```

## Changing it

- A CAR model refresh that adds or renames a field makes `validate.py` fail
  until the field has a decision in `objects.yml` — the intended coupling.
- A mapping decision changes in `objects.yml` **and** in the matching
  `_b_<object>` builder of `stix.py`; `tests/test_stix.py` fails when the
  `OBJECTS` table and `objects.yml` disagree on `sco`, `sro_end`, `hash_subject`
  or `acting`. Bump `contract.version` when an id recipe or a target property
  changes — ids are what consumers keep.
- Do not add a native key as an SRO source, and do not project an inferred node
  as its would-be SCO type.

## What this is not

- Not an OpenCTI connector or data model — the bundle is the interface.
- Not the CAR → ECS loader contract (`model/projection/`) — the two mirror the
  same identity conventions and are otherwise independent.
- Not a replacement for the JSONL exports; additive.
