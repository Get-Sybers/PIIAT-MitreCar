# `model/projection/` — the CAR → ECS boundary contract

**Hand-authored. Validated by `validate.py`. Owned by PIIAT-MitreCar.**

This directory is the one place that decides *how a finished MITRE CAR event
lands in Elastic*: the mapping of every CAR object and every CAR field onto
**Elastic Common Schema 8.x** (`ecs.version: 8.11.0`). It is the boundary
contract the **DX_DFIR loader consumes** to write CAR events into Elastic as
`logs-car.<object>-*` data streams — one data stream per CAR object, one ECS
document per CAR event row, no envelope.

Unlike its siblings under `model/`, nothing here is generated: a projection is
a *decision* (which ECS field is the honest home for `thread.start_address`?
none — so it stays native), and decisions are authored, reviewed and versioned
by hand. What *is* mechanical is keeping those decisions in step with the
generated CAR model — that is `validate.py`'s job, and it fails the build on
drift.

## Layout

```
model/projection/
├── README.md                      this file
├── conventions.yml                cross-cutting rules: the common header, data-stream shape,
│                                  the car.* custom namespace, precedence/coercion rules
├── objects/<object>.yml           one file per CAR object (13): every object_field -> ECS, or native
├── validate.py                    the drift check (pyyaml only) — exit 1 on any problem
└── test_projection_contract.py    thin pytest wrapper around validate.py
```

## The shape of the contract

### `conventions.yml`

- **Identity.** `timestamp → @timestamp`, `car_action → event.action` (the CAR
  verb, verbatim), `guid → event.id` (and, for `process`, `process.entity_id`),
  `owning_guid → process.entity_id` (the owning/acting process — in ECS the
  `process.*` block on a file/registry/module/… event *is* the process that
  acted), `parent_guid → process.parent.entity_id` (a MITRE `process` field, in
  `objects/process.yml`).
- **Provenance / scope.** `source_artefact → event.provider`,
  `source_host → host.name`; `event.dataset` / `data_stream.dataset` are the
  constant `car.<object>`.
- **Confidence.** `link_confidence → car.link_confidence` (float:
  `definitive = 1.0`, `heuristic = 0.5`) plus the verbatim word in
  `labels.link_confidence`. Deliberately *not* `event.risk_score` — it measures
  the owner/parent join, not event risk, and the Detection Engine's
  `risk_score_mapping` would otherwise read it as such.
- **Native.** `native → car.native` (ECS `flattened`): the source-evidence bag,
  keys verbatim. CAR *object* fields ECS cannot home land at
  `car.<object>.<field>` with a declared type. **Nothing homeless is dropped.**
- **Rules** the object files rely on: `one_home`, `fallback` (explicit
  precedence when two CAR fields share an ECS target), `coercion` (an
  unparseable value for a typed ECS field is kept verbatim under `car.*`),
  `verbatim` (only ECS-demanded normalisations, each called out on its entry),
  `nulls`, `event_action`.
- The **data-stream shape** (`logs-car.<object>-<namespace>`, the constants
  stamped on every document, a recommended deterministic `_id`) and the default
  `event.category` per object.

### `objects/<object>.yml`

```yaml
object: process
data_stream: logs-car.process-*
event_defaults:
  category: [process]              # ECS event.category for the object
  type_by_action: {create: [start], terminate: [end], ...}   # every car_action, no more
fields:
  - car: command_line              # a CAR object_field (must exist in model/car/objects/process.yml)
    ecs: process.command_line      # its ONE primary ECS home ...
    also: [related.user]           # ... plus optional unconditional copies
  - car: uid
    ecs: user.id
    fallback: true                 # shares user.id with `sid`: fills it only when sid is null
  - car: integrity_level
    native: true                   # ECS has no honest home -> car.process.integrity_level
    type: keyword                  # its mapping type there
    rationale: ECS has no process integrity-level field ...
```

An entry is **mapped** (`ecs:`) or **native** (`native: true` + `rationale` +
`type`) — never both, never neither. `derived:` entries name ECS fields the
loader builds from CAR data that is not a field of its own (e.g.
`http.request.method` from `car_action`).

### Namespace decisions, per object

| object | ECS home | native (`car.<object>.*`) |
|---|---|---|
| authentication | `user.*` = the account **being authenticated**, `source.user.*` = the initiating account, `related.user`, `event.outcome`, `source.domain`, `destination.domain` | `method`, `user_type`, `target_user_type` |
| driver | `file.*` (the driver image; ECS has no driver object), `file.code_signature.*`, `process.pid` | `base_address` |
| email | `email.*` (sender = envelope, from = header, to = envelope recipient), `source/destination.*` | `dest`-vs-`to` overflow, `server_relay`, `message_links`, `src_domain`, `message_body` |
| file | `file.*`, `file.hash.*` (the file's own hash), `process.*` (the acting process) | `previous_creation_time`, `content` |
| flow | `network.*`, `source.*` (initiator), `destination.*` (responder), `event.start/end`, `process.*` | `content`, `proto_info`, `tcp_flags` |
| http | `url.*`, `http.*`, `user_agent.*`, `source.ip` | — |
| module | `dll.*` (+ `file.*` copies, as Elastic's Sysmon 7 does), `process.*` | `base_address` |
| process | `process.*`, `process.parent.*`, `process.hash.*`, `process.code_signature.*`, `user.*` | `integrity_level`, `access_level`, `call_trace`, `target_guid/pid/address/name` (ECS has no target-process block) |
| registry | `registry.*` (key verbatim; hive abbreviated per ECS), `process.*` | `new_content` |
| service | `service.name`, `process.*`, `user.*`; Windows-service specifics arrive via `car.native` | — |
| socket | `source.*` = local end, `destination.*` = remote end, `network.transport/type`, `event.outcome` | — |
| thread | `process.*` = the **acting** process/thread, `dll.*` for the start module | `tgt_pid`, `tgt_tid`, every stack/start address, `start_function` |
| user_session | `user.*`, `related.user`, `source/destination.*`, `event.outcome` | `login_id` (the LUID join key), `login_type` |

Recording where ECS *lacks* a field is the point of a hand-authored contract:
a bad mapping is worse than an honest `native`.

## Validating

```sh
python model/projection/validate.py      # exit 1 + a problem list on drift; one-line summary on success
pytest -q model/projection               # the same, as a test
```

`validate.py` asserts: every CAR object has a file and there is no orphan
file; every `object_field` has exactly one entry and no entry names a field the
object does not have; every common-header field is projected; `ecs:` paths are
ECS-shaped (a known ECS 8.x top-level field set — `car.*` homes must be
`native: true`, never an `ecs:` path); shared targets declare `fallback: true`;
`event_defaults` cover every `car_action` and only those; `derived:` sources
exist.

## Changing it

- **A CAR model refresh** (submodule-pin bump + `python model/generate.py`)
  that adds or renames a field makes `validate.py` fail until the new field has
  a decision here. That is the intended coupling.
- **A mapping decision** changes in `objects/<object>.yml` (or, for the header,
  `conventions.yml`); bump `contract.version` in `conventions.yml` when a target
  field *path* changes — the loader and any rule written against the old path
  need to know.
- Do not add a `car.*` path as an `ecs:` target; mark the field `native: true`
  and let the namespace rule place it.

## What this is not

- Not runtime code: no loader, no index templates, no ingest pipeline. Those
  are built in DX_DFIR *from* this contract.
- Not the Sigma/detection layer: rules are authored against the ECS fields this
  contract produces (and the `car-detections` lookup joins on `event.id`), in a
  later phase.
- Not a replacement for the existing JSONL/Kusto export (`store.export_jsonl()`)
  — this is additive until decision D1 retires ADX.
