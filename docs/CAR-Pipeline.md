# The DX_DFIR CAR pipeline — how it works

*Epic: [Get-Sybers/DX_DFIR#86](https://github.com/Get-Sybers/DX_DFIR/issues/86).
Companion docs: `CAR-Relations.md` (per-object identity/join/inheritance/limit
rules) and `car_data_model.json` (the authoritative MITRE model).*

## 1. What it is

`piiat_mitrecar` turns each ingested evidence **source** into finished
**MITRE CAR** — every extractable record becomes a CAR **object** performing an
**action** at a **timestamp**, carrying that object's canonical **properties** —
and emits it as **JSON** for ADX to ingest as `mitre.car_*` tables.

The design is deliberately small and **repeatable**. One recipe, run per source:

```
input source ──▶ artefact map(s) ──▶ normalize ──▶ its own car.db ──▶ enrich
   (a file        (object/action/      (raw row →     (SQLite, one     (self-
    or a dir)      property rules)      CAR event)     table/object)    contained)
                                                                          │
                                                        JSON out ◀────────┘
                                                   car_<object>.jsonl → ADX
```

It is the pipeline-wide application of what shipped in **PIIAT-Mem v1.0.0** for
memory: the mapping/inference logic lives in the processor we own, the store is
finished CAR, and the query layer just reads the model instead of re-deriving it.

## 2. The isolation rule — one source, one database

**Each evidence source gets its OWN `car.db`, enriched only within itself.** A
source is a coherent evidence set:

| source | what counts as "the source" |
|---|---|
| Windows event logs (a host) | all `*_EvtxECmd_Output.json` for that host, OR the host's Plaso `winevtx` output |
| Zeek | one capture's per-protocol logs (`conn.json`, `http.json`, …) together |
| log2timeline | one image's `.jsonl` (a container of many parsers, split internally) |
| memory | PIIAT-Mem's finished `car.db` (passed through 1:1) |

No source ever depends on another being present, and nothing is mixed.
Cross-source ("final") enrichment is a **separate, optional end-stage** over the
aggregate — never part of the per-source product (see §9, still to build).

Run it:

```
python -m piiat_mitrecar --in <file-or-dir> --out <dir> [--host NAME] [--artefacts k1,k2]
# → <dir>/car.db  +  <dir>/car_<object>.jsonl   (one JSONL per populated object)
```

## 3. Components (`piiat_mitrecar/`)

| module | role |
|---|---|
| `carmodel.py` | loads repo-root `car_data_model.json` — the single source of truth for objects/actions/fields |
| `mappings/` | per-artefact declarative maps (one file per family; auto-discovered) |
| `normalize.py` | the marker engine: `normalize(artefact, record) → CAR event`, or `None` if unmapped |
| `adapters/winevt.py` | Plaso winevt(x) record → EvtxECmd shape, so the evtx maps run unchanged |
| `adapters/l2t_split.py` | a raw log2timeline json_line container → per-parser wrapped tables (`SourceImage`, `RecordId`, `Timestamp`, `Parser`, `Record`) |
| `ids.py` | the one id recipe — canonical JSON + the namespaces (`STIX_NS`, `CAR_NS`, `SPINDLE_NS`) — shared by the STIX projection and the spindle row guid |
| `enrich.py` | the relationship + inheritance cascade (identity, joins, inheritance, dedupe, canonical accounts) |
| `store.py` | the per-object SQLite CAR store + `export_jsonl()` (the ADX contract) |
| `sources.py` | source readers: `iter_mapped()` (raw → normalize) and `load_piiat_car()` (memory passthrough) |
| `pipeline.py` | orchestration: route source → normalize → enrich (self-contained) → store → JSON |

## 4. The CAR data model (13 objects)

`car_data_model.json` is a **verified exact match** to `car.mitre.org` — every
object, action, and field (diffed 13/13, 0 missing, 0 extra). The 13 objects:
authentication, driver, email, file, flow, http, module, process, registry,
service, socket, thread, user_session.

The store keeps **one table per object**. Each row = one CAR event: a minimal
header (`timestamp, car_action, guid, owning_guid, link_confidence,
source_artefact, source_host, native`) + that object's MITRE fields. Header
columns beyond MITRE are the deliberate, labelled additions a materialized
multi-source store needs; `parent_guid` is a process-only column (MITRE defines
it only there); `owning_guid` is the one non-MITRE field we add — the definitive
spoke→process link. `native` (JSON) holds evidence with no CAR home — never
faked into a canonical column.

## 5. Artefact coverage (source → CAR objects)

| artefact | map(s) | CAR objects filled |
|---|---|---|
| **Windows event logs** (EvtxECmd *and* Plaso winevtx — same maps) | `evtx_security`, `evtx_security_sessions`, `evtx_process`, `evtx_services`, `evtx_bits`, `evtx_rdp`, `evtx_sysmon` | authentication, user_session, process, service, http (BITS), module, driver, thread, registry, file, flow (Sysmon) |
| **Zeek** | `zeek_conn`, `zeek_http`, `zeek_smtp`, `zeek_files` | flow, http, email, file |
| **Plaso execution** | `plaso_exec_prefetch/winreg/cron` | process |
| **Plaso filesystem + Linux** | `l2t_filestat/mft/usnjrnl/utmp/utmpx/text` | file, user_session |
| **Memory** (PIIAT-Mem) | passthrough | all 10 memory objects (finished CAR) |

Windows event-log EventIds covered: 4624/4625/4634/4647/4672/4688 (Security),
7045/4697 (service), BITS 59/60, TerminalServices 21/24/25, Sysmon
1/3/5/6/7/8/11/12/13/23. **The same maps serve both EvtxECmd and log2timeline** —
a Plaso record is adapted to the EvtxECmd shape and run through the identical
maps (verified: Plaso-parsed LoneWolf → byte-identical CAR to the EvtxECmd run,
including definitive Sysmon ProcessGuid links).

Honest non-coverage: `email` has no live source yet (the only smtp capture is
STARTTLS-encrypted); Zeek dns/ssl/x509/dhcp/ntp/snmp/ocsp/weird/pe have no
dedicated CAR object (flow-detail, routed to `[]` explicitly); SRUM/RECmd is
**parked** pending real Velociraptor/EZ output.

## 6. The mapping engine

A map declares, per artefact (and per *variant* where one artefact splits across
objects): the CAR `object`, `action`, `ts`, the identity that becomes `guid`,
`props` (CAR field → source), `keep`/`native_extract` (native evidence + join
keys), and a `host` (the enrich scope). **Markers** do the small transforms and
nest freely: `first`, `const`, `basename`, `ext`, `lower`, `regex1`,
`domain_of`, `epoch_ts`, `map_value`, `concat`, `exe_path`, `hex_int`, `at`
(positional), `payload`/`userdata` (EvtxECmd shapes), `host_label`, `ts_before`
(two timestamps compared as instants — a verdict the evidence proves).

**Extract maximally; never fake.** Map any record that carries a valid CAR
object/action/property; a canonical field with no honest source is left null
(not a near-miss); a record with no valid CAR action stays raw (e.g. 7040 — the
service object has no `modify` action). Companion events are mapped as their own
entries (e.g. 4672 → authentication with `user_role=administrator`); the cascade
sorts out how they relate.

## 7. The enrichment cascade (`enrich.py`)

Runs once over the whole (per-source) store — data enriching itself, PIIAT-Mem
style. All joins are **scoped per evidence host**, never across hosts.

- **Identity.** `guid` is the reuse-proof identity (memory: the `_EPROCESS`
  offset; Sysmon: `ProcessGuid`; event-record events: `<host>-<channel>-<recordid>`;
  disk-image rows: the minted **spindle id** — see §7.1).
- **Owner links, two tiers.** A spoke resolves its owning process: **definitive**
  when it natively carries the owner's guid (Sysmon `ProcessGuid`); else
  **heuristic** by the `(pid, create-time window)` join — the latest process
  created at-or-before the event (a later process can't own an earlier event).
  Marked in `link_confidence`.
- **Parent links.** `ParentProcessGuid` (definitive) → `ppid`-window (heuristic).
- **The LUID cascade.** Authentication ↔ user_session join on `(host, LUID)`;
  definitive except the per-boot well-known LUIDs; a *failed* auth never opens a
  session.
- **Inheritance fills only nulls** — a spoke inherits owner context for fields
  its object has; a natively-extracted value is never overwritten.
- **Fold (dedupe)** on `(host, object, guid, action, target_guid, access_level)`
  — rows that are the same event fold into **one**, additively by default
  (`relationships.yml dedupe.fold`): every property any row supplied, a
  disagreeing value kept in `native.coalesced_conflicts`, the contributors
  counted in `native.contributions` / `native.contributed_by`
  (`{source_artefact, spindle_ref}`); `most_populated` keeps one row instead.
  Identity-less rows never fold.
- **Canonical accounts** — well-known SIDs render the same everywhere, without
  overwriting real evidence (e.g. a machine account).

The full per-object identity/join/inheritance/**limit** rules — and the MITRE
wording that grounds each — are in `CAR-Relations.md`.

### 7.1 Row identity on disk-image sources — the spindle id

A Plaso/l2t record carries no sensor-minted id, so its rows used to have
`guid = None` — and a guid-less row can neither dedupe, relate (a `superset`
edge needs a guid on both ends; `derive` links skip it) nor export to STIX as
anything but a positional observation. Every such row now gets a **spindle
id**, minted exactly the way `stix.py` mints a STIX 2.1 §2.9 id — `ids.py` is
the one shared recipe:

```
guid       = uuid5(SPINDLE_NS, canonical_json({"_obj": <object>, "_v": <version>, <name>: <value>, …}))
SPINDLE_NS = uuid5(CAR_NS, "spindle")
```

The identity **key** is the CAR object, the registry entry's identity-key
**version** (`_v` — bumped whenever what identifies an artefact's row
changes, which re-mints every guid of that entry) and the record's own
stable-identity fields **keyed by name**: the names give domain separation (a
`file_reference` and a `usn` with the same value never collide, nor do two
objects), and values contribute as strings (a parser that emits `843` and one
that emits `"843"` agree; a field may declare `normalize: json` for a
type-faithful rendering — none does in v1). `ids.mint(object, identity,
version)` is the one seam that builds the key and the guid; `ids.guid_of(key)`
re-mints a row's own key. The source, parser and artefact **name are never
hashed** — that is what must stay invariant so two tools parsing the same
image mint the same guid for the same record. The readable key rides in `native.spindle_key`;
`native.spindle_scope` says how far the identity holds (`intrinsic`:
intrinsic to the artefact, valid across tools, runs and sources;
`positional`: the per-record fallback, see below).

**Which** fields identify each artefact's row is a rule, not code — declared as
data in `piiat_mitrecar/spindle.yml` (the registry: per entry the CAR object,
the ordered identity as `name ← source path on the normalized event` — a CAR
field's canonical value, `timestamp`, `owning_pid`, or `native.<key>`, the
path convention `relationships.yml` already uses — and the scope). A map only
names its entry (`"guid": _common.spindle("l2t_mft")`) and never spells
fields, so registry and maps cannot drift: `spindle.verify_registry()` holds
registry ↔ maps ↔ engine in step, `model/spindle/identity.yml` is the resolved
snapshot and `model/spindle/record.yml` the spindle's shape (both
`python model/generate.py`; `python -m piiat_mitrecar.spindle --check` in CI).
The registry today:

| map | object | identity (`native.spindle_key`) |
|---|---|---|
| `l2t_mft` | file | `file_reference`, `event_time` |
| `l2t_usnjrnl` | file | `usn`, `file_reference` |
| `l2t_filestat` | file | `file_path`, `event_time` |
| `l2t_lnk` | file | `lnk_file`, `file_path`, `event_time` |
| `l2t_recyclebin` | file | `artefact_file`, `file_path`, `event_time` |
| `plaso_shellitem` | file | `origin`, `file_path`, `event_time` |
| `plaso_fseventsd` | file | `event_identifier`, `file_path` |
| `plaso_pecoff` | file | `file_path`, `sha256` — time-free: every PE stamp is internal to the binary, so one PE's header / table / placeholder rows share the identity |
| `plaso_olecf` | file | `file_path`, `event_time` |
| `plaso_exec_prefetch` | process | `exe`, `prefetch_hash`, `run_time` |
| `plaso_exec_winreg` amcache | process | `image_path`, `recorded_time` (the key-write / MAC stamp — never a run time) |
| `plaso_exec_winreg` amcache Link Time | file | `file_path`, `sha1` — time-free: the compile stamp is not an event |
| `plaso_exec_winreg` userassist | process | `key_path`, `value_name`, `event_time` |
| `plaso_exec_winreg` bam | process | `key_path`, `image_path`, `event_time` |
| `plaso_exec_winreg` appcompatcache | process | `image_path`, `recorded_time` (the cached file's mtime; the per-ControlSet copies collapse) |
| `plaso_exec_cron` | process | `command`, `pid`, `event_time` |
| `plaso_registry` | registry | `hive`, `key_path`, `last_write` |
| `l2t_msiecf` / `l2t_firefox_cache` / `l2t_firefox_places` / `l2t_javaidx` | http | `db_path`, `url`, `visit_time` |
| `l2t_srum` network_usage | flow | `application`, `user_identifier`, `interface_luid`, `recorded_time` |
| `l2t_srum` application_usage | process | `application`, `user_identifier`, `recorded_time` |
| `l2t_utmp` / `l2t_utmpx` | user_session | `pid`, `terminal`, `event_time` |
| `l2t_text` (sshd login) | user_session | `pid`, `user`, `event_time` |

`event_time` (and its per-artefact names `last_write` / `visit_time` /
`run_time` / `recorded_time`) is the row's own CAR timestamp (the `timestamp`
source); `recorded_time` marks a stamp whose meaning is inferred (a shimcache
mtime, an amcache key write — labelled natively by `time_meaning` /
`execution_inferred`), never an asserted run time. A row that asserts no
event at all (a PE's compile stamp, an amcache Link Time) is an **entity**
record: its identity is the artefact's entity key with no time, so rows that
differ only in native stamps share it. Where an entity has several same-action events (a
prefetch's eight last-run times, a key's successive snapshots, an $MFT entry's
$SI and $FN times) the time is part of what identifies the event — so distinct
events never collapse, and true duplicates (the same record parsed twice) do.

**Positional fallback.** `adapters/l2t_split.py` stamps every wrapped row with
`RecordId` — its physical line in the container, minted from the input like
the EVTX record id (stable across re-splits of the same json_line file, not
across a re-run of the parser). A row whose intrinsic identity is incomplete
(a blank component) falls back to `{"_obj", "SourceImage", "RecordId"}` and is
flagged `native.spindle_scope = "positional"`: deterministic, but valid only
inside this source, so a cross-source pass must skip it. Every minted row —
intrinsic or positional — also carries `native.spindle_ref`
(`{SourceImage, RecordId}`): where the record came from, **outside** the key.

Sysmon (`ProcessGuid`) and event-record (`<host>-<channel>-<recordid>`) guids —
including the Plaso `winevtx` route through the evtx maps — are left exactly as
they were: they are already stable cross-tool keys and are never wrapped in
uuid5. The shapes not yet confirmed against a multi-tool corpus (cross-tool
renderings of `file_reference`, timestamps, `db_path`, `prefetch_hash`; the
registry value-level component) are recorded in
`to-be-validated/spindle_identity.yml`.

## 8. Output contract (JSON → ADX)

`store.export_jsonl()` writes one `car_<object>.jsonl` per populated object; each
line is a flat CAR event (`native` as a JSON object for a dynamic column). ADX
ingests these as **new `mitre.car_*` tables**, additive — the existing raw tables
(`host.EvtxEcmdJson`, `memory.VolatilityJson`, `network.ZeekConn`, …) are
untouched. This is the "minimise changing what's built" contract: add CAR
tables + repoint the public `Car<Object>()` functions at them.

## 9. What is NOT done yet

See epic #86 for the tracked, detailed plan. In short: the CAR stage is
**standalone** (not yet wired into the ingest lane/CLI); the **ADX
materialization** (car_* tables + mappings, and collapsing the 1056-line
query-time `40-mitre.kql` to read them) is not built; **cross-source final
enrichment** is deferred behind a capability-determination + data-assessment
pass; **SRUM/RECmd** is parked pending real output; and a **payload-parse cache**
is a known perf item.
