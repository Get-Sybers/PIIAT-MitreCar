# Cross-source correlation — the opt-in end-stage

*Status: **built**, opt-in, default off.* Module: `piiat_mitrecar/crosssource.py`;
tests: `tests/test_crosssource.py`. Companion docs: [Architecture.md](Architecture.md)
(the isolation rule), [CAR-Pipeline.md](CAR-Pipeline.md) (the per-source
recipe), [CAR-Relations.md](CAR-Relations.md) (why cross-source joins are
heuristic).

## 1. What it is — and what it is not

The per-source product does not change. Every evidence source is still
normalised and enriched **on its own** into its own `car.db` + `superset.db`;
no source depends on another being present, and nothing is mixed. That rule
is what makes each store reproducible and trustworthy.

Cross-source correlation is the **separate, optional end-stage over the
aggregate** those docs promised: it runs *after* every source is finished,
reads the per-source stores **read-only**, and writes a **combined** store of
its own. It never enriches a source with another source's data, never writes
into a per-source store, and never runs unless asked:

```
python -m piiat_mitrecar.crosssource <tree> [--out DIR]     # a tree of per-source car dirs
python -m piiat_mitrecar --batch <processed_dir> --derive --crosssource   # after the batch
```

`<tree>` is any directory holding per-source car directories (each a `car.db`
[+ `superset.db`]) — typically the `--batch` output root, where the directory
name *is* the batch source name (`windows_logs_hostA`, `zeek_cap1`,
`memory_img1`, …). Output: `<tree>/crosssource/crosssource.db` +
`car_crosssource.jsonl` (or `--out DIR`). Re-running rebuilds the aggregate
from the per-source stores.

## 2. What it correlates on

Only the **content-keyed strong identities** the per-source derived pass
already extracts (`relationships.yml` `derived.identities`, kind `content`):

| identity | node | the same … | method |
|---|---|---|---|
| `hash` (`sha256:<hex>`, `sha1:`, `md5:`) | `file_content` | bytes | `cross_source_hash` |
| `sid` (`sid:S-1-5-21-…` / `S-1-12-1-…`) | `user_account` | real account (well-known SIDs identify no account and are excluded upstream) | `cross_source_sid` |

These are the identities that mean the same thing in *every* source: a hash is
the same bytes whether Sysmon, Zeek `files.log`, a Plaso PE record or a memory
image reports it; a real SID is the same account across a host's event logs,
its disk image and its memory image. Sensor-minted instance identities (a
Sysmon `ProcessGuid`, a Zeek `uid`, a memory offset) are **not** joined across
sources — they only mean something inside the source that minted them.

The per-source content layer is read from `superset.db` where the source was
built with `--derive`. A source built without it has no content layer stored;
the stage then derives one **in memory** from its `car.db` by the same
per-source rules (`derive.content_entities`) — read-only, nothing written back
(`content_layer` in the summary and the `source` table says which).

## 3. The union — one entity per identity, additive

Content nodes are deterministic by content (`sha256:<hex>` is the same
`node_id` in every source), so the aggregate simply **unions by `node_id`**:

- `properties` — every value any source supplied, unioned (a hash's paths on
  host A *and* host B; an account's user names); nothing is dropped;
- `ref_count` summed; `first_seen` / `last_seen` widened across sources;
- `identity_key` — the first contributor's (by source name); each source's own
  key, counts, seen-window and hosts stay legible under **`per_source`**;
- **`sources`** — every contributing source, and `source_count`.

Every `entity_ref` (record → node, with the record's field as its role) is
carried over with its **`source`** added.

## 4. The cross-source derived relationship

Where an entity has **two or more** sources, the stage emits **one edge per
(entity, unordered source pair)**:

| column | value |
|---|---|
| `class` | `derived` (the D4 data-driven class) |
| `relationship` | `corroborated` — *the entity as seen in source A corroborated the entity as seen in source B* |
| `source_object` / `target_object` | the node kind (`file_content` / `user_account`) |
| `source_guid` / `target_guid` | the `node_id` (both ends: the same entity, on either side of the boundary) |
| `method` | `cross_source_hash` / `cross_source_sid` |
| `identity_key` | the identity family (`hash` / `sid`) |
| `confidence` | **`heuristic`** — always |
| `corroborated_by` | the guids of the records on **both** sides (up to 64 per side) |
| `corroboration` | per source: the exact record count and the hosts |
| `timestamp` | the instant **both** sources had seen the entity (the later `first_seen`) |
| `source_host` | the source-end's host (both hosts are in `corroboration`) |
| `sources` / `source_boundary` | `[A, B]` / `{"source": A, "target": B}` |

Why one edge per entity and pair, not one per record pair: the per-source
engine's rule is that a derived link is **1:1** and an ambiguous many-to-many
stays on the content node. A SID is referenced by hundreds of records per
source; a record-to-record cross product would be huge and would assert
nothing a record pair actually shares. The entity-level edge is bounded
(entities × pairs), and the record detail is on the entity's refs.

Why `heuristic`, never `definitive`: a shared hash proves the same *bytes*,
not that the file on host B's disk is the instance that ran in host A's
memory; a shared SID proves the same *account*, which a domain account
legitimately has on many hosts; and two evidence sets can carry the same
`source_host` label for different machines or cases. The edge says *these
sources corroborate the same entity* — the analyst decides what that means.

Why `corroborated` is not an ATT&CK verb: the per-source relationship verbs
are held to the ATT&CK data-source vocabulary because they say what one data
element *did* to another. A cross-source edge asserts a shared identity across
evidence sets — a correlation, not an action. The verb is defined once, in
`crosssource.py`, and appears only in the cross-source store and stream.

## 5. The source boundary — stored on every object

`source_host` is not a boundary: several evidence sets describe one host (its
event logs, its disk image, its memory image), and different cases or machines
may carry the same host label over time. So every cross-source row carries the
contributing **source names** — the per-source store's path under the tree:

- `content_node.sources` (+ `source_count`, `per_source`),
- `entity_ref.source`,
- `relationship.sources` + `source_boundary` (which end is which),
- and a `source` registry table (name, path, content-layer origin, hosts,
  counts).

A consumer can always answer *which evidence sets say this* without going
back to the per-source stores.

## 6. Outputs

`crosssource.db` — tables `source`, `content_node`, `entity_ref`,
`relationship`. The node / ref / relationship columns are those of the
per-source `superset.db` tables (same names, same meaning) plus the boundary
columns above, so a consumer of `car_relationships.jsonl` reads a cross-source
edge with no new vocabulary beyond `sources`, `source_boundary`,
`corroboration`.

`car_crosssource.jsonl` — every unified entity (`type: content_node`, all of
them, `source_count` tells which are cross-source) followed by every
cross-source relationship (`type: relationship`), each line carrying its
`sources`. It is destined for **its own stream, `logs-car.crosssource-*`** —
never a `car_<object>` table and never mixed into a per-source
`car_relationships.jsonl`. Entity refs stay in the store (they are the
per-record join, potentially one row per record).

## 7. Limits

- Nodes stay **per algorithm** (`sha256:` and `md5:` of the same bytes are two
  nodes, as per source); a consumer unions the nodes one record co-references,
  as the STIX projection does.
- No typed cross-object verbs (no cross-source *process --executed--> file*),
  no reconstruction, no inheritance across sources: nothing flows back into a
  per-source store, and nothing is asserted beyond *same entity, these sources*.
- The stage is only as good as the per-source content layer: a source whose
  maps extract no hash / SID contributes no entities.
