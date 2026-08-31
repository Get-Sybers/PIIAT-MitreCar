# Optional Azul-style Logstash/Kafka/OpenSearch path for PIIAT-MitreCar

Generated from repository code/docs and public project docs on 2026-08-31.

## Executive summary

- **Yes, the current `car.db` + `superset.db` housing can be replaced, but not by configuration alone.** In `PIIAT-MitreCar`, `car.db` is the per-source CAR event store and `superset.db` is the per-source relationship/materialization store; both are rebuilt on every run, exported as JSONL, and then read back by the timeline builder. Replacing them means reworking the storage contract in [`README.md`](../../../README.md), [`docs/Architecture.md`](../../Architecture.md), [`docs/CAR-Pipeline.md`](../../CAR-Pipeline.md), [`piiat_mitrecar/store.py`](../../../piiat_mitrecar/store.py), [`piiat_mitrecar/superset.py`](../../../piiat_mitrecar/superset.py), [`piiat_mitrecar/pipeline.py`](../../../piiat_mitrecar/pipeline.py), and [`piiat_mitrecar/timeline.py`](../../../piiat_mitrecar/timeline.py).
- **DX_DFIR already has downstream Elastic-style infrastructure, but not at the CAR-entry stage.** It ships a localhost-only SOF-ELK stack based on Filebeat + Logstash + Elasticsearch + Kibana in [`docker/sof-elk/docker-compose.yml`](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml), [`docker/sof-elk/Dockerfile`](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/Dockerfile), [`docker/sof-elk/filebeat.yml`](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/filebeat.yml), and [`docker/sof-elk/pipelines.yml`](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/pipelines.yml), but that path is for **raw/pre-CAR artefacts**, not finished `car_*.jsonl`. The current CAR ingest still targets ADX/Kusto through [`python/get_sybers_dfir/ingest/__init__.py`](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py) and [`kusto/schema/40-mitre.kql`](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql).
- **The least disruptive path is additive, not immediate removal.** First publish the already-exported CAR JSONL to a Logstash/Elasticsearch/OpenSearch path; only remove SQLite after the replacement also covers per-source rebuilds, idempotent ingest, relationship edges, and timeline reconstruction. That staged approach fits the current build contract in [`python/get_sybers_dfir/mitrecar.py`](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/mitrecar.py), [`python/get_sybers_dfir/cli.py`](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/cli.py), and [`docs/Get-Started.md`](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/Get-Started.md).
- **If the goal is to follow Azul’s infrastructure shape, Kafka + OpenSearch is plausible.** Azul’s public architecture documents Kafka, OpenSearch, S3-compatible object storage, REST APIs and Kubernetes as its data-plane components, so a Kafka/OpenSearch branch would be directionally consistent with Azul’s enrichment stack rather than with the current local SQLite packaging. ([Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md), [azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md))

## Current state: what the SQLite files are doing now

### `car.db`

`PIIAT-MitreCar` documents `car.db` as one of the two self-contained SQLite stores each source produces, and `store.py` implements it as one table per CAR object with a common header plus native evidence JSON. ([README](../../../README.md), [Architecture](../../Architecture.md), [CAR pipeline](../../CAR-Pipeline.md), [store.py](../../../piiat_mitrecar/store.py))

The important point for replacement work is that `car.db` is not just “some database”. It currently provides all of these functions:

1. **Per-source object materialization**: `CarStore._create()` creates one SQLite table per CAR object and indexes by `guid` and `timestamp`. ([store.py](../../../piiat_mitrecar/store.py))
2. **Post-enrichment persistence**: `pipeline.py` runs `enrich.enrich(events)` over the full in-memory event set, then writes the finished events into `car.db`. ([pipeline.py](../../../piiat_mitrecar/pipeline.py))
3. **Per-object export contract**: `CarStore.export_jsonl()` writes one `car_<object>.jsonl` file per populated object. That JSONL is the downstream ingest contract used today. ([store.py](../../../piiat_mitrecar/store.py), [Kusto schema](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
4. **Timeline input**: `timeline.py` reads `car.db` directly with `sqlite3` when building `timeline.jsonl`. ([timeline.py](../../../piiat_mitrecar/timeline.py))

### `superset.db`

`superset.db` is the second per-source store and is not optional in the present design. The repo docs describe it as the CAR+ATT&CK superset/reference model plus the relationship-instance timeline, and `superset.py` implements that with `model_object`, `relationship_type`, and `relationship` tables. ([README](../../../README.md), [Architecture](../../Architecture.md), [superset.py](../../../piiat_mitrecar/superset.py))

That means replacing `superset.db` also means replacing:

1. **Reference seeding** from `build_data_model.build_superset()`. ([superset.py](../../../piiat_mitrecar/superset.py))
2. **Relationship-instance materialization** from `edges_from_events()`, which produces the `source → relationship → target` edge timeline. ([superset.py](../../../piiat_mitrecar/superset.py), [tests/test_superset.py](../../../tests/test_superset.py), [cascade_relationships.yml](../../../piiat_mitrecar/cascade_relationships.yml))
3. **Relationship export** to `car_relationships.jsonl`. ([superset.py](../../../piiat_mitrecar/superset.py))
4. **Timeline input** for the edge side of `timeline.py`. ([timeline.py](../../../piiat_mitrecar/timeline.py))

## What DX_DFIR already has, and what it does not

DX_DFIR already contains two relevant backend directions:

- **ADX/Kusto**, where `dxdfir build-car` produces the CAR stores and `dxdfir ingest --only car` loads `car_*.jsonl` into `mitre.car_*` tables. ([Get Started](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/Get-Started.md), [mitrecar.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/mitrecar.py), [ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py), [40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
- **SOF-ELK/Elastic**, where Filebeat watches `/logstash/<type>/`, ships to Logstash, and Logstash writes to Elasticsearch/Kibana. ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml), [filebeat.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/filebeat.yml), [pipelines.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/pipelines.yml), [Dockerfile](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/Dockerfile))

What is **missing** for a CAR-stage replacement is just as important:

- there is **no Kafka broker** or Kafka-oriented compose service in DX_DFIR’s current stack; ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml))
- there is **no CAR-specific Logstash pipeline** that reads `car_*.jsonl` or `car_relationships.jsonl`; ([pipelines.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/pipelines.yml))
- there is **no OpenSearch deployment path** yet; the shipped image is Elasticsearch 9.4.3; ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml))
- there is **no Kafka producer** in `PIIAT-MitreCar`; `pyproject.toml` only depends on `pyyaml`; ([pyproject.toml](../../../pyproject.toml))
- `DX_DFIR`’s current CAR ingest path expects files on disk and an ADX ledger, not a streaming backend. ([ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py))

## What would need to be built in PIIAT-MitreCar

### 1. Add a backend abstraction, or replace the two store modules directly

Today, `pipeline.py` hard-codes `store.CarStore` and `superset.build_superset_db()`. A real replacement therefore needs either:

- a **storage abstraction** such as `CarStore`/`SupersetStore` implementations for `sqlite` and `elastic`, or
- a direct rewrite of `store.py` and `superset.py` so their current responsibilities target Kafka/OpenSearch instead of SQLite. ([pipeline.py](../../../piiat_mitrecar/pipeline.py), [store.py](../../../piiat_mitrecar/store.py), [superset.py](../../../piiat_mitrecar/superset.py))

Without that, Logstash/Kafka/OpenSearch would only be an additional sink, not a replacement.

### 2. Recreate the `car.db` responsibilities as documents/topics

To replace `car.db`, the repo would need a new persisted contract for every object row that `CarStore` writes now. The cleanest equivalent is:

- **13 object topics** in Kafka, one per CAR object (`car.process`, `car.file`, `car.flow`, etc.), because the current export is already split by object into `car_<object>.jsonl`; ([store.py](../../../piiat_mitrecar/store.py), [40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
- **13 object indices** in Elasticsearch/OpenSearch (`car-process`, `car-file`, `car-flow`, etc.), because the current Kusto materialization is also one table per object; ([40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
- **a stable document shape** containing the existing CAR header fields (`timestamp`, `car_action`, `guid`, `owning_guid`, `link_confidence`, `source_artefact`, `source_host`, `native`) plus the object’s canonical fields; ([store.py](../../../piiat_mitrecar/store.py))
- **a deterministic document id** so replay is idempotent, because today idempotence is partly achieved by deleting and rebuilding the local store and, downstream, by DX_DFIR’s ingest ledger. A practical `_id` would be derived from the source path + object + guid + action + timestamp. ([pipeline.py](../../../piiat_mitrecar/pipeline.py), [ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py))

### 3. Recreate the `superset.db` relationship timeline

To replace `superset.db`, the repo would need:

- **one relationship topic** such as `car.relationships`; ([superset.py](../../../piiat_mitrecar/superset.py))
- **one relationship index** such as `car-relationships`; ([superset.py](../../../piiat_mitrecar/superset.py))
- **a document schema** matching the existing exported edge rows: `timestamp`, `source_host`, `relationship`, `source_object`, `source_guid`, `target_object`, `target_guid`, `confidence`, `method`; ([superset.py](../../../piiat_mitrecar/superset.py))
- **continued validation that emitted verbs stay in the ATT&CK relationship vocabulary**, because `tests/test_superset.py` currently enforces that contract. ([tests/test_superset.py](../../../tests/test_superset.py), [cascade_relationships.yml](../../../piiat_mitrecar/cascade_relationships.yml))

The `model_object` and `relationship_type` tables do **not** need to become searchable indices. Those are reference data already generated from pinned inputs and can remain static YAML/JSON shipped with the repo. ([Architecture](../../Architecture.md), [superset.py](../../../piiat_mitrecar/superset.py))

### 4. Replace the local timeline reader

`timeline.py` currently discovers store directories by looking for `car.db`, opens `car.db` and `superset.db` with `sqlite3`, and merges the rows into `timeline.jsonl`. If SQLite is actually removed, one of these has to be built:

1. a **new OpenSearch-backed timeline reader** that queries the object and relationship indices and merges them in timestamp order, or
2. a **JSONL-backed timeline reader** that reads `car_*.jsonl` and `car_relationships.jsonl` directly, preserving the current `--host`, `--after`, `--before`, `--objects-only`, and `--edges-only` behavior. ([timeline.py](../../../piiat_mitrecar/timeline.py))

This is the main reason an additive “publish to Elastic as well” phase is lower risk than immediate SQLite removal.

### 5. Add dependencies and CLI/configuration controls

Replacing or even augmenting SQLite with Kafka/OpenSearch requires new dependencies and runtime settings that do not exist today:

- a Python Kafka client such as `kafka-python` or `confluent-kafka`; ([pyproject.toml](../../../pyproject.toml))
- CLI flags or environment variables for broker/bootstrap servers, topic prefix, and mode selection in `pipeline.py`; ([pipeline.py](../../../piiat_mitrecar/pipeline.py))
- tests for the new backend shape, parallel to the existing `store.py`/`superset.py` expectations. ([tests/test_superset.py](../../../tests/test_superset.py))

## What would need to be built in DX_DFIR

### 1. Add a new backend path to the CLI/orchestration

`dxdfir process` only knows `adx` and `sofelk` as pipeline choices, and `dxdfir ingest` is explicitly the ADX ingest role. To make OpenSearch/Kafka a first-class path, DX_DFIR would need:

- a new CLI/backend option such as `--pipeline opensearch` or a widened `sofelk` mode that explicitly includes CAR outputs; ([cli.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/cli.py))
- a deploy role/playbook parallel to the current ADX and SOF-ELK flows; ([cli.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/cli.py), [Get Started](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/Get-Started.md))
- documentation equivalent to `docs/Get-Started.md` and `docs/Kusto-Port.md` for the new backend contract. ([Get Started](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/Get-Started.md))

### 2. Either extend SOF-ELK, or build a new compose stack

DX_DFIR already builds and runs a local SOF-ELK image around Elasticsearch, Filebeat and Logstash. That means there are two practical implementation choices:

#### Option A: reuse the current file-based SOF-ELK delivery model first

This is the **smallest** DX_DFIR change:

- keep `PIIAT-MitreCar` exporting `car_*.jsonl` and `car_relationships.jsonl`; ([store.py](../../../piiat_mitrecar/store.py), [superset.py](../../../piiat_mitrecar/superset.py))
- add a **new Filebeat input** or watched path for CAR JSONL under the existing `/logstash/...` delivery model; ([filebeat.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/filebeat.yml))
- add a **new Logstash config** dedicated to CAR files instead of raw artefacts; ([pipelines.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/pipelines.yml), [Dockerfile](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/Dockerfile))
- add Elasticsearch/OpenSearch index templates for the CAR objects and relationships. ([40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))

This path replaces the downstream analytics store without forcing Kafka into the design on day one.

#### Option B: add Kafka and follow Azul’s architecture more closely

This is the **larger** change:

- add a Kafka broker and, if desired, ZooKeeper-less KRaft configuration to the DX_DFIR compose/deploy path because no Kafka service exists today; ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml))
- install the Logstash Kafka input plugin and configure a CAR pipeline that reads from Kafka topics and writes to Elasticsearch/OpenSearch; ([Dockerfile](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/Dockerfile), [Logstash Kafka input](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-kafka.html), [Logstash Elasticsearch output](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-elasticsearch.html))
- add producer wiring on the PIIAT side; otherwise Kafka has nothing to read. ([pyproject.toml](../../../pyproject.toml), [pipeline.py](../../../piiat_mitrecar/pipeline.py))

If Kafka is used, topic/partition design must preserve the existing per-source isolation expectations; Kafka only guarantees ordering within a partition, so the message key needs to keep one source/host’s timeline together where ordering matters. ([Kafka docs](https://kafka.apache.org/documentation/#intro_topics), [Architecture](../../Architecture.md), [CAR pipeline](../../CAR-Pipeline.md))

### 3. Replace or supplement the current CAR ingest harness

DX_DFIR’s current `run_car()` implementation:

- searches for `car_*.jsonl` under `data_store/processed/car`; 
- maps file names to `mitre.car_<object>` tables;
- stages files into the Kusto container;
- records sha1 hashes in `_DfirIngestLedger` for idempotence. ([ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py))

An Elasticsearch/OpenSearch replacement would need the same operational features:

1. **discovery/routing** of object vs relationship files or topics;
2. **idempotence**, either with deterministic `_id` values in Elasticsearch/OpenSearch or a separate ingest ledger index;
3. **batching/retry/error reporting** comparable to the current ingest summary;
4. **operator-visible CLI output** so `dxdfir ingest` or its replacement still reports what was loaded and what failed. ([ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py), [cli.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/cli.py))

### 4. Build index templates/mappings around the current CAR contract

DX_DFIR already tells us what the CAR document shape needs to be, because `40-mitre.kql` defines every current target column. That should drive the first OpenSearch/Elasticsearch index templates:

- one template per object index, mirroring the current `car_<object>` table fields; ([40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
- one template for `car-relationships`, mirroring the current relationship export fields; ([superset.py](../../../piiat_mitrecar/superset.py))
- `native` mapped as a JSON object/dynamic field, because it is already treated as structured JSON in the current stores and Kusto schema; ([store.py](../../../piiat_mitrecar/store.py), [40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
- “numeric-looking” CAR values such as pids and ports kept as strings/keywords unless there is a deliberate conversion policy, because the current Kusto schema explicitly keeps them as strings due to evidence inconsistency. ([40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))

OpenSearch’s own docs are the relevant reference for index templates and ingest pipelines if this backend is built. ([OpenSearch index templates](https://docs.opensearch.org/latest/im-plugin/index-templates/), [OpenSearch ingest pipelines](https://docs.opensearch.org/latest/ingest-pipelines/))

## Additional modifications required beyond “just change the store”

The big architectural catch is that replacing SQLite also changes several behavior contracts that are currently implicit:

### Per-source rebuild semantics

`pipeline.py` deletes and rebuilds `car.db` each run, and `superset.py` does the same for `superset.db`. In a document store, that behavior must be recreated explicitly, likely by:

- assigning a **run/source identifier** to every emitted document and deleting old documents for that source before re-indexing, or
- using deterministic `_id` values and a “replace whole source” workflow that clears the source partition/index slice first. ([pipeline.py](../../../piiat_mitrecar/pipeline.py), [superset.py](../../../piiat_mitrecar/superset.py))

### Source isolation

The repo’s architecture is explicit that enrichment is self-contained within a source and cross-source correlation is later. A shared Elasticsearch/OpenSearch cluster therefore needs a stored **source boundary** on every object and relationship document, not just `source_host`, because multiple cases or hosts may share a host label over time. ([Architecture](../../Architecture.md), [CAR pipeline](../../CAR-Pipeline.md))

### Relationship query ergonomics

The current relationship timeline is row-based and flat. To preserve easy process-tree and provenance pivots in Elasticsearch/OpenSearch, the relationship documents should remain standalone edge documents instead of being nested into object documents. That matches the current `car_relationships.jsonl` contract and avoids expensive nested updates. ([superset.py](../../../piiat_mitrecar/superset.py), [timeline.py](../../../piiat_mitrecar/timeline.py))

### Validation and regression testing

Even if the change is documentation-led today, an actual implementation would need at least:

- regression tests that exported CAR JSONL stays byte-compatible if the additive path is chosen;
- backend tests that relationship verbs and field names match the current schemas;
- end-to-end DX_DFIR tests proving `build-car` + new ingest/backend yields the same analyst-visible CAR content as the ADX path. ([CONTRIBUTING](../../../CONTRIBUTING.md), [tests/test_superset.py](../../../tests/test_superset.py), [Get Started](https://github.com/Get-Sybers/DX_DFIR/blob/main/docs/Get-Started.md))

## Recommended implementation order

1. **Start with file-based Elasticsearch/OpenSearch ingest for CAR JSONL.** That reuses the existing DX_DFIR SOF-ELK/Filebeat/Logstash shape and requires fewer moving parts than adding Kafka immediately. ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml), [filebeat.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/filebeat.yml))
2. **Keep SQLite during the first Elastic/OpenSearch phase.** This preserves `timeline.py`, preserves the current per-source rebuild behavior, and lets JSONL parity be checked against the ADX contract. ([timeline.py](../../../piiat_mitrecar/timeline.py), [40-mitre.kql](https://github.com/Get-Sybers/DX_DFIR/blob/main/kusto/schema/40-mitre.kql))
3. **Add Kafka only if Azul-style asynchronous decoupling is actually wanted.** Kafka becomes justified when the goal is buffered fan-out, multiple consumers, or deeper alignment with Azul’s service-oriented architecture, not merely because Logstash and Elasticsearch/OpenSearch exist. ([Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md), [Kafka docs](https://kafka.apache.org/documentation/#intro_topics))
4. **Remove SQLite only after replacing timeline and rebuild semantics.** Until those two behaviors are reimplemented, removing `car.db`/`superset.db` would delete capabilities the current repo actively uses. ([pipeline.py](../../../piiat_mitrecar/pipeline.py), [timeline.py](../../../piiat_mitrecar/timeline.py))

## Bottom line

If the objective is **“use the existing DX_DFIR Elastic-style stack for CAR output”**, that is realistic and mostly requires new CAR-specific Logstash/Filebeat/index-template work plus a new DX_DFIR backend path. ([docker-compose.yml](https://github.com/Get-Sybers/DX_DFIR/blob/main/docker/sof-elk/docker-compose.yml), [ingest/__init__.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/ingest/__init__.py))

If the objective is **“fully replace `car.db` and `superset.db` with a Kafka/OpenSearch backbone aligned to Azul’s architecture”**, that is a larger engineering change spanning both repositories: store abstraction or rewrite, new producer code, new topic/index schemas, new idempotence/rebuild handling, new timeline retrieval, new DX_DFIR deploy/ingest flows, and new operator docs. ([Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md), [store.py](../../../piiat_mitrecar/store.py), [superset.py](../../../piiat_mitrecar/superset.py), [cli.py](https://github.com/Get-Sybers/DX_DFIR/blob/main/python/get_sybers_dfir/cli.py))
