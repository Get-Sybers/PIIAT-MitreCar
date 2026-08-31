# Azul research for PIIAT-MitreCar

Generated from public Azul repositories and docs on 2026-08-31.

## Executive summary

- Azul is best understood as a **malware repository + plugin-driven analysis platform + clustering system**, not as a DFIR event-log normalizer. The public docs describe it as a malware knowledge base/repository for archiving, analytics and clustering, with historical reprocessing as plugin logic improves. ([azul README](https://github.com/AustralianCyberSecurityCentre/azul/blob/main/README.md), [Azul about](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md))
- For **adaptation into PIIAT-MitreCar**, the strongest reusable ideas are Azul's **source/origin metadata**, **normalized feature naming discipline**, **parent/child entity relationships**, and **API/client/plugin extension points**. These are useful for provenance and enrichment, but they do **not** replace PIIAT-MitreCar's CAR-first event/object mapping model. ([Azul about](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md))
- Azul appears more suitable as an **adjacent enrichment system** for malware/file artefacts discovered during an investigation than as the primary representation for Windows-native activity. Its public model is built around entities, features, info blobs, plugin results and binary relationships. ([Azul about](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [binary2](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/binary2.md), [runner structure](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/structure.md))
- Azul is promising for **contribution and integration** because the ecosystem is split into focused repositories (REST API, runner, client, plugins, docs, metastore), the docs say pull requests are welcome, and the main implementation repos publish explicit plugin and API extension mechanisms. ([Azul contributing](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/01-contributing.md), [azul-restapi-server README](https://github.com/AustralianCyberSecurityCentre/azul-restapi-server/blob/main/README.md), [azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md))
- Azul's **storage stack should not replace** PIIAT-MitreCar's current per-source SQLite outputs for the primary product shape, but it **could sit alongside them** as a central malware enrichment tier. PIIAT's current contract is self-contained per-source `car.db` + `superset.db`; Azul's architecture is a service stack around Kafka, OpenSearch, S3, REST API, OIDC and Kubernetes. ([PIIAT README](../../../README.md), [PIIAT Architecture](../../Architecture.md), [PIIAT CAR pipeline](../../CAR-Pipeline.md), [Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md), [azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md))
- Azul maintainers have explicitly said they are interested in **future STIX integration**, especially for knowledge sharing with external systems and robust testing with **OpenCTI**, but there is currently no public export path. That makes it sensible for PIIAT to keep any Azul bridge in a separate static mapping layer that can grow into STIX later. ([Issue #4 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/4#issuecomment-3949198963))

## What Azul offers

| Area | Finding | Why it matters to PIIAT-MitreCar | Sources |
|---|---|---|---|
| Core purpose | Azul is positioned as a malware repository/knowledge base for archiving, analytics and clustering, and explicitly says it is **not** a binary triage system. | Good fit for malware/sample enrichment; weak fit as a first-class event-log normalization layer. | [README](https://github.com/AustralianCyberSecurityCentre/azul/blob/main/README.md), [About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md) |
| Storage and scale | The docs say Azul is designed to store tens/hundreds of millions of samples, keeps files in S3-compatible storage, and uses OpenSearch plus Kafka in the reference architecture. | Useful if PIIAT later wants long-lived malware/sample enrichment at scale, but heavier than the current CAR timeline problem. | [README](https://github.com/AustralianCyberSecurityCentre/azul/blob/main/README.md), [About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [Architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md) |
| Integration surfaces | Azul exposes a web UI, a REST API, and a headless client. The client docs map CLI/API calls to endpoints for binaries, features, plugins, sources, security and statistics. | This makes Azul a plausible downstream or sidecar integration target for file/sample artefacts discovered by PIIAT. | [About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [azul-client README](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/README.md), [azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md) |
| Analysis model | Azul's runner framework is plugin-oriented: plugins fetch jobs, process binaries/entities, emit features/info/data streams, and can create child entities with explicit relationships. | This is the most reusable design idea: separate extraction mechanics from normalized outputs and provenance edges. | [azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md), [runner structure](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/structure.md) |
| Normalization model | Azul normalizes around **features** (named values with types like string, integer, datetime, filepath, uri) and encourages cross-plugin reuse of feature names; richer structure can be retained in `info` JSON. | This is reusable for enrichment signals, but it is flatter and less semantically strict than CAR object/action mappings. | [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md) |
| Static schema assets | Azul publishes a large static file-type taxonomy in `identify.yaml` and a typed `BinaryEvent` Avro schema describing hashes, source, features, info and datastreams. | These are the strongest public candidates for direct reuse in YAML/STIX bridge work. | [identify.yaml](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/identify.yaml), [BinaryEvent schema](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/events/schemas/v6/1_binary.json), [event_binary.go](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/events/event_binary.go) |
| Provenance model | Azul tracks **source** and origin/reference metadata, and its result documents preserve source, submission and parent/link context rather than merging everything into one record. | This aligns strongly with PIIAT's need to preserve how evidence was supplied while still normalizing its interpretation. | [About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md), [binary2](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/binary2.md) |
| Relationship handling | Azul supports ancestor/descendant queries, parent-child links, and relationship labels on produced child entities. | This can inform how PIIAT records derivation/provenance edges around extracted artefacts without collapsing them into a single event row. | [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md), [azul-runner README example](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md) |
| Existing ATT&CK use | The public `azul-plugin-maco` example output includes ATT&CK technique IDs among extracted features. | ATT&CK-aligned enrichment already exists in Azul and could complement CAR timelines, but it is still plugin-derived malware metadata rather than native host activity evidence. | [azul-plugin-maco README](https://github.com/AustralianCyberSecurityCentre/azul-plugin-maco/blob/main/README.md) |
| Security / access | Azul integrates with OpenID Connect and documents user/security endpoints. | Relevant if PIIAT ever needs shared analyst-facing enrichment rather than only local pipeline outputs. | [About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [Architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md), [azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md) |

## Adaptation assessment for PIIAT-MitreCar

### Strong matches

1. **Preserve source context separately from normalized interpretation.** Azul explicitly tracks source/origin metadata and keeps submission/link/result context distinct; that maps well to the PIIAT premise that a Windows event should normalize the same way whether it arrived from Plaso or native EVTX, while the ingest wrapper preserves provenance. ([About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md))
2. **Reuse a naming discipline for enrichment values.** Azul's feature guidance pushes authors toward stable, cross-plugin names for equivalent facts; that same discipline is valuable for PIIAT when recording enrichment-only values that should not become primary CAR assertions. ([runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md))
3. **Model derivation edges explicitly.** Azul's child entities, parent links and ancestor/descendant queries are a practical precedent for representing "this artefact was extracted from / produced by / observed with" without overstating causality. ([azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md))
4. **Use Azul as enrichment for malware artefacts found in a case.** If a CAR timeline identifies dropped files, downloaded payloads or email attachments, Azul could store those binaries and return analyst pivots such as shared features, similar entities, extracted URLs and ATT&CK-tagged config data. ([azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md), [azul-plugin-maco README](https://github.com/AustralianCyberSecurityCentre/azul-plugin-maco/blob/main/README.md))

### Weak matches / limits

1. **Azul is file/sample-centric, not event-log-centric.** The public docs focus on binaries, entities, plugin results, features and malware clustering, so it is not a drop-in schema for CAR event/activity objects. ([About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md))
2. **The public model is flatter than CAR.** Azul's primary normalization unit is the feature name/value pair, with optional labels and `info` JSON, which is useful for pivots but weaker than explicit CAR object/action/property semantics for timeline reconstruction. ([runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md))
3. **Azul maintainers have publicly said the project is focused on binary-oriented rule engines such as Yara and Maco, and that the SIEM angle is not something Azul is looking to support.** That makes it a poor candidate for becoming PIIAT's canonical event-analysis layer. ([Issue #7 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/7#issuecomment-4570493888))
4. **There is no current public STIX export path.** A maintainer said ATT&CK/MBC features are indexed today, but STIX would need to be wrangled through the API or added in metastore/export logic. ([Issue #4 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/4#issuecomment-3949198963))

## Integration options

### Option A - use Azul as a downstream malware enrichment backend

Recommended use:

- Keep PIIAT-MitreCar as the authority for **CAR-normalized host/network activity**.
- When the pipeline encounters a file artefact worth deeper malware analysis, submit the binary to Azul with source references from the case, then attach returned Azul pivots back to the CAR timeline as enrichment, not as replacement evidence. Azul's API/client already supports binary upload, source metadata, child uploads, searching and metadata retrieval. ([azul-client README](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/README.md), [azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md))

Why this fits the current project premise:

- It keeps the "same Windows event regardless of ingress path" rule intact.
- It lets malware-specific outputs remain optional side knowledge.
- It supports your three stated goals by adding pivots and gap-filling hints around binaries without diluting primary CAR mappings. ([Issue #26](https://github.com/Get-Sybers/PIIAT-MitreCar/issues/26))

### Option B - borrow Azul's provenance and feature discipline, but not its schema

Recommended use:

- Reuse the *idea* of explicit source/result/link separation and cross-plugin naming discipline.
- Reuse public static assets where they genuinely help, especially Azul's `identify.yaml` taxonomy and typed `BinaryEvent` schema as references for enrichment adapters.
- Keep CAR object/action rows and cascade rules in repository-owned static data.
- Treat Azul-style "features" as a secondary enrichment namespace for uncertain, tool-specific or pivot-oriented facts. ([runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md), [binary2](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/binary2.md))

### Option C - do not try to make Azul the canonical timeline store

Reason:

- Azul's public design optimizes for malware samples, plugin outputs and clustering. PIIAT-MitreCar's core problem is evidence-to-CAR normalization with strict relationship/inheritance reasoning. Those are adjacent but different jobs. ([About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md), [docs/CAR-Relations.md](../../CAR-Relations.md))

## Could Azul infrastructure replace the current SQLite housing?

### Short answer

**Not cleanly for the current PIIAT product shape; yes as a sidecar/adjacent tier.**

### Why it is a poor direct replacement

PIIAT's current architecture intentionally emits **two self-contained SQLite stores per evidence source**: `car.db` for finished CAR object events and `superset.db` for relationship instances and reference data. The docs frame this as a repeatable per-source package, isolated from other sources and suitable for direct JSONL export. ([PIIAT README](../../../README.md), [PIIAT Architecture](../../Architecture.md), [PIIAT CAR pipeline](../../CAR-Pipeline.md))

Azul's enrichment-phase housing is fundamentally different:

- the reference architecture assumes **Kafka + OpenSearch + S3-compatible object storage + REST API + OIDC**, running in Kubernetes; ([Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md))
- metastore is built to **store binary files and plugin execution results**, then expose search/download/re-enqueue functions through REST; ([azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md))
- Azul's primary normalized unit is still a **binary/entity plus feature bag**, not a CAR event row; ([BinaryEvent schema](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/events/schemas/v6/1_binary.json), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md))
- the Azul team explicitly says **metastore is not recommended as a library**, which makes "swap out SQLite internals for Azul storage internals" a poor fit. ([azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md))

For PIIAT, replacing SQLite with Azul would therefore trade away:

- **source-local portability** (`car.db` / `superset.db` travel with the source);
- **simple relational/event-oriented storage** aligned to CAR objects and cascade edges;
- **offline repeatability** without standing up a distributed service stack.

### Where Azul can sit alongside SQLite

Azul fits better as an **optional centralized enrichment layer** that receives binaries, attachments or extracted artefacts referenced by PIIAT events while PIIAT keeps SQLite as the authoritative per-source timeline product.

Practical split:

- **SQLite remains authoritative** for normalized host/network activity, CAR relationships, and source-scoped enrichment.
- **Azul stores optional malware/sample enrichment** such as extracted ATT&CK tags, family names, config artefacts, YARA results, and similarity pivots.
- PIIAT keeps only the **relevant references back**: hash, source reference, selected enrichment features, and analyst leads.

This side-by-side model matches both systems' design centers instead of forcing one into the other's role. ([PIIAT Architecture](../../Architecture.md), [azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md), [azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md))

## Contribution assessment

| Contribution area | What public docs show | PIIAT-facing opportunity | Sources |
|---|---|---|---|
| New analysis plugins | Azul says plugins are the primary way new analytical techniques are added; `azul-runner` provides local and remote execution paths. | Contribute malware/config-extraction plugins if PIIAT finds recurring payload families in investigations. | [Azul contributing](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/01-contributing.md), [azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md) |
| API plugins | `azul-restapi-server` enables routes through installable plugins via the `azul_restapi.plugin` entry point. | Add PIIAT-specific read/export endpoints only if a shared Azul-backed analyst workflow becomes desirable. | [azul-restapi-server README](https://github.com/AustralianCyberSecurityCentre/azul-restapi-server/blob/main/README.md) |
| Docs / conventions | Azul's docs explicitly welcome bug reports, feature requests and pull requests, and ask for tests and documentation with new functionality. | A low-risk starting point if you later want to propose provenance or ATT&CK/CAR documentation improvements. | [Azul contributing](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/01-contributing.md) |
| Licensing | Azul is MIT-licensed overall, while the docs note that some plugins may use different licenses. | Compatible for reference/integration work, but each plugin repo should still be checked before adopting code. | [azul license](https://github.com/AustralianCyberSecurityCentre/azul/blob/main/license.md), [docs licence](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/licence.md) |
| Maintenance signals | The ecosystem has many actively updated component repos, the umbrella repo still has 2026 commits, and the implementation repos declare production/stable classifiers; the umbrella repo currently shows no GitHub releases. | Promising ecosystem, but maturity lives in the component repos more than the umbrella repository. | [azul commit example](https://github.com/AustralianCyberSecurityCentre/azul/commit/ccc7bfaf23f10856972d43b3d32f80bd43a17eb9), [azul releases](https://github.com/AustralianCyberSecurityCentre/azul/releases), [azul-runner pyproject](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/pyproject.toml), [azul-restapi-server pyproject](https://github.com/AustralianCyberSecurityCentre/azul-restapi-server/blob/main/pyproject.toml) |

## Recommended repos to fork/pin under `third_party/`

If PIIAT chooses to vendor/fork Azul components, the minimal set suggested by the integration paths above is:

| Repo | Why it is relevant to PIIAT | Sources |
|---|---|---|
| `azul-bedrock` | Highest-value static asset source: `identify.yaml`, Avro schemas, shared models, feature types. | [azul-bedrock README](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/README.md), [identify.yaml](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/identify.yaml), [BinaryEvent schema](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/events/schemas/v6/1_binary.json) |
| `azul-runner` | Public plugin SDK if PIIAT wants an Azul-facing plugin/export path. | [azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md) |
| `azul-metastore` | Public storage/query layer if PIIAT wants to experiment with an Azul-backed enrichment sidecar. | [azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md) |
| `azul-restapi-server` | Public API composition surface and plugin entrypoint for custom read/export endpoints. | [azul-restapi-server README](https://github.com/AustralianCyberSecurityCentre/azul-restapi-server/blob/main/README.md) |
| `azul-client` | Ready-made client surface for scripted uploads/queries from PIIAT tooling. | [azul-client README](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/README.md), [azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md) |

Optional, depending on how much example material is desired:

| Repo | Why it is relevant to PIIAT | Sources |
|---|---|---|
| `azul-plugin-maco` | Concrete example of ATT&CK-bearing feature output and config-extraction mapping. | [azul-plugin-maco README](https://github.com/AustralianCyberSecurityCentre/azul-plugin-maco/blob/main/README.md) |
| `azul-docs` | Convenient local copy of architecture/developer guidance that informs integration decisions. | [azul-docs README](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/README.md) |

## Static-state proposal for reuse in PIIAT-MitreCar

The clearest reusable overlap is **not** "map Azul directly into CAR", but "preserve Azul-style provenance and enrichment in static data alongside CAR mapping/cascade data". The strongest public static inputs are Azul's `identify.yaml`, its `BinaryEvent` schema, and the source/result/link/feature model shown in the docs. The examples below are proposed PIIAT-side designs informed by those public assets. ([identify.yaml](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/identify.yaml), [BinaryEvent schema](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/gosrc/events/schemas/v6/1_binary.json), [result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md))

### Proposed YAML: source/provenance wrapper

```yaml
kind: piiat_source_adapter
name: azul_binary_enrichment
description: >
  Preserve how a malware artefact was supplied to analysis without changing
  the CAR interpretation of the event or object that referenced it.
ingest:
  trigger:
    - car_object: file
      conditions:
        - field: image_path
          exists: true
        - field: sha256
          exists: true
  azul_submission:
    source: piiat_case_binary
    references:
      case_id: "{case_id}"
      host: "{hostname}"
      source_event_guid: "{guid}"
      source_car_object: "{car_object}"
      source_car_action: "{car_action}"
      acquisition_path: "{source_path}"
```

### Proposed YAML: enrichment-to-CAR handling rules

```yaml
kind: piiat_enrichment_policy
name: azul_feature_bridge
rules:
  - match:
      azul_feature: attack
    action: annotate_only
    target:
      namespace: enrichment.azul.attack
    rationale: >
      ATT&CK IDs extracted from malware config are useful pivots but are not
      direct proof of the host activity timeline event that referenced the file.

  - match:
      azul_feature_type: uri
    action: candidate_gap_fill
    target:
      namespace: analyst_leads.network_uri
    rationale: >
      Extracted URIs can tell analysts where to look next, but should not be
      promoted to observed CAR flow/http rows without matching evidence.

  - match:
      azul_feature: family
    action: annotate_only
    target:
      namespace: enrichment.azul.family
```

### Proposed STIX-style relationship sketch

```json
{
  "type": "bundle",
  "id": "bundle--12345678-1234-4000-8000-123456789abc",
  "objects": [
    {
      "type": "observed-data",
      "id": "observed-data--22345678-1234-4000-8000-123456789abc",
      "first_observed": "2026-08-31T00:00:00Z",
      "last_observed": "2026-08-31T00:00:00Z",
      "number_observed": 1,
      "object_refs": ["file--32345678-1234-4000-8000-123456789abc"]
    },
    {
      "type": "file",
      "id": "file--32345678-1234-4000-8000-123456789abc",
      "hashes": {
        "SHA-256": "..."
      },
      "name": "payload.bin"
    },
    {
      "type": "malware",
      "id": "malware--42345678-1234-4000-8000-123456789abc",
      "name": "Family identified by Azul enrichment",
      "is_family": true,
      "sample_refs": ["file--32345678-1234-4000-8000-123456789abc"]
    }
  ]
}
```

Suggested interpretation:

- keep the **CAR event/object** as the authoritative observation;
- represent Azul outputs as **enrichment references/relationships** or analyst leads;
- only promote an Azul-derived value into a first-class CAR row when independent evidence confirms it.

That preserves the same discipline already documented in this repository: native evidence first, null when unknown, and explicit distinction between definitive and heuristic relationships. ([docs/CAR-Relations.md](../../CAR-Relations.md))

## STIX direction and payoff

The most important public statement here is from Azul maintainer `james-acsc`: Azul already indexes ATT&CK and MBC values that plugins emit, there is **no current automated STIX workflow**, but STIX is still considered a sensible longer-term direction because it enables **knowledge sharing between Azul and external systems** and should be tested robustly with **OpenCTI**. The same comment suggests two near-term paths before any native STIX support exists: use the API to wrangle the data yourself, or add export logic in metastore. ([Issue #4 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/4#issuecomment-3949198963))

For PIIAT, the payoff from building *toward* that direction now is:

- a future Azul bridge can emit **the same enrichment facts** to both PIIAT and STIX/OpenCTI instead of inventing a second mapping later;
- ATT&CK-bearing Azul features (`attack`, MBC-bearing plugin outputs, YARA/CAPE/Maco enrichments) can become a **shared enrichment vocabulary** across internal timeline analysis and external intelligence-sharing workflows; ([azul-plugin-maco README](https://github.com/AustralianCyberSecurityCentre/azul-plugin-maco/blob/main/README.md), [Issue #4 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/4#issuecomment-3949198963))
- keeping PIIAT's Azul bridge in **static YAML/STIX-oriented policy data** now makes later OpenCTI/STIX export a translation problem rather than a rewrite.

The public direction alluded to so far is therefore:

1. keep Azul plugin outputs rich in ATT&CK/MBC-style features now;
2. use API/metastore exports as the short-term extraction point;
3. leave space for later **native STIX/OpenCTI integration** once the model and testing story are mature.

## Bottom line

- **Adopt ideas, not the whole schema.** Azul offers strong provenance, feature-normalization and plugin-extension ideas, but its public model is centered on malware entities rather than CAR timeline activity. ([About](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/overview/about.md), [runner features](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/runner/docs/features.md))
- **Best practical integration:** use Azul as a malware/file enrichment system behind PIIAT rather than as PIIAT's canonical normalized store. ([azul-client API](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/docs/api.md))
- **Storage answer:** keep SQLite as the per-source product store; use Azul only as an optional shared enrichment tier. ([PIIAT README](../../../README.md), [Azul architecture](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/sysadmin-guide/20-architecture.md))
- **Fork/pin priority:** if vendoring Azul components later, start with `azul-bedrock`, `azul-runner`, `azul-metastore`, `azul-restapi-server`, and `azul-client`. ([azul-bedrock README](https://github.com/AustralianCyberSecurityCentre/azul-bedrock/blob/main/README.md), [azul-runner README](https://github.com/AustralianCyberSecurityCentre/azul-runner/blob/main/README.md), [azul-metastore README](https://github.com/AustralianCyberSecurityCentre/azul-metastore/blob/main/README.md), [azul-restapi-server README](https://github.com/AustralianCyberSecurityCentre/azul-restapi-server/blob/main/README.md), [azul-client README](https://github.com/AustralianCyberSecurityCentre/azul-client/blob/main/README.md))
- **STIX direction:** build the bridge so it can later feed OpenCTI/STIX if Azul exposes or adopts that path. ([Issue #4 maintainer comment](https://github.com/AustralianCyberSecurityCentre/azul/issues/4#issuecomment-3949198963))
- **Best reusable output for this repo:** keep hard mappings/relationships/sources in static YAML or STIX-like side data owned by PIIAT, borrowing Azul's provenance and enrichment patterns where helpful. ([result documents](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/result_document.md), [binary2](https://github.com/AustralianCyberSecurityCentre/azul-docs/blob/main/docs/developer-guide/components/core/metastore/docs/binary2.md))
