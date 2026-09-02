# Contributing

## Setup

The object model is reconstructed live from **pinned submodules**, so clone
recursively (or init them after):

```
git clone --recursive https://github.com/Get-Sybers/PIIAT-MitreCar
# or, in an existing checkout:
git submodule update --init --recursive
pip install -e '.[dev]'
```

- `third_party/car` — the MITRE CAR data model (the 13 CAR objects).
- `third_party/attack-datasources` — the ATT&CK data-sources model (the superset
  objects + the relationship catalogue).

A model refresh is a **submodule-pin bump**, never a hand-edit — nothing about the
model or the ATT&CK vocabulary is committed as a copy (see
[docs/DataModel.md](docs/DataModel.md)).

## Everyday commands

```
python -m piiat_mitrecar --in <file-or-dir> --out <dir>   # run one source
python -m piiat_mitrecar --batch <processed_dir>          # every source
python -m piiat_mitrecar.gen_sources                      # regenerate sources/ after a map change
python -m piiat_mitrecar.timeline <car-dir>               # unified CAR timeline (car.db + superset.db)
python -m piiat_mitrecar.build_data_model --write out/    # export the models for inspection
pytest -q                                                 # tests
```

CI (`.github/workflows/lint.yml`) runs `gen_sources --check`, `spindle --check`
(the identity registry, its snapshot and the golden vectors), `yamale`,
`yamllint`, and `pytest` — with submodules checked out.

## Code style — [module-best-practices](https://github.com/mattdesl/module-best-practices)

- **Small, focused, separate files** — one artefact family per file in
  `mappings/` (auto-discovered). Prefer another small file over a big one; this
  guide favours that over deep subpackage nesting, so the module layout stays flat.
- **Don't duplicate** — shared map helpers live in `mappings/_common.py`
  (`R`/`plaso_rec`/`PLASO_HOST`/`spindle`, `EVTX_HOST`/`EVTX_FQDN`/`EVTX_KEEP`/
  `EVTX_RECORD_GUID`/`evtx_payload_field`), and the one id recipe (namespaces +
  canonical JSON, shared by the STIX projection and the spindle row guid) in
  `ids.py`. Import them rather than re-defining.
- **Data, not code** — the cascade rules (`relationships.yml`), the
  relationship-verb bridge (`cascade_relationships.yml`), the spindle
  row-identity registry (`spindle.yml` — which fields a disk-image row's guid
  is minted from; snapshot `model/spindle/`), and the source manifests
  (`sources/`, generated) are data; the engine implements mechanics.
- **Honest mapping** — map a record only when it fits a canonical CAR
  object + action; nulls/duplicates are fine, near-misses are not (see
  [docs/CAR-Relations.md](docs/CAR-Relations.md)). Unvalidated inferences go in
  `to-be-validated/`.
- Naming: `readers.py` = input readers; `sources_model.py` = the source-manifest
  generator; `sources/` = its generated output. Keep those distinct.

## Adding a map

1. Add `mappings/<artefact>.py` exporting `MAPPINGS` (+ `PREDICATES` if needed),
   using the `_common` helpers.
2. Route it in `pipeline.py` (`ROUTES` / `EVTX_MAPS`) if it needs filename routing.
3. `python -m piiat_mitrecar.gen_sources` and commit the regenerated `sources/`.
4. A disk-image (l2t/Plaso) map names its row identity: add the entry to
   `spindle.yml` — `object`, `kind` (`record` | `entity`), `scope: intrinsic`,
   `version: 1`, `validated_against: [plaso]`, `stable_across`, the `identity`
   fields and a `golden` sample — reference it with
   `_common.spindle("<entry>")`, then `python model/generate.py` and commit
   the regenerated `model/spindle/` (identity, record and golden). Any other
   map's raw guid form must be one of the registry's `external:` forms.
   **The P7 rule:** a leaf that emits no timestamp (`ts: None` — a PE's
   compile stamp, an amcache Link Time) MUST name a time-free `kind: entity`
   entry; `spindle --check` refuses a Plaso leaf without an entry and a timed
   identity on an untimed leaf.
5. Add a test; run `pytest -q`.

## Changing a row identity (the change protocol)

An entry's identity fields, names, rendering or golden sample change **only
with a `version` bump** — the version is hashed into every guid as `_v`:

1. edit the entry in `spindle.yml` and bump its `version`;
2. `python model/generate.py` — regenerates `model/spindle/` (the golden vector
   moves with the version; the generator refuses a guid that moved without it);
3. commit the snapshot, `golden.yml` included, and the regenerated `sources/`
   (each manifest states its identity entries and versions);
4. rebuild the stores (`--batch --force`) — every guid of that entry re-mints
   (a remint / audit tool is a follow-up). The id recipe itself (namespaces,
   canonical JSON) never changes under a version bump: that would move every
   guid at once and is a new spindle.

## Branch / release flow

- Land work on **`dev`**.
- Promote to **`main` via a `dev → main` pull request** (never a ref
  fast-forward); CI must be green. Maintainers merge — open the PR and leave it.
- Follow **SemVer** for `version` in `pyproject.toml`.
