# Data model

Two models and a relationship catalogue, all reconstructed **live from pinned
submodules** — never committed copies, so nothing can drift from upstream.

## CAR — 13 objects

The canonical MITRE CAR model: `authentication, driver, email, file, flow, http,
module, process, registry, service, socket, thread, user_session`. Reconstructed
by `carmodel.load()` from `third_party/car/data_model/*.yaml` (the pinned
[mitre-attack/car](https://github.com/mitre-attack/car) fork). CAR is the source
of **scalar fields** — the columns of every `car.db` table.

## Superset — CAR + ATT&CK data-sources

CAR has no principal/host/volume object and no relationship model. The
[ATT&CK data-sources](https://github.com/mitre-attack/attack-datasources) model
supplies them, so `build_data_model.build_superset()` merges the two (from the
pinned `third_party/attack-datasources` submodule):

- the 13 CAR objects (kept verbatim — the only source of scalar fields), **plus**
- the ATT&CK data-source objects CAR lacks (`user_account`, `group`, `volume`,
  `logon_session`→`user_session`, …), whose **actions come from ATT&CK data
  components** (scalar fields are added as events are mapped to them).

**Never a replace, always a superset** — ATT&CK data-sources carry no scalar
fields (they describe an object as relationships to *other objects*), so replacing
CAR would lose the car.db columns.

## Relationships — the cascade vocabulary

ATT&CK models an object as a graph: each data component carries
`source → relationship → target` edges between data elements (mostly object
references). `build_superset()` emits this catalogue (~243 edge-types) — the
proven-relationship vocabulary. The cascade's own edges (owning-process, parent,
auth↔session by LUID, file→process by image path, thread injection) are typed
instances of it: `cascade_relationships.yml` maps each cascade edge to a verb, and
a test enforces every verb exists in the reconstructed ATT&CK catalogue. The
relationship *instances* land in `superset.db` as a timestamped timeline (see
[Architecture.md](Architecture.md)).

## Regenerating / inspecting

The models are built on demand; nothing is committed. To export them for
inspection:

```
git submodule update --init --recursive
python -m piiat_mitrecar.build_data_model --write out/
```

A model refresh is a **submodule-pin bump**, not a code or data-file edit.
