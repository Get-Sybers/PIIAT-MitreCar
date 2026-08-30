"""The data-model generator (epic #12).

Reconstructs, from the pinned submodules: car_data_model.json = the 13 canonical
CAR objects (from third_party/car), and superset_data_model.json = CAR 13 + ATT&CK
data-source objects (from third_party/attack-datasources), plus the ATT&CK
relationship edge catalogue. These tests keep that derivation honest.
"""
from piiat_mitrecar import build_data_model

_CAR_13 = {"authentication", "driver", "email", "file", "flow", "http", "module",
           "process", "registry", "service", "socket", "thread", "user_session"}


def _n(o):
    return o["name"][0] if isinstance(o["name"], list) else o["name"]


def test_car_model_is_the_13_from_the_submodule():
    car = {_n(o): o for o in build_data_model.build_car()["objects"]}
    assert set(car) == _CAR_13
    assert car["process"]["fields"]      # scalar fields come from the car submodule


def test_superset_preserves_car13_and_adds_attack_objects():
    car = {_n(o): o for o in build_data_model.build_car()["objects"]}
    superset, _ = build_data_model.build_superset()
    built = {_n(o): o for o in superset["objects"]}
    assert _CAR_13 <= set(built)
    assert len(built) > len(car)                              # ATT&CK objects added
    # CAR objects keep their exact scalar fields + at least their CAR actions
    for name, b in car.items():
        assert list(b["fields"]) == list(built[name]["fields"])
        assert set(b["actions"]) <= set(built[name]["actions"])
    # pure-ATT&CK objects: actions only, no scalar fields yet
    for k in ("user_account", "group", "volume"):
        assert k in built and built[k]["actions"] and built[k]["fields"] == []
        assert built[k]["source"] == "attack"


def test_relationships_catalogue_present():
    _, rels = build_data_model.build_superset()
    assert len(rels) > 100
    trip = {(r["source"], r["relationship"], r["target"]) for r in rels}
    assert ("user", "created", "logon session") in trip
    assert ("process", "loaded", "module") in trip


def test_generation_is_deterministic():
    # reconstruction from the pinned submodules is stable across calls
    assert build_data_model.build_car() == build_data_model.build_car()
    a, ra = build_data_model.build_superset()
    b, rb = build_data_model.build_superset()
    assert a == b and ra == rb
