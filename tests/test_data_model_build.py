"""The data-model superset generator (epic #86).

car_data_model.json = CAR 13 (verbatim, the scalar-field source) + ATT&CK
data-source objects (component-derived actions), generated repeatably from
car_data_model.base.json + attack_data_sources_objects.yaml, plus the ATT&CK
relationship edge catalogue. These tests keep that derivation honest.
"""
import json
import os

from piiat_mitrecar import build_data_model, carmodel

_CAR_13 = {"authentication", "driver", "email", "file", "flow", "http", "module",
           "process", "registry", "service", "socket", "thread", "user_session"}


def test_car13_preserved_verbatim():
    # every CAR object keeps its exact scalar fields + at least its CAR actions
    base = {(_n(o)): o for o in json.load(open(build_data_model._BASE))["objects"]}
    model, _ = build_data_model.build()
    built = {(_n(o)): o for o in model["objects"]}
    for name, b in base.items():
        assert name in built
        assert list(b["fields"]) == list(built[name]["fields"])   # fields verbatim
        assert set(b["actions"]) <= set(built[name]["actions"])    # actions superset


def test_attack_objects_added_actions_only():
    model, _ = build_data_model.build()
    objs = {_n(o): o for o in model["objects"]}
    assert _CAR_13 <= set(objs)
    for k in ("user_account", "group", "volume"):
        assert k in objs
        assert objs[k]["actions"]        # component-derived actions
        assert objs[k]["fields"] == []   # no scalar fields yet (defined on mapping)
        assert objs[k]["source"] == "attack"


def test_relationships_catalogue_present():
    _, rels = build_data_model.build()
    assert len(rels) > 100
    trip = {(r["source"], r["relationship"], r["target"]) for r in rels}
    assert ("user", "created", "logon session") in trip
    assert ("process", "loaded", "module") in trip


def test_generation_is_idempotent_and_in_sync():
    # committed outputs must match a fresh build (CI-style drift guard)
    assert build_data_model.check() == []


def _n(o):
    return o["name"][0] if isinstance(o["name"], list) else o["name"]
