"""Regenerate car_data_model.json as a CAR + ATT&CK-data-sources SUPERSET, and
emit the ATT&CK relationship (edge) catalogue (epic #86).

Two models, two layers, merged repeatably:

- **CAR** (car_data_model.base.json — the pristine 13 objects) is the only source
  of SCALAR FIELDS (the car.db columns) and the canonical actions. Kept verbatim.
- **ATT&CK data-sources** (attack_data_sources_objects.yaml, vendored/pinned) adds
  ~25 OBJECTS CAR lacks (user_account, group, logon_session, volume, …) and, per
  object, data COMPONENTS whose names map to ACTIONS. It has NO scalar fields —
  it describes an object as RELATIONSHIPS to other data elements, which are almost
  all object references (user/process/file/…). Those relationships are NOT columns;
  they are the cascade edge vocabulary, emitted separately to attack_relationships.yml.

Output (deterministic, idempotent):
  - car_data_model.json      : objects = CAR 13 (fields+actions, verbatim) + ATT&CK
                               objects (component-derived actions; scalar fields
                               empty until defined as events are mapped); overlap
                               objects gain any ATT&CK-derived actions CAR lacked.
  - attack_relationships.yml : the distinct (source, relationship, target) edges —
                               the proven-relationship catalogue for the cascade.

Run:  python -m piiat_mitrecar.build_data_model [--check]
"""
from __future__ import annotations

import argparse
import json
import os
import re

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.join(_HERE, "car_data_model.base.json")
_ADS = os.path.join(_HERE, "attack_data_sources_objects.yaml")
_MODEL_OUT = os.path.join(_HERE, "car_data_model.json")
_REL_OUT = os.path.join(_HERE, "attack_relationships.yml")

# ATT&CK data-source name -> our object key. Overlaps fold onto the CAR object
# (which keeps its scalar fields); everything else becomes a new object.
_OVERLAP = {
    "file": "file", "process": "process", "driver": "driver", "module": "module",
    "service": "service", "windows registry": "registry",
    "network traffic": "flow", "logon session": "user_session",
}


def _key(att_name: str) -> str:
    low = att_name.strip().lower()
    if low in _OVERLAP:
        return _OVERLAP[low]
    return re.sub(r"[^a-z0-9]+", "_", low).strip("_")


# component name (minus the object prefix) -> canonical action verb, by keyword.
def _action_for(component_name: str, object_name: str) -> str:
    s = component_name.lower()
    op = object_name.lower()
    if s.startswith(op):
        s = s[len(op):].strip()
    checks = [
        ("creat", "create"), ("deletion", "delete"), ("delet", "delete"),
        ("terminat", "terminate"), ("modif", "modify"), ("authenticat", "authenticate"),
        ("enumerat", "enumerate"), ("execut", "execute"), ("metadata", "metadata"),
        ("access", "access"), ("connect", "connect"), ("load", "load"),
        ("start", "start"), ("stop", "stop"), ("bind", "bind"), ("listen", "listen"),
        ("lock", "lock"), ("enable", "enable"), ("disable", "disable"),
        ("power", "power_state"), ("deploy", "deploy"),
    ]
    for kw, verb in checks:
        if kw in s:
            return verb
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_") or "activity"


def build() -> tuple[dict, list[dict]]:
    base = json.load(open(_BASE, encoding="utf-8"))
    ads = yaml.safe_load(open(_ADS, encoding="utf-8"))

    # index the CAR base by key (name may be a 1-list)
    objs: dict[str, dict] = {}
    order: list[str] = []
    for o in base["objects"]:
        name = o["name"][0] if isinstance(o["name"], list) else o["name"]
        objs[name] = {"name": [name], "fields": list(o["fields"]),
                      "actions": list(o["actions"]), "source": "car"}
        order.append(name)

    edges: set[tuple[str, str, str]] = set()
    for a in ads:
        k = _key(a["name"])
        comp_actions = set()
        for c in a.get("data_components") or []:
            comp_actions.add(_action_for(c["name"], a["name"]))
            for r in c.get("relationships") or []:
                s, rel, t = (r.get("source_data_element"), r.get("relationship"),
                             r.get("target_data_element"))
                if s and rel and t:
                    edges.add((s, rel, t))
        if k in objs:
            # overlap: keep CAR fields, UNION in ATT&CK-derived actions
            merged = sorted(set(objs[k]["actions"]) | comp_actions)
            objs[k]["actions"] = merged
            objs[k]["source"] = "car+attack"
            objs[k].setdefault("attack_name", a["name"])
        else:
            objs[k] = {
                "name": [k], "fields": [], "actions": sorted(comp_actions),
                "source": "attack", "attack_name": a["name"],
                "definition": a.get("definition"),
                "platforms": a.get("platforms"),
                "collection_layers": a.get("collection_layers"),
            }
            order.append(k)

    model = {"objects": [objs[k] for k in sorted(order)]}
    rels = [{"source": s, "relationship": r, "target": t}
            for (s, r, t) in sorted(edges)]
    return model, rels


def _dump_model(model: dict) -> str:
    return json.dumps(model, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _dump_rels(rels: list[dict]) -> str:
    header = ("# Generated by build_data_model.py from attack_data_sources_objects.yaml.\n"
              "# The ATT&CK data-source relationship (edge) catalogue: the proven\n"
              "# source->relationship->target edges between data elements (mostly object\n"
              "# references). This is the cascade vocabulary (goal B) — our within-source\n"
              "# joins (owning-process, parent, auth<->session, file->process) are typed\n"
              "# instances of these. NOT scalar fields; never car.db columns.\n")
    return header + yaml.safe_dump({"relationships": rels}, sort_keys=False,
                                   allow_unicode=True)


def write() -> None:
    model, rels = build()
    open(_MODEL_OUT, "w", encoding="utf-8").write(_dump_model(model))
    open(_REL_OUT, "w", encoding="utf-8").write(_dump_rels(rels))


def check() -> list[str]:
    model, rels = build()
    problems = []
    if not os.path.exists(_MODEL_OUT) or open(_MODEL_OUT, encoding="utf-8").read() != _dump_model(model):
        problems.append("car_data_model.json is stale — run build_data_model")
    if not os.path.exists(_REL_OUT) or open(_REL_OUT, encoding="utf-8").read() != _dump_rels(rels):
        problems.append("attack_relationships.yml is stale — run build_data_model")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="piiat_mitrecar.build_data_model")
    ap.add_argument("--check", action="store_true", help="fail if outputs are stale")
    args = ap.parse_args(argv)
    if args.check:
        probs = check()
        for p in probs:
            print("DRIFT:", p)
        print("OK: data model + relationships in sync" if not probs else "STALE")
        return 1 if probs else 0
    write()
    model, rels = build()
    print(f"wrote {len(model['objects'])} objects to car_data_model.json "
          f"and {len(rels)} relationship edges to attack_relationships.yml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
