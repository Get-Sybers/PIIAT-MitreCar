"""Reconstruct the object models LIVE from the pinned submodules (epic #12).

Nothing is committed — the models are always the pinned upstream source:

- build_car() -> the 13 CAR objects (name / actions / scalar fields), from
  third_party/car/data_model/*.yaml. CAR is the only source of scalar fields.
- build_superset() -> the CAR + ATT&CK-data-sources superset: the 13 CAR objects
  plus the objects ATT&CK adds (user_account, group, volume, …), from
  third_party/attack-datasources. ATT&CK has NO scalar fields — it describes an
  object as RELATIONSHIPS to other objects; component names give the actions, and
  the (source, relationship, target) edges are the cascade vocabulary. Overlap
  objects keep CAR's scalar fields and gain any ATT&CK-derived actions.

`--write DIR` optionally exports the built models for inspection.
"""
from __future__ import annotations

import argparse
import json
import os
import re

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
# Sources are the PINNED submodules — never a vendored copy — so the model is
# reconstructed from upstream, not validated against ourselves.
_CAR_DM = os.path.join(_ROOT, "third_party", "car", "data_model")
_ADS = os.path.join(_ROOT, "third_party", "attack-datasources", "docs",
                    "attack_data_sources_objects.yaml")
# Nothing is committed: the CAR model (13), the CAR+ATT&CK superset (~38) and the
# relationship catalogue are all reconstructed live from the pinned submodules
# (build_car / build_superset). `--write DIR` can export them for inspection.


def _load_car_base() -> dict:
    """Reconstruct the CAR object model from the pinned car submodule's
    data_model/*.yaml (name / actions[].name / fields[].name)."""
    import glob
    files = sorted(glob.glob(os.path.join(_CAR_DM, "*.yaml")))
    if not files:
        raise SystemExit("car submodule not checked out — run: "
                         "git submodule update --init third_party/car")
    objects = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        key = re.sub(r"[^a-z0-9]+", "_", doc["name"].lower()).strip("_")
        objects.append({
            "name": [key],
            "fields": [f["name"] for f in (doc.get("fields") or [])],
            "actions": [a["name"] for a in (doc.get("actions") or [])],
        })
    return {"objects": objects}

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


def build_car() -> dict:
    """The 13 canonical CAR objects, reconstructed from the pinned car submodule."""
    return _load_car_base()


def build_superset() -> tuple[dict, list[dict]]:
    base = _load_car_base()
    if not os.path.exists(_ADS):
        raise SystemExit("attack-datasources submodule not checked out — run: "
                         "git submodule update --init third_party/attack-datasources")
    with open(_ADS, encoding="utf-8") as fh:
        ads = yaml.safe_load(fh)

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
    header = ("# Generated by build_data_model from the pinned attack-datasources submodule.\n"
              "# The ATT&CK data-source relationship (edge) catalogue: the proven\n"
              "# source->relationship->target edges between data elements (mostly object\n"
              "# references). This is the cascade vocabulary (goal B) — our within-source\n"
              "# joins (owning-process, parent, auth<->session, file->process) are typed\n"
              "# instances of these. NOT scalar fields; never car.db columns.\n")
    return header + yaml.safe_dump({"relationships": rels}, sort_keys=False,
                                   allow_unicode=True)


def write(out_dir: str) -> None:
    """Optional export of the live-built models for inspection (not committed)."""
    os.makedirs(out_dir, exist_ok=True)
    car = build_car()
    superset, rels = build_superset()
    with open(os.path.join(out_dir, "car_data_model.json"), "w", encoding="utf-8") as fh:
        fh.write(_dump_model(car))
    with open(os.path.join(out_dir, "superset_data_model.json"), "w", encoding="utf-8") as fh:
        fh.write(_dump_model(superset))
    with open(os.path.join(out_dir, "attack_relationships.yml"), "w", encoding="utf-8") as fh:
        fh.write(_dump_rels(rels))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="piiat_mitrecar.build_data_model")
    ap.add_argument("--write", metavar="DIR", help="export the built models to DIR")
    args = ap.parse_args(argv)
    car = build_car()
    superset, rels = build_superset()
    if args.write:
        write(args.write)
        print("exported to", args.write)
    print(f"CAR: {len(car['objects'])} objects | superset: {len(superset['objects'])} "
          f"objects | relationships: {len(rels)} edges (live from pinned submodules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
