#!/usr/bin/env python3
"""Drift check for the CAR -> STIX 2.1 projection contract (pyyaml only).

Asserts that model/stix/{conventions,objects}.yml stay in step with the
materialized CAR model (model/car/objects) and with the rules the engine
declares (piiat_mitrecar/relationships.yml, enrich.py, derive.py):

- objects.yml covers the 13 CAR objects exactly, no orphan;
- every object_field has exactly one projection entry, no entry names a field
  the object lacks;
- `sco` is a known SCO / custom type, `sro_end` is `sco` or `observed-data`;
- `hash_subject` names a path column of the object iff the object carries hash
  fields, and equals engine_declarations.hash_subject;
- `acting` columns exist on the object;
- the inheritance-trace native keys are ones enrich.py / derive.py write;
- the two native-only join keys name rules relationships.yml declares, and the
  key is the rule's join/reference.

    python model/stix/validate.py      # exit 1 + a problem list on drift
"""
from __future__ import annotations

import glob
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CAR_OBJECTS = os.path.join(ROOT, "model", "car", "objects")
RULES = os.path.join(ROOT, "piiat_mitrecar", "relationships.yml")
ENGINES = [os.path.join(ROOT, "piiat_mitrecar", "enrich.py"),
           os.path.join(ROOT, "piiat_mitrecar", "derive.py")]

SCO_TYPES = {"artifact", "autonomous-system", "directory", "domain-name", "email-addr",
             "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
             "network-traffic", "process", "software", "url", "user-account",
             "windows-registry-key", "x509-certificate", "x-car-thread", "x-car-record"}
HASH_FIELDS = {"md5_hash", "sha1_hash", "sha256_hash"}


def load_car_model() -> dict[str, list[str]]:
    out = {}
    for path in sorted(glob.glob(os.path.join(CAR_OBJECTS, "*.yml"))):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        out[doc["name"]] = [f["name"] for f in doc["properties"]["object_fields"]]
    return out


def load_contract() -> tuple[dict, dict]:
    with open(os.path.join(HERE, "conventions.yml"), encoding="utf-8") as fh:
        conventions = yaml.safe_load(fh)
    with open(os.path.join(HERE, "objects.yml"), encoding="utf-8") as fh:
        objects = yaml.safe_load(fh)["objects"]
    return conventions, objects


def _derived_rules() -> dict[str, dict]:
    with open(RULES, encoding="utf-8") as fh:
        d = yaml.safe_load(fh)["derived"]
    out = {}
    for r in d.get("links", []):
        out[r["name"]] = dict(r, _key=(r.get("join") or {}).get("source"), _object=r["source"])
    for r in d.get("reconstruct", []):
        # YAML 1.1 reads the bare key `on` as the boolean True (PyYAML does)
        on = r.get("on") if "on" in r else r.get(True)
        out[r["name"]] = dict(r, _key=r.get("reference"), _object=str(on or "").partition("/")[0])
    return out


def validate(car: dict, conventions: dict, objects: dict) -> list[str]:
    errors: list[str] = []
    for obj in sorted(set(car) - set(objects)):
        errors.append(f"{obj}: CAR object has no projection file entry")
    for obj in sorted(set(objects) - set(car)):
        errors.append(f"{obj}: orphan — not a CAR object")

    for obj in sorted(set(car) & set(objects)):
        spec, fields = objects[obj], car[obj]
        if spec.get("sco") not in SCO_TYPES:
            errors.append(f"{obj}: sco {spec.get('sco')!r} is not a known SCO / custom type")
        if spec.get("sro_end") not in ("sco", "observed-data"):
            errors.append(f"{obj}: sro_end must be sco or observed-data")
        props = spec.get("properties") or {}
        for f in fields:
            if f not in props:
                errors.append(f"{obj}.{f}: no projection entry")
        for f in props:
            if f not in fields:
                errors.append(f"{obj}.{f}: orphan — not a field of the object")
        hs = spec.get("hash_subject")
        if set(fields) & HASH_FIELDS:
            if hs not in fields or not str(hs).endswith("_path"):
                errors.append(f"{obj}: hash_subject must name a path column of the object (got {hs!r})")
        elif hs is not None:
            errors.append(f"{obj}: hash_subject {hs!r} on an object without hash fields")
        for col in spec.get("acting") or []:
            if col not in fields:
                errors.append(f"{obj}: acting column {col!r} is not a field of the object")

    decl = conventions.get("engine_declarations") or {}
    want = {o: s.get("hash_subject") for o, s in objects.items() if s.get("hash_subject")}
    if decl.get("hash_subject") != want:
        errors.append(f"engine_declarations.hash_subject {decl.get('hash_subject')} != objects.yml {want}")

    engine_src = ""
    for path in ENGINES:
        with open(path, encoding="utf-8") as fh:
            engine_src += fh.read()
    for key in (decl.get("inheritance_trace") or {}).get("native_keys") or []:
        if f'"{key}"' not in engine_src:
            errors.append(f"inheritance_trace.native_keys: {key!r} is not written by enrich.py / derive.py")

    rules = _derived_rules()
    joins = decl.get("native_only_join_keys") or []
    if len(joins) != 2:
        errors.append(f"native_only_join_keys: expected exactly two, got {len(joins)}")
    for j in joins:
        rule = rules.get(j.get("rule"))
        if rule is None:
            errors.append(f"native_only_join_keys: rule {j.get('rule')!r} is not in relationships.yml derived")
            continue
        if not str(j.get("key", "")).startswith("native."):
            errors.append(f"native_only_join_keys[{j['rule']}]: key {j.get('key')!r} is not native.<key>")
        if rule["_key"] != j.get("key"):
            errors.append(f"native_only_join_keys[{j['rule']}]: key {j.get('key')!r} != rule's {rule['_key']!r}")
        if rule["_object"] != j.get("object"):
            errors.append(f"native_only_join_keys[{j['rule']}]: object {j.get('object')!r} != rule's {rule['_object']!r}")
        col = str(j.get("key", ""))[len("native."):]
        if col in (car.get(j.get("object")) or []):
            errors.append(f"native_only_join_keys[{j['rule']}]: {col!r} IS a CAR column of {j.get('object')}")
    return errors


def main() -> int:
    car = load_car_model()
    conventions, objects = load_contract()
    errors = validate(car, conventions, objects)
    if errors:
        print("car-stix projection: DRIFT")
        for e in errors:
            print(f"  - {e}")
        return 1
    n_fields = sum(len(v) for v in car.values())
    print(f"car-stix projection OK: {len(objects)} objects, {n_fields} fields, "
          f"{len(conventions['engine_declarations']['hash_subject'])} hash subjects, "
          f"{len(conventions['engine_declarations']['native_only_join_keys'])} native-only join keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
