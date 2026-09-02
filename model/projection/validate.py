#!/usr/bin/env python3
"""Validate the hand-authored CAR->ECS projection contract against the CAR model.

The contract (conventions.yml + objects/<object>.yml) is written by hand; the
CAR model it projects (model/car/objects/*.yml) is generated from the pinned
submodules. This script keeps the two in lock-step — any drift is a non-zero
exit:

  * every CAR object has an objects/<object>.yml, and there is no orphan file;
  * every object_field of every object has exactly ONE projection entry —
    mapped (`ecs: <path>`) or explicitly homeless (`native: true` + `rationale`
    + `type`) — and no entry names a CAR field the object does not have;
  * conventions.yml projects every common_header field exactly once, and its
    per-object overrides / custom-namespace roots name real objects / fields;
  * every `ecs:` path looks like ECS (lower-case dotted, a known ECS 8.x
    top-level field set); custom homes are expressed as `native: true`, never
    as an `ecs:` path under `car.`;
  * two entries of one object sharing a primary target are explicit about it
    (exactly one primary, `fallback: true` on every other — rules.fallback);
  * event_defaults: a category, and an event.type for every car_action of the
    object (and only those); outcome sources name real actions / fields;
  * `derived:` entries build from real header / object fields.

Dependencies: pyyaml only.

    python model/projection/validate.py
"""
from __future__ import annotations

import glob
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.dirname(HERE)
CAR_OBJECTS_DIR = os.path.join(MODEL_DIR, "car", "objects")
CONVENTIONS_PATH = os.path.join(HERE, "conventions.yml")
OBJECTS_DIR = os.path.join(HERE, "objects")

# ECS 8.x top-level field sets (+ the base fields). A cheap guard against
# typos (`proccess.name`) — the full ECS schema is deliberately not vendored.
ECS_TOP_LEVEL = {
    "@timestamp", "labels", "message", "tags",
    "agent", "as", "client", "cloud", "code_signature", "container", "data_stream",
    "destination", "device", "dll", "dns", "ecs", "elf", "email", "error", "event",
    "faas", "file", "geo", "group", "hash", "host", "http", "interface", "log",
    "macho", "network", "observer", "orchestrator", "organization", "os", "package",
    "pe", "process", "registry", "related", "risk", "rule", "server", "service",
    "source", "threat", "tls", "trace", "transaction", "url", "user", "user_agent",
    "vlan", "vulnerability", "x509",
}
CUSTOM_ROOT = "car"
ECS_PATH = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
NATIVE_TYPES = {"keyword", "text", "long", "double", "float", "boolean", "date", "ip", "flattened"}
ENTRY_KEYS = {"car", "ecs", "also", "fallback", "note", "native", "rationale", "type"}
OUTCOMES = {"success", "failure", "unknown"}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_car_model() -> dict[str, dict]:
    """{object: {header: [...], fields: [...], actions: [...]}} from model/car/objects/*.yml."""
    model: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(CAR_OBJECTS_DIR, "*.yml"))):
        doc = _load(path)
        props = doc.get("properties") or {}
        model[doc["name"]] = {
            "header": list(props.get("common_header") or []),
            "fields": [f["name"] for f in (props.get("object_fields") or [])],
            "actions": list(doc.get("car_action") or []),
        }
    return model


def load_contract() -> tuple[dict, dict[str, dict]]:
    """(conventions, {object: objects/<object>.yml doc})."""
    conventions = _load(CONVENTIONS_PATH)
    objects = {}
    for path in sorted(glob.glob(os.path.join(OBJECTS_DIR, "*.yml"))):
        objects[os.path.splitext(os.path.basename(path))[0]] = _load(path)
    return conventions, objects


def _check_path(path, where: str, errors: list[str], allow_custom: bool = False) -> None:
    if path == "@timestamp":
        return
    if not isinstance(path, str) or not ECS_PATH.match(path):
        errors.append(f"{where}: {path!r} is not an ECS-style field path")
        return
    root = path.split(".", 1)[0]
    if root == CUSTOM_ROOT:
        if not allow_custom:
            errors.append(f"{where}: '{path}' is under the custom car.* namespace — "
                          "express a homeless field as native: true, not as an ecs: target")
        return
    if root not in ECS_TOP_LEVEL:
        errors.append(f"{where}: '{path}' — '{root}' is not an ECS 8.x top-level field set")


def _validate_conventions(conv: dict, car: dict[str, dict], errors: list[str]) -> None:
    header_union: set[str] = set()
    for m in car.values():
        header_union |= set(m["header"])
    entries = conv.get("common_header")
    if not isinstance(entries, dict):
        errors.append("conventions.yml: common_header: must be a mapping of header field -> entry")
        return
    for h in sorted(header_union - set(entries)):
        errors.append(f"conventions.yml common_header: CAR header field '{h}' has no projection")
    for h in sorted(set(entries) - header_union):
        errors.append(f"conventions.yml common_header.{h}: orphan — not a CAR header field")
    custom = conv.get("custom_namespace") or {}
    for h, entry in entries.items():
        where = f"conventions.yml common_header.{h}"
        if not isinstance(entry, dict) or not entry.get("ecs"):
            errors.append(f"{where}: needs an ecs: target")
            continue
        _check_path(entry["ecs"], where, errors, allow_custom=True)
        if str(entry["ecs"]).startswith(CUSTOM_ROOT + ".") and entry["ecs"] not in custom:
            errors.append(f"{where}: custom target '{entry['ecs']}' is not declared in custom_namespace")
        for a in entry.get("also") or []:
            _check_path(a, f"{where} also", errors, allow_custom=True)
        for obj, override in (entry.get("per_object") or {}).items():
            if obj not in car:
                errors.append(f"{where}.per_object: '{obj}' is not a CAR object")
            for a in (override or {}).get("also") or []:
                _check_path(a, f"{where}.per_object.{obj} also", errors, allow_custom=True)
    for obj in conv.get("event_categorisation") or {}:
        if obj not in car:
            errors.append(f"conventions.yml event_categorisation: '{obj}' is not a CAR object")


def _validate_object(name: str, model: dict, doc: dict, header_union: set[str],
                     errors: list[str]) -> None:
    where = f"objects/{name}.yml"
    if doc.get("object") != name:
        errors.append(f"{where}: object: must be '{name}'")
    if doc.get("data_stream") != f"logs-car.{name}-*":
        errors.append(f"{where}: data_stream: must be 'logs-car.{name}-*'")

    fields = doc.get("fields")
    if not isinstance(fields, list):
        errors.append(f"{where}: fields: must be a list of projection entries")
        return
    seen: set[str] = set()
    primary: dict[str, list[tuple[str, bool]]] = {}
    for i, e in enumerate(fields):
        if not isinstance(e, dict) or not e.get("car"):
            errors.append(f"{where} fields[{i}]: entry needs a car: field name")
            continue
        f = e["car"]
        ew = f"{where} fields[{f}]"
        if f not in model["fields"]:
            hint = (" (a common_header field — projected by conventions.yml)"
                    if f in header_union else "")
            errors.append(f"{ew}: orphan — CAR object '{name}' has no field '{f}'{hint}")
            continue
        if f in seen:
            errors.append(f"{ew}: duplicate entry")
            continue
        seen.add(f)
        unknown = sorted(set(e) - ENTRY_KEYS)
        if unknown:
            errors.append(f"{ew}: unknown key(s) {unknown}")
        has_ecs, is_native = "ecs" in e, e.get("native") is True
        if has_ecs == is_native:
            errors.append(f"{ew}: needs exactly one of ecs: <path> or native: true")
        if has_ecs:
            _check_path(e["ecs"], ew, errors)
            primary.setdefault(str(e["ecs"]), []).append((f, bool(e.get("fallback"))))
        if is_native:
            if not isinstance(e.get("rationale"), str) or not e["rationale"].strip():
                errors.append(f"{ew}: native: true needs a one-line rationale")
            if e.get("type") not in NATIVE_TYPES:
                errors.append(f"{ew}: native: true needs type: one of {sorted(NATIVE_TYPES)}")
            for k in ("also", "fallback"):
                if k in e:
                    errors.append(f"{ew}: {k}: is only meaningful with ecs:")
        for a in e.get("also") or []:
            _check_path(a, f"{ew} also", errors)
    for f in model["fields"]:
        if f not in seen:
            errors.append(f"{where}: CAR field '{f}' has no projection entry "
                          "(map it with ecs: or mark it native: true)")
    for target, users in primary.items():
        if len(users) < 2:
            continue
        primaries = [f for f, fallback in users if not fallback]
        if len(primaries) != 1:
            errors.append(f"{where}: target '{target}' is shared by {[f for f, _ in users]} — "
                          f"exactly one entry must be the primary (no fallback:), "
                          f"found {primaries or 'none'} (rules.fallback)")

    ed = doc.get("event_defaults") or {}
    if not isinstance(ed.get("category"), list) or not ed["category"]:
        errors.append(f"{where} event_defaults.category: required (a list)")
    tba = ed.get("type_by_action") or {}
    actions = set(model["actions"])
    for a in sorted(set(tba) - actions):
        errors.append(f"{where} event_defaults.type_by_action: '{a}' is not a car_action of {name}")
    for a in sorted(actions - set(tba)):
        errors.append(f"{where} event_defaults.type_by_action: car_action '{a}' has no event.type")
    for a, t in tba.items():
        if not isinstance(t, list) or not t:
            errors.append(f"{where} event_defaults.type_by_action.{a}: must be a non-empty list")
    for a, o in (ed.get("outcome_from_action") or {}).items():
        if a not in actions:
            errors.append(f"{where} event_defaults.outcome_from_action: '{a}' is not a car_action")
        if o not in OUTCOMES:
            errors.append(f"{where} event_defaults.outcome_from_action.{a}: '{o}' is not an event.outcome")
    off = ed.get("outcome_from_field")
    if off is not None and off not in model["fields"]:
        errors.append(f"{where} event_defaults.outcome_from_field: '{off}' is not a field of {name}")

    for i, d in enumerate(doc.get("derived") or []):
        dw = f"{where} derived[{i}]"
        src = (d or {}).get("from")
        if src not in model["fields"] and src not in header_union:
            errors.append(f"{dw}: from: '{src}' is neither a header nor a {name} field")
        _check_path((d or {}).get("ecs"), dw, errors)


def validate(car: dict[str, dict], conventions: dict, objects: dict[str, dict]) -> list[str]:
    """Every contract problem as a message; an empty list means the contract is in step."""
    errors: list[str] = []
    for o in sorted(set(car) - set(objects)):
        errors.append(f"objects/{o}.yml: missing — CAR object '{o}' has no projection")
    for o in sorted(set(objects) - set(car)):
        errors.append(f"objects/{o}.yml: orphan — there is no CAR object '{o}'")
    _validate_conventions(conventions, car, errors)
    header_union: set[str] = set()
    for m in car.values():
        header_union |= set(m["header"])
    for name in sorted(set(car) & set(objects)):
        _validate_object(name, car[name], objects[name], header_union, errors)
    return errors


def summary(car: dict[str, dict], conventions: dict, objects: dict[str, dict]) -> str:
    n_fields = sum(len(m["fields"]) for m in car.values())
    entries = [e for o in objects.values() for e in o.get("fields") or []]
    n_native = sum(1 for e in entries if e.get("native") is True)
    targets = {str(e["ecs"]) for e in entries if "ecs" in e}
    for e in entries:
        targets.update(e.get("also") or [])
    return (f"car-ecs projection OK: {len(car)} objects | {n_fields} CAR fields -> "
            f"{n_fields - n_native} ECS-mapped, {n_native} native (car.<object>.*) | "
            f"{len(targets)} distinct ECS targets | header: "
            f"{len(conventions.get('common_header') or {})} fields | "
            f"ECS {conventions.get('contract', {}).get('ecs_version', '?')}")


def main() -> int:
    car = load_car_model()
    if not car:
        print(f"no CAR objects found under {CAR_OBJECTS_DIR}", file=sys.stderr)
        return 1
    conventions, objects = load_contract()
    errors = validate(car, conventions, objects)
    if errors:
        print(f"car-ecs projection DRIFT: {len(errors)} problem(s)", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(summary(car, conventions, objects))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
