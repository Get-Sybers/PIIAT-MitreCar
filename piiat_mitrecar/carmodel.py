"""The MITRE CAR data model — the single source of truth for the 13 objects.

Single source of truth for which objects exist and which actions/properties each
has. Same loader shape as PIIAT-Mem's carmodel, pointed at the repo-root file
(shared by the KQL layer and this normalizer). A model refresh is a data change,
not a code change.
"""
from __future__ import annotations

import json
import os

# The model ships WITH the package — a verified exact match to the authoritative
# mitre-attack/car repo (vendored as the third_party/car submodule; see
# docs/CAR-Pipeline.md). A model refresh is a data change, not a code change.
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "car_data_model.json")

_cache: dict | None = None


def load() -> dict[str, dict]:
    """{object_name: {"fields": [...], "actions": [...]}} from the model."""
    global _cache
    if _cache is None:
        with open(MODEL_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
        out = {}
        for o in doc["objects"]:
            name = o["name"][0] if isinstance(o["name"], list) else o["name"]
            out[name] = {"fields": list(o["fields"]), "actions": list(o["actions"])}
        _cache = out
    return _cache


def objects() -> list[str]:
    return sorted(load())


def fields(obj: str) -> list[str]:
    return load()[obj]["fields"]


def actions(obj: str) -> list[str]:
    return load()[obj]["actions"]


def all_fields() -> list[str]:
    out: set[str] = set()
    for spec in load().values():
        out.update(spec["fields"])
    return sorted(out)
