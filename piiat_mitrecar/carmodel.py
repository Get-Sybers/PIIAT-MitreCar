"""The MITRE CAR object model — the 13 canonical CAR objects.

Reconstructed LIVE from the pinned car submodule
(third_party/car/data_model/*.yaml) via build_data_model — no committed copy, so
the model is always the pinned source and cannot drift. The CAR + ATT&CK
SUPERSET is a separate model (build_data_model.build_superset), used by the
superset store. A model refresh is a submodule-pin change.
"""
from __future__ import annotations

_cache: dict | None = None


def load() -> dict[str, dict]:
    """{object_name: {"fields": [...], "actions": [...]}} from the pinned car submodule."""
    global _cache
    if _cache is None:
        from . import build_data_model
        doc = build_data_model.build_car()
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
