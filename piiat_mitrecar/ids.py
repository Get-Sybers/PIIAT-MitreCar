"""Deterministic identity minting — the ONE recipe every minted id derives from.

STIX 2.1 §2.9 mints a content SCO id as UUIDv5 over a namespace and the
canonical JSON (sorted keys, no whitespace, UTF-8) of the ID-contributing
properties. stix.py has always minted its global ids that way; this module
lifts the recipe out so the CAR row identity — the `guid` a disk-image row
carries — is minted the SAME way, under its own namespace (the "spindle" id):

    guid = uuid5(SPINDLE_NS, canonical_json({"_obj": <car_object>, "_v": <version>,
                                             <name>: <value>, ...}))

The contributing dict (the identity KEY) is the CAR object, the identity-key
VERSION of the registry entry that named the fields, and the record's
stable-identity fields keyed BY NAME. The names give domain separation — a
`file_reference` and a `usn` with the same value cannot collide, nor can a
`file` and a `registry` identity — the version re-mints every guid of an entry
when what identifies its rows changes (the change protocol), and what is
deliberately NOT in the key is the source, parser or artefact name: that is
exactly what must stay invariant so two tools parsing the same image mint the
same guid for the same record.

Values contribute in their STRING rendering (`rendering: str`, the registry's
global rule): a parser that emits the NTFS file reference as 843 and one that
emits "843" must agree, and §2.9's type-faithful JSON would keep them apart.
A field may override that with `normalize: json` (type-faithful canonical JSON
text). The two reserved keys `_obj` (str) and `_v` (int) are exempt. A blank
value never contributes — an identity with a blank component is incomplete,
and the caller (normalize._spindle) falls back to the record's positional
identity within its source.

`mint()` is the single seam: the engine, the golden renderer and a re-mint all
go through it, and `guid_of(key)` re-derives a guid from a row's own key.
"""
from __future__ import annotations

import json
import uuid

# STIX 2.1 §2.9: the namespace every spec-deterministic SCO id is minted under
STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# the project namespace: case-scoped STIX ids hang off it (case_ns = uuid5(CAR_NS, "case|<case>"))
CAR_NS_URL = "https://github.com/Get-Sybers/PIIAT-MitreCar/stix"
CAR_NS = uuid.uuid5(uuid.NAMESPACE_URL, CAR_NS_URL)
# the CAR row-identity namespace, one level under CAR_NS: a row guid can never
# coincide with a case-scoped id or a §2.9 global id. The registry
# (spindle.yml) documents the same recipe; spindle.verify_registry holds the two in step.
SPINDLE_LABEL = "spindle"
SPINDLE_NS = uuid.uuid5(CAR_NS, SPINDLE_LABEL)

# the reserved keys of an identity key: the CAR object and the identity-key version
OBJECT_KEY, VERSION_KEY = "_obj", "_v"
RESERVED_KEYS = (OBJECT_KEY, VERSION_KEY)
# the value renderings: the global default and the per-field override
RENDER_STR, RENDER_JSON = "str", "json"
RENDERINGS = (RENDER_STR, RENDER_JSON)


def canonical_json(props: dict) -> str:
    """The ID-contributing properties as §2.9 canonical JSON (sorted keys, no
    whitespace, UTF-8) — RFC 8785 for the string values this pipeline contributes."""
    return json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def render(value, mode: str = RENDER_STR) -> str:
    """A contributing value as it enters the key: `str` — a scalar in its
    string form, a structured value as its canonical JSON text (so differing
    scalar renderings of one value agree); `json` — type-faithful canonical
    JSON text (a string stays quoted, an int stays bare)."""
    if mode == RENDER_JSON:
        return canonical_json(list(value) if isinstance(value, tuple) else value)
    if mode != RENDER_STR:
        raise ValueError(f"unknown rendering {mode!r}: one of {RENDERINGS}")
    if isinstance(value, (list, tuple, dict)):
        return canonical_json(list(value) if isinstance(value, tuple) else value)
    return str(value)


def guid_of(key: dict) -> str:
    """The guid of an identity key AS RENDERED — what a row's native.spindle_key
    re-mints to; the invariant every spindle row satisfies."""
    return str(uuid.uuid5(SPINDLE_NS, canonical_json(key)))


def mint(obj: str, identity: dict, version: int, normalize: dict | None = None) -> tuple[str, dict]:
    """THE seam: (guid, key) for a CAR object, its raw identity values keyed by
    name, and the identity-key version of the registry entry that named them.
    `normalize` maps a name to a rendering override (`json`); everything else
    renders `str`. A missing value is a programming error here — the caller
    decides the positional fallback before minting."""
    key = {OBJECT_KEY: obj, VERSION_KEY: int(version)}
    modes = normalize or {}
    for name, value in identity.items():
        if name in RESERVED_KEYS:
            raise ValueError(f"identity name {name!r} is reserved")
        if value is None:
            raise ValueError(f"spindle identity {name!r} is missing for {obj!r}")
        key[name] = render(value, modes.get(name, RENDER_STR))
    return guid_of(key), key
