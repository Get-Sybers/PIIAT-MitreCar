"""Deterministic identity minting — the ONE recipe every minted id derives from.

STIX 2.1 §2.9 mints a content SCO id as UUIDv5 over a namespace and the
canonical JSON (sorted keys, no whitespace, UTF-8) of the ID-contributing
properties. stix.py has always minted its global ids that way; this module
lifts the recipe out so the CAR row identity — the `guid` a disk-image row
carries — is minted the SAME way, under its own namespace (the "spindle" id):

    guid = uuid5(SPINDLE_NS, canonical_json({"_obj": <car_object>,
                                             <name>: <value>, ...}))

The contributing dict is the CAR object plus the record's stable-identity
fields, keyed BY NAME. The names give domain separation — a `file_reference`
and a `usn` with the same value cannot collide, nor can a `file` and a
`registry` identity — and what is deliberately NOT in the hash is the source,
parser or artefact name: that is exactly what must stay invariant so two tools
parsing the same image mint the same guid for the same record.

Values contribute in their STRING rendering: a parser that emits the NTFS file
reference as 843 and one that emits "843" must agree, and §2.9's type-faithful
JSON would keep them apart. A blank value never contributes — an identity with
a blank component is incomplete, and the caller (normalize._spindle) falls back
to the record's positional identity within its source.
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

# the key carrying the CAR object type in a spindle identity
OBJECT_KEY = "_obj"


def canonical_json(props: dict) -> str:
    """The ID-contributing properties as §2.9 canonical JSON (sorted keys, no
    whitespace, UTF-8) — RFC 8785 for the string values this pipeline contributes."""
    return json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _render(value) -> str:
    """A contributing value in its string rendering (a structured value as its
    canonical JSON text) — so differing scalar renderings of one value agree."""
    if isinstance(value, (list, tuple, dict)):
        return canonical_json(list(value) if isinstance(value, tuple) else value)
    return str(value)


def spindle_key(obj: str, identity: dict) -> dict:
    """The contributing dict of a spindle id: {"_obj": obj, <name>: <rendered
    value>, ...} — the readable identity tuple a row keeps in native.spindle_key."""
    key = {OBJECT_KEY: obj}
    for name, value in identity.items():
        if value is None:
            raise ValueError(f"spindle identity {name!r} is missing for {obj!r}")
        key[name] = _render(value)
    return key


def spindle_id(obj: str, identity: dict) -> str:
    """The spindle id: uuid5(SPINDLE_NS, canonical_json(spindle_key(obj, identity)))."""
    return str(uuid.uuid5(SPINDLE_NS, canonical_json(spindle_key(obj, identity))))
