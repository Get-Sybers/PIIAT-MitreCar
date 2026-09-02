"""Shared helpers + constants for the artefact maps.

De-duplicates the per-file EvtxECmd and Plaso boilerplate that was copy-pasted
across the map modules. Import aliased to the map's local name, e.g.
``from ._common import R as _R, plaso_rec as _rec``.
"""
from __future__ import annotations

import json

from ..normalize import host_label, payload, regex1


# --- Plaso (log2timeline) wrapped records -----------------------------------

def R(key):
    """A field out of the wrapped row's flat plaso ``Record`` dict (marker)."""
    return payload(key, "Record")


def plaso_rec(rec) -> dict:
    """The plaso ``Record`` dict off a wrapped row (empty dict when absent)."""
    r = rec.get("Record")
    return r if isinstance(r, dict) else {}


PLASO_HOST = host_label(R("image_hostname"))

def spindle(name: str) -> dict:
    """A disk-image row's guid spec: the MINTED spindle id, by registry entry.
    WHICH fields identify the row is a rule in ``piiat_mitrecar/spindle.yml``
    (the entry `name` — the map key, or ``<map>/<variant>``), never spelled
    here; the engine mints ``uuid5(SPINDLE_NS, canonical_json({"_obj":
    <object>, name: value, ...}))`` from the event's own values (ids.py — the
    recipe stix.py mints §2.9 ids with) and falls back to the registry's
    positional (SourceImage, RecordId) identity when a component is blank.
    spindle.verify_registry holds map and registry in step."""
    return {"spindle": name}


# --- EvtxECmd (raw Windows event logs) --------------------------------------

EVTX_HOST = host_label("Computer")
EVTX_FQDN = regex1("Computer", r"^([^.]+\..+)$")
EVTX_KEEP = ["EventId", "EventRecordId", "Channel", "Computer", "Provider",
             "Payload", "SourceFile", "MapDescription", "UserName"]
# a stable per-record identity (unique per channel within one .evtx export)
EVTX_RECORD_GUID = {"fields": ["Computer", "Channel", "EventRecordId"]}


def evtx_payload_field(rec, name: str) -> str:
    """An EventData/Data @Name value from the EvtxECmd Payload blob — for GATING
    (the map itself resolves values via the payload() marker)."""
    raw = rec.get("Payload")
    if not raw:
        return ""
    try:
        data = raw if isinstance(raw, dict) else json.loads(raw)
        for d in (data.get("EventData") or {}).get("Data") or []:
            if isinstance(d, dict) and d.get("@Name") == name:
                return str(d.get("#text") or "")
    except (ValueError, AttributeError, TypeError):
        pass
    return ""
