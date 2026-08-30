"""JLECmd (jump lists) → per-entry records (epic #86 Phase D).

A JLECmd AutomaticDestinations JSON record describes ONE jump-list file: the
owning application (AppId + Description) and a LIST of DestListEntries — each
entry the record of a file the user interacted with through that application.
The engine maps one record to one event, so this adapter flattens each record
into per-entry records carrying the app context, and converts the .NET
`/Date(ms)/` timestamps to ISO-8601.

Jump lists are OLECF containers, which Plaso renders opaquely (routed to [] in
the l2t lane) — JLECmd is the parser that actually interprets them, so this is
NEW artefact coverage, not a duplicate of an l2t map.
"""
from __future__ import annotations

import datetime
import re

_DOTNET_DATE = re.compile(r"/Date\((-?\d+)\)/")


def dotnet_date(v):
    """'/Date(1522187139502)/' (ms since epoch) -> UTC ISO-8601, else None."""
    if not v:
        return None
    m = _DOTNET_DATE.search(str(v))
    if not m:
        return str(v)                      # already rendered — pass through
    try:
        ms = int(m.group(1))
        return datetime.datetime.fromtimestamp(
            ms / 1000.0, datetime.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def flatten(record: dict):
    """One JLECmd AutomaticDestinations record -> one flat record per
    DestListEntry, app context merged in. Records without entries yield
    nothing (an empty jump list asserts no file interaction)."""
    app = record.get("AppId") or {}
    for e in record.get("DestListEntries") or []:
        if not isinstance(e, dict):
            continue
        yield {
            "Path": e.get("Path"),
            "LastModified": dotnet_date(e.get("LastModified")),
            "CreatedOn": dotnet_date(e.get("CreatedOn")),
            "Hostname": e.get("Hostname"),
            "InteractionCount": e.get("InteractionCount"),
            "EntryNumber": e.get("EntryNumber"),
            "MRUPosition": e.get("MRUPosition"),
            "Pinned": e.get("Pinned"),
            "MacAddress": e.get("MacAddress"),
            "VolumeDroid": e.get("VolumeDroid"),
            "AppId": app.get("AppId"),
            "AppDescription": app.get("Description"),
            "SourceFile": record.get("SourceFile"),
        }
