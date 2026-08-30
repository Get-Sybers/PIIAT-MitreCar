"""JLECmd jump-list destination entries → CAR file (epic #86 Phase D).

Consumes the FLATTENED per-entry records the jlecmd adapter emits (one per
DestListEntry, app context merged). A destination entry is the record that a
user OPENED the file through the owning application — **file/read**, timed at
the entry's LastModified (the last interaction; the first interaction
CreatedOn and the InteractionCount ride in native). The jump list's Hostname
is the recording host. Verified against real LoneWolf jump lists.

CustomDestinations files have a different, pin-centric structure with no
per-entry interaction times — routed to [] explicitly (raw), not mapped.
"""
from __future__ import annotations

from ..normalize import basename, ext, first  # noqa: F401


def jl_is_dest_entry(rec) -> bool:
    return bool(rec.get("Path"))


PREDICATES = {"jl_is_dest_entry": jl_is_dest_entry}

MAPPINGS = {
    "jlecmd_dest": {
        "variants": [
            ("jl_is_dest_entry", {
                "object": "file", "action": "read", "ts": "LastModified",
                # a stable per-entry identity within the source
                "guid": {"fields": ["SourceFile", "EntryNumber"]},
                "host": "Hostname",
                "props": {
                    "file_path": "Path",
                    "file_name": basename("Path"),
                    "extension": ext("Path"),
                    "hostname": "Hostname",
                },
                "keep": ["AppId", "AppDescription", "InteractionCount",
                         "CreatedOn", "EntryNumber", "MRUPosition", "Pinned",
                         "MacAddress", "VolumeDroid", "SourceFile"],
            }),
        ],
        "default": None,
    },
}
