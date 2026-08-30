"""RECmd batch output → CAR registry (un-parked).

RECmd (the hardened dfir/recmd container) runs a curated batch (e.g. Kroll)
over extracted hives and emits JSONL (``--json``): one record per registry
VALUE it matched, with the Kroll categorisation. Field shapes verified against
the real LoneWolf hives (7,493 records).

- Each non-deleted record → **registry/value_edit**: the value as it exists,
  timestamped by its KEY's LastWriteTimestamp — the key's last write is the
  nearest recorded time for the value's content (the same convention the
  memory registry map uses; which value changed last is not per-value
  attributable, and that caveat rides with the action).
- ``Deleted: true`` records (recovered from unallocated) stay RAW: the
  deletion happened but its TIME is unknowable from the record —
  ``remove`` at the key's last-write would assert a time the evidence does
  not contain.
- `user` is recovered from a per-user hive path (Users/<name>/...) — the
  hive-path convention; system hives yield null.
- The Kroll batch's Category/Description/Comment are evidence-grade
  context and ride in native.
"""
from __future__ import annotations

from ..normalize import basename, first, payload, regex1, replace  # noqa: F401


def recmd_is_value_record(rec) -> bool:
    """A live (non-deleted) batch record with a real key path."""
    return bool(rec.get("KeyPath")) and rec.get("Deleted") is not True


PREDICATES = {"recmd_is_value_record": recmd_is_value_record}

MAPPINGS = {
    "recmd_batch": {
        "variants": [
            ("recmd_is_value_record", {
                "object": "registry", "action": "value_edit",
                # RECmd renders '2018-04-02 01:15:16.9540407' — normalised to
                # ISO 'T' form so timestamps sort with every other source
                "ts": replace("LastWriteTimestamp", " ", "T"),
                "guid": {"fields": ["HivePath", "KeyPath", "ValueName"]},
                "props": {
                    "hive": "HiveType",
                    "key": "KeyPath",
                    "value": "ValueName",
                    "data": first("ValueData", "ValueData2", "ValueData3"),
                    # model registry.type — RECmd's ValueType (RegSz/RegDword/…);
                    # promoted from native to the canonical column
                    "type": "ValueType",
                    # for a value snapshot the current content IS its content —
                    # parity with the Sysmon registry map (data + new_content)
                    "new_content": first("ValueData", "ValueData2", "ValueData3"),
                    # a per-user hive names its user (hive-path convention)
                    "user": regex1("HivePath", r"[/\\]Users[/\\]([^/\\]+)[/\\]"),
                },
                "keep": ["HivePath", "HiveType", "Category", "Description",
                         "Comment", "ValueType", "Deleted", "Recursive"],
            }),
        ],
        "default": None,   # Deleted records: the deletion time is unknowable -> raw
    },
}
