"""Plaso filesystem/file artefacts that were previously dropped → CAR file
(epic #86, Phase C coverage). Ingest as much as possible; nulls are fine.

- **macos:fseventsd:record** → file/modify. macOS FSEvents records a filesystem
  change to a path — a genuine file event we must NOT drop. The precise change
  (created/removed/renamed) is encoded in raw `flags`, but the authoritative
  on-disk change-bit constants are not confirmed here (only IsDirectory/
  EndOfTransaction were), so the action is the safe generic `modify` (a change
  occurred — no false create/delete claim) and the raw flags ride in native.
  The precise flags→action decode is captured in
  ../to-be-validated/plaso_fseventsd_flags.yml for validation against a real
  macOS image.
- **pe_coff:file** → file, WITHOUT a timestamp. A PE binary on disk: a real
  path AND the file's own sha256 + PE metadata (imphash / pe_type / export
  name / sections). Every stamp plaso dates the row by is INTERNAL to the
  binary — the header TimeDateStamp (plaso: 'Creation Time' — when it was
  compiled/linked) and the export / load-configuration table stamps ('Content
  Modification Time') — none is a host file event, so asserting file/create
  or file/modify at one put compile times on the timeline. Each row is a
  timestamp-less file record instead (off the timeline; in car.db for the
  hash/path pivots), its own stamp kept natively: `compile_time` on the
  header row, `pe_table_time` on a table-stamp row, nothing on the undated
  placeholder row ('Not a time'). One PE therefore yields up to three records
  differing only in native (duplicates are fine; nothing is faked).
  pe_coff:dll_import / pe_coff:resource (import-table entries, resource
  stamps) have no filesystem/CAR object → stay raw.
- **olecf:summary_info** → file. An OLE document (old Office .doc/.xls) with its
  authoring metadata (author/title/application/last-saved) + the doc's own
  sha256. Action from timestamp_desc. olecf:item (internal OLE streams) → raw.

Row identity (the spindle guid — spindle.yml, docs/CAR-Pipeline.md §7.1): the
FSEvents record (event_identifier + path — the journal's own record id); the
PE as a time-free ENTITY record (path + its own sha256 — every PE stamp is
internal to the binary, so the three rows of one PE share the identity and
differ only in native); the OLE document's path at the row's time.
"""
from __future__ import annotations

import re

from ..normalize import (basename, ext, first, host_label,  # noqa: F401
                         payload, regex1)
from ._common import R as _R, plaso_rec as _rec, spindle as _spindle


def _td(rec) -> str:
    return str(_rec(rec).get("timestamp_desc") or "")


_TD_CREATE = re.compile(r"(?i)creation|crtime|birth")
_TD_MODIFY = re.compile(r"(?i)modification|mtime|last written|content")
_TD_READ = re.compile(r"(?i)last access|atime|access time")

# strip a Plaso display_name volume prefix ("NTFS:\path", "GZIP:\path") -> "\path"
_PATH = first(regex1(_R("display_name"), r"^[^:]+:(.+)$"), _R("display_name"))


def _dt(rec, name):
    return _rec(rec).get("data_type") == name


# --- macos:fseventsd:record -------------------------------------------------
def fse_is_record(rec) -> bool:
    return _dt(rec, "macos:fseventsd:record")


# --- pe_coff:file (NOT pe_coff:dll_import / pe_coff:resource) ---------------
# which PE-INTERNAL stamp the row carries: the header TimeDateStamp (plaso's
# 'Creation Time' = the compile/link time), an export / load-configuration
# table stamp ('Content Modification Time'), or none (the 'Not a time'
# placeholder plaso emits for a PE it could not date at all)
def pe_is_compile_stamp(rec):
    return _dt(rec, "pe_coff:file") and bool(_TD_CREATE.search(_td(rec)))
def pe_is_table_stamp(rec):
    return _dt(rec, "pe_coff:file") and bool(_TD_MODIFY.search(_td(rec)))
def pe_is_file(rec):
    return _dt(rec, "pe_coff:file")


# --- olecf:summary_info -----------------------------------------------------
def ole_is_create(rec):
    return _dt(rec, "olecf:summary_info") and bool(_TD_CREATE.search(_td(rec)))
def ole_is_modify(rec):
    return _dt(rec, "olecf:summary_info") and not _TD_CREATE.search(_td(rec))


PREDICATES = {
    "fse_is_record": fse_is_record,
    "pe_is_compile_stamp": pe_is_compile_stamp, "pe_is_table_stamp": pe_is_table_stamp,
    "pe_is_file": pe_is_file,
    "ole_is_create": ole_is_create, "ole_is_modify": ole_is_modify,
}

_HOST = host_label(_R("image_hostname"))
# EWF/partition provenance — where on disk the record was found
_PROV = {"disk_id": _R("disk_id"), "volume_id": _R("volume_id"),
         "volume_offset": _R("volume_offset")}


def _pe_map(stamp):
    """The PE's file record. `stamp` names the native slot the row's own
    PE-internal timestamp is kept under (compile_time for the header stamp,
    pe_table_time for an export/load-config table stamp; None for the undated
    placeholder row). The record itself carries NO timestamp: a stamp baked
    into the binary is not a host file event — `create` says only that the
    file exists on disk (it was created, at an unknown time), never when."""
    native = {
        "data_type": _R("data_type"), "timestamp_desc": _R("timestamp_desc"),
        "imphash": _R("imphash"), "pe_type": _R("pe_type"),
        "export_dll_name": _R("export_dll_name"),
        "section_names": _R("section_names"), **_PROV,
    }
    if stamp:
        native[stamp] = "Timestamp"
    return {
        "object": "file", "action": "create", "ts": None,
        # the PE as an ENTITY (path + its own sha256; spindle.yml) — time-free,
        # so the header / table / placeholder rows of one PE share the identity
        "guid": _spindle("plaso_pecoff"), "host": _HOST,
        "props": {
            "file_path": _PATH,
            "file_name": basename(_PATH),
            "extension": ext(_PATH),
            # the PE file's own SHA-256 (the `pe` parser hashes the file)
            "sha256_hash": _R("sha256_hash"),
            "hostname": _R("image_hostname"),
        },
        "keep": [],
        "native_extract": native,
    }


def _ole_map(action):
    return {
        "object": "file", "action": action, "ts": "Timestamp",
        "guid": _spindle("plaso_olecf"), "host": _HOST,
        "props": {
            "file_path": _PATH,
            "file_name": basename(_PATH),
            "extension": ext(_PATH),
            "sha256_hash": _R("sha256_hash"),      # the document's own hash
            "owner": _R("author"),                 # doc author (best-effort)
            "hostname": _R("image_hostname"),
        },
        "keep": [],
        "native_extract": {
            "data_type": _R("data_type"), "timestamp_desc": _R("timestamp_desc"),
            "title": _R("title"), "author": _R("author"),
            "last_saved_by": _R("last_saved_by"), "application": _R("application"),
            "revision_number": _R("revision_number"),
            "subject": _R("subject"), "keywords": _R("keywords"),
            "comments": _R("comments"), "template": _R("template"),
            "number_of_pages": _R("number_of_pages"),
            "number_of_words": _R("number_of_words"),
            "number_of_characters": _R("number_of_characters"),
            "security_flags": _R("security"), "codepage": _R("codepage"),
            **_PROV,
        },
    }


MAPPINGS = {
    "plaso_fseventsd": {
        "variants": [
            ("fse_is_record", {
                "object": "file", "action": "modify", "ts": "Timestamp",
                # the journal's own record id + the path it names (spindle.yml)
                "guid": _spindle("plaso_fseventsd"), "host": _HOST,
                "props": {
                    "file_path": _R("path"),
                    "file_name": basename(_R("path")),
                    "extension": ext(_R("path")),
                    "hostname": _R("image_hostname"),
                },
                "keep": [],
                "native_extract": {
                    "data_type": _R("data_type"), "flags": _R("flags"),
                    "event_identifier": _R("event_identifier"),
                    "node_identifier": _R("node_identifier"),
                    "timestamp_desc": _R("timestamp_desc"),
                    "artefact_sha256": _R("sha256_hash"),   # the fsevents DB hash
                    "disk_id": _R("disk_id"), "volume_id": _R("volume_id"),
                },
            }),
        ],
        "default": None,
    },
    "plaso_pecoff": {
        "variants": [
            ("pe_is_compile_stamp", _pe_map("compile_time")),
            ("pe_is_table_stamp", _pe_map("pe_table_time")),
            # the undated placeholder: still a real PE file on disk -> record
            ("pe_is_file", _pe_map(None)),
        ],
        "default": None,   # pe_coff:dll_import / pe_coff:resource -> raw
    },
    "plaso_olecf": {
        "variants": [
            ("ole_is_create", _ole_map("create")),
            ("ole_is_modify", _ole_map("modify")),
        ],
        "default": None,   # olecf:item -> raw
    },
}
