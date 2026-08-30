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
- **pe_coff:file** → file. A PE binary on disk: carries a real path AND the
  file's own sha256 + PE metadata (imphash / pe_type / export name / sections).
  Action from timestamp_desc (Plaso surfaces the PE header time). Note: that
  time is the PE header timestamp, not necessarily the filesystem MAC time —
  kept honest via timestamp_desc in native. pe_coff:dll_import (static import
  table entries) has no filesystem/CAR object → stays raw.
- **olecf:summary_info** → file. An OLE document (old Office .doc/.xls) with its
  authoring metadata (author/title/application/last-saved) + the doc's own
  sha256. Action from timestamp_desc. olecf:item (internal OLE streams) → raw.
"""
from __future__ import annotations

import re

from ..normalize import (basename, ext, first, host_label,  # noqa: F401
                         payload, regex1)
from ._common import R as _R, plaso_rec as _rec


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


# --- pe_coff:file (NOT pe_coff:dll_import) ----------------------------------
def pe_is_file_create(rec):
    return _dt(rec, "pe_coff:file") and bool(_TD_CREATE.search(_td(rec)))
def pe_is_file_modify(rec):
    return _dt(rec, "pe_coff:file") and bool(_TD_MODIFY.search(_td(rec)))
def pe_is_file_other(rec):
    return _dt(rec, "pe_coff:file") and not (_TD_CREATE.search(_td(rec)) or _TD_MODIFY.search(_td(rec)))


# --- olecf:summary_info -----------------------------------------------------
def ole_is_create(rec):
    return _dt(rec, "olecf:summary_info") and bool(_TD_CREATE.search(_td(rec)))
def ole_is_modify(rec):
    return _dt(rec, "olecf:summary_info") and not _TD_CREATE.search(_td(rec))


PREDICATES = {
    "fse_is_record": fse_is_record,
    "pe_is_file_create": pe_is_file_create, "pe_is_file_modify": pe_is_file_modify,
    "pe_is_file_other": pe_is_file_other,
    "ole_is_create": ole_is_create, "ole_is_modify": ole_is_modify,
}

_HOST = host_label(_R("image_hostname"))
# EWF/partition provenance — where on disk the record was found
_PROV = {"disk_id": _R("disk_id"), "volume_id": _R("volume_id"),
         "volume_offset": _R("volume_offset")}


def _pe_map(action):
    return {
        "object": "file", "action": action, "ts": "Timestamp",
        "guid": {"none": True}, "host": _HOST,
        "props": {
            "file_path": _PATH,
            "file_name": basename(_PATH),
            "extension": ext(_PATH),
            # the PE file's own SHA-256 (the `pe` parser hashes the file)
            "sha256_hash": _R("sha256_hash"),
            "hostname": _R("image_hostname"),
        },
        "keep": [],
        "native_extract": {
            "data_type": _R("data_type"), "timestamp_desc": _R("timestamp_desc"),
            "imphash": _R("imphash"), "pe_type": _R("pe_type"),
            "export_dll_name": _R("export_dll_name"),
            "section_names": _R("section_names"), **_PROV,
        },
    }


def _ole_map(action):
    return {
        "object": "file", "action": action, "ts": "Timestamp",
        "guid": {"none": True}, "host": _HOST,
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
                "guid": {"none": True}, "host": _HOST,
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
            ("pe_is_file_create", _pe_map("create")),
            ("pe_is_file_modify", _pe_map("modify")),
            # any other timestamp_desc: still a real PE file on disk -> modify
            ("pe_is_file_other", _pe_map("modify")),
        ],
        "default": None,   # pe_coff:dll_import -> raw
    },
    "plaso_olecf": {
        "variants": [
            ("ole_is_create", _ole_map("create")),
            ("ole_is_modify", _ole_map("modify")),
        ],
        "default": None,   # olecf:item -> raw
    },
}
