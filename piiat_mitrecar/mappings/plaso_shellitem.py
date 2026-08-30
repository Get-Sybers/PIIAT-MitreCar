"""Plaso shell items → CAR file (epic #86, Phase C coverage).

`windows:shell_item:file_entry` records are the shell-item entries embedded in
LNK targets, shellbags (BagMRU) and MRU lists — each names a file/folder the
user navigated to, with its recorded MAC timestamps. That is file-access
evidence, so each timestamped row → **file**, action by `timestamp_desc` exactly
like the LNK map (Creation→create, Modification→modify, Last Access→read).

The same data_type arrives via TWO parser chains (LNK → L2tLnk, shellbags →
L2tWinreg), so this map is routed on BOTH; it is gated strictly on the shell
data_type so it never touches the LNK-link or registry rows on those routes.
Normalisation only — no joins (the file_path → on-disk file corroboration is an
end-stage cascade concern).
"""
from __future__ import annotations

import re

from ..normalize import (basename, ext, first, host_label,  # noqa: F401
                         regex1, unescape_backslashes)


def _R(key):
    from ..normalize import payload
    return payload(key, "Record")


def _rec(rec) -> dict:
    return rec.get("Record") or {}


def _td(rec) -> str:
    return str(_rec(rec).get("timestamp_desc") or "")


_TD_CREATE = re.compile(r"(?i)creation|crtime|birth")
_TD_MODIFY = re.compile(r"(?i)modification|mtime")
_TD_READ = re.compile(r"(?i)last access|atime|access time")

_DT = "windows:shell_item:file_entry"


def plasoshell_create(rec) -> bool:
    return _rec(rec).get("data_type") == _DT and bool(_TD_CREATE.search(_td(rec)))


def plasoshell_modify(rec) -> bool:
    return _rec(rec).get("data_type") == _DT and bool(_TD_MODIFY.search(_td(rec)))


def plasoshell_read(rec) -> bool:
    return _rec(rec).get("data_type") == _DT and bool(_TD_READ.search(_td(rec)))


PREDICATES = {
    "plasoshell_create": plasoshell_create,
    "plasoshell_modify": plasoshell_modify,
    "plasoshell_read": plasoshell_read,
}

# the navigated target: shell_item_path (strip the "<My Computer> " prefix) then
# long_name / name
_PATH = unescape_backslashes(first(
    regex1(_R("shell_item_path"), r"^(?:<[^>]+>\s*)?(.+)$"),
    _R("long_name"), _R("name")))
_HOST = host_label(_R("image_hostname"))


def _shell_map(action):
    props = {
        "file_path": _PATH,
        "file_name": basename(_PATH),
        "extension": ext(_PATH),
        "hostname": _R("image_hostname"),
    }
    if action == "create":
        props["creation_time"] = "Timestamp"
    return {
        "object": "file", "action": action, "ts": "Timestamp",
        "guid": {"none": True}, "host": _HOST,
        "props": props,
        "keep": [],
        "native_extract": {
            "data_type": _R("data_type"),
            "origin": _R("origin"),          # the .lnk / hive it came from
            "shell_item_path": _R("shell_item_path"),
            "long_name": _R("long_name"),
            "name": _R("name"),
        },
    }


MAPPINGS = {
    "plaso_shellitem": {
        "variants": [
            ("plasoshell_create", _shell_map("create")),
            ("plasoshell_modify", _shell_map("modify")),
            ("plasoshell_read", _shell_map("read")),
        ],
        "default": None,
    },
}
