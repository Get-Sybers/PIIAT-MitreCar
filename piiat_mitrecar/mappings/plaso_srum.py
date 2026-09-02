"""Plaso SRUM (System Resource Usage Monitor) → CAR (un-parked).

SRUM is parsed with **Plaso's `esedb/srum` parser** — SrumECmd itself cannot
run on Linux (it P/Invokes the Windows-only ESE native libraries; verified on
the real tool), and the artefact≠processor rule means the SRUM *artefact* maps
the same regardless of parser. Field shapes verified against the real LoneWolf
SRUDB.dat (17,928 rows).

- **windows:srum:network_usage → flow/message**: an HOURLY AGGREGATE of bytes
  an application moved on an interface — application + user attribution with
  in_bytes/out_bytes. `message` is the honest action ("content sent over the
  connection"); there are no endpoints (no ips/ports — SRUM records the
  interface, kept native) and the timestamp is the aggregate's Recorded Time.
- **windows:srum:application_usage → process/create**: execution evidence
  (the prefetch precedent) — the application demonstrably ran in the recorded
  hour; resource counters stay native.
- windows:srum:network_connectivity: interface connect telemetry whose fields
  are SRUM-internal indexes — no honest CAR object; stays raw.

`application` is either a kernel device path
(\\Device\\HarddiskVolume4\\...\\LogonUI.exe) or a bare service name
(DiagTrack); `user_identifier` is a SID *or* an SRUM-internal index — the sid
column is gated on the S-1- form (an index is not an identity).

Row identity (the spindle guid, docs/CAR-Pipeline.md §7): the aggregate's own
key — application + user (+ interface for network usage) at its recorded time.
"""
from __future__ import annotations

import re

from ..normalize import basename, ext, first, payload, regex1  # noqa: F401
from ._common import R as _r, spindle as _spindle


def _dt(rec) -> str:
    r = rec.get("Record")
    return str((r or {}).get("data_type") or "")


def srum_is_network_usage(rec) -> bool:
    return _dt(rec) == "windows:srum:network_usage"


def srum_is_application_usage(rec) -> bool:
    return _dt(rec) == "windows:srum:application_usage"


PREDICATES = {
    "srum_is_network_usage": srum_is_network_usage,
    "srum_is_application_usage": srum_is_application_usage,
}

# a real SID, never an SRUM-internal numeric index
_SID = regex1(_r("user_identifier"), r"^(S-1-[0-9-]+)$")
# a device path carries the executable; a bare name is only the exe
_IMAGE = regex1(_r("application"), r"^(\\Device\\.+)$")
_EXE = first(basename(_IMAGE), _r("application"))

_KEEP_NATIVE = {
    "data_type": _r("data_type"),
    "identifier": _r("identifier"),
    "interface_luid": _r("interface_luid"),
    "user_identifier": _r("user_identifier"),
    # the raw application string (device path OR bare service name) — exe /
    # image_path split it; the row identity keys on it whole (spindle.yml)
    "application": _r("application"),
}

MAPPINGS = {
    "l2t_srum": {
        "variants": [
            ("srum_is_network_usage", {
                "object": "flow", "action": "message", "ts": "Timestamp",
                "guid": _spindle("l2t_srum/network_usage"),
                "props": {
                    "exe": _EXE,
                    "image_path": _IMAGE,
                    "in_bytes": _r("bytes_received"),
                    "out_bytes": _r("bytes_sent"),
                    "uid": _SID,
                },
                "keep": [], "native_extract": _KEEP_NATIVE,
            }),
            ("srum_is_application_usage", {
                "object": "process", "action": "create", "ts": "Timestamp",
                "guid": _spindle("l2t_srum/application_usage"),
                "props": {
                    "exe": _EXE,
                    "image_path": _IMAGE,
                    "sid": _SID,
                },
                "keep": [],
                "native_extract": dict(_KEEP_NATIVE,
                                       foreground_cycle_time=_r("foreground_cycle_time"),
                                       foreground_bytes_read=_r("foreground_bytes_read"),
                                       foreground_bytes_written=_r("foreground_bytes_written"),
                                       face_time=_r("face_time")),
            }),
            # network_connectivity: SRUM-internal indexes only -> raw
        ],
        "default": None,
    },
}
