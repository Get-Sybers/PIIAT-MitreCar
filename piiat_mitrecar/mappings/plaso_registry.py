"""Plaso registry artefacts → CAR registry (epic #86, Phase C coverage).

A disk image's registry hives parse into a large family of `windows:registry:*`
data_types (service, run, winlogon, usb, bagmru, typedurls, sam_users,
key_value, …). `plaso_exec_winreg` already claims the ones that evidence
EXECUTION (amcache/userassist/bam/appcompatcache) as process events; this map
claims EVERY registry data_type as a **registry** event so the on-disk registry
state is ingested as CAR — the goal is to populate as many CAR entries as
possible (null/duplicate properties are fine) for the end-stage cascade to
relate. A registry snapshot is the KEY as it exists at its LastWrite time, so
the canonical action is **key_edit** (the same discipline as the RECmd map).

Relationship joins are NOT done here — this only NORMALISES and surfaces the
join keys (service `name`, run/winlogon `command`/`image_path`, hive-owner SID)
into `_native` for the enrichment end-stage.

Values live in a `values` LIST that the marker set cannot index, so `value`/
`data`/`type` stay in `_native.values`; `key`/`hive` are the canonical columns.
Runs alongside `plaso_exec_winreg` on the same L2tWinreg route — a record that
is both an execution artefact and a registry key legitimately yields both a
process row and a registry row (duplicate views are intended).
"""
from __future__ import annotations

from ..normalize import host_label, payload, regex1  # noqa: F401
from ._common import R as _R


def plaso_is_registry(rec) -> bool:
    dt = str((rec.get("Record") or {}).get("data_type") or "")
    # the shell-item rows that also arrive on L2tWinreg are NOT registry
    return dt.startswith("windows:registry:")


PREDICATES = {"plaso_is_registry": plaso_is_registry}

_HOST = host_label(_R("image_hostname"))

MAPPINGS = {
    "plaso_registry": {
        "variants": [
            ("plaso_is_registry", {
                "object": "registry", "action": "key_edit", "ts": "Timestamp",
                "guid": {"none": True}, "host": _HOST,
                "props": {
                    "key": _R("key_path"),
                    # the hive file the key came from (Plaso's display_name)
                    "hive": _R("display_name"),
                    # present on service rows (the svchost/binary) — null else
                    "image_path": _R("image_path"),
                    "hostname": _R("image_hostname"),
                },
                "keep": [],
                # surface everything a registry data_type may carry — absent
                # fields resolve null (that is fine); the values LIST holds the
                # value/data/type the marker set cannot flatten. join keys for
                # the end-stage: name (service), command/entries (autostart),
                # username/account_rid (sam), serial/vendor (usb).
                "native_extract": {
                    "data_type": _R("data_type"),
                    "values": _R("values"),
                    "name": _R("name"),
                    "object_name": _R("object_name"),
                    # service (7045-equivalent config)
                    "start_type": _R("start_type"),
                    "service_type": _R("service_type"),
                    "service_dll": _R("service_dll"),
                    "error_control": _R("error_control"),
                    # autostart (run / winlogon)
                    "command": _R("command"),
                    "application": _R("application"),
                    "handler": _R("handler"),
                    "trigger": _R("trigger"),
                    "entries": _R("entries"),
                    # accounts (sam_users)
                    "username": _R("username"),
                    "fullname": _R("fullname"),
                    "comments": _R("comments"),
                    "account_rid": _R("account_rid"),
                    "login_count": _R("login_count"),
                    # removable media (usb / usbstor)
                    "serial": _R("serial"),
                    "vendor": _R("vendor"),
                    "product": _R("product"),
                    "subkey_name": _R("subkey_name"),
                    "device_display_name": _R("device_display_name"),
                    "device_type": _R("device_type"),
                    "revision": _R("revision"),
                    # mounted drives / shares (mount_points2 / network_drive)
                    "server_name": _R("server_name"),
                    "share_name": _R("share_name"),
                    "source_type": _R("source_type"),
                    "drive_letter": _R("drive_letter"),
                    # OS install / timezone / IE zones
                    "product_name": _R("product_name"),
                    "build_number": _R("build_number"),
                    "service_pack": _R("service_pack"),
                    "version": _R("version"),
                    "owner": _R("owner"),
                    "configuration": _R("configuration"),
                    "settings": _R("settings"),
                    # hive-owner SID for the end-stage user attribution
                    "hive_user_sid": regex1(_R("display_name"),
                                            r"(S-1-5-21-[0-9-]+)"),
                },
            }),
        ],
        "default": None,
    },
}
