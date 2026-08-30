"""Windows Security-audit event logs → CAR (epic #86, Phase C coverage).

The object-access / detailed-file-share / filtering-platform / process-exit /
registry-audit families. These require the matching audit subcategory to be
ENABLED (auditpol), so they are absent from the current corpora — the maps are
therefore SCHEMA-GROUNDED (documented Windows EventData @Name fields) rather
than sample-verified, and are INERT until such an event appears (each variant is
gated on Channel+EventId). Action DECISIONS are keyed on the STABLE numeric
AccessMask bits (not the %%-token strings, which depend on EvtxECmd's message
resolution), so the mapping is robust once real records arrive.

Relationship joins are NOT done here — only the owning-process key (ProcessId /
ProcessID) is surfaced for the enrichment end-stage.

- 4663 object-access (ObjectType=File) → file read/write/delete by AccessMask
  (DELETE 0x10000 → delete; WriteData/AppendData 0x2|0x4 → write; ReadData 0x1
  → read; otherwise raw). 4660 object-deleted → file/delete (path lives in the
  paired 4663 via HandleId — surfaced native, path honest-null). 4670
  permissions-changed (File) → file/acl_modify.
- 4657 registry value modified → registry add/value_edit/remove by OperationType.
- 4689 process exit → process/terminate (pairs with 4688 in the end-stage).
- 5140/5145 file share access → file read/write by AccessMask.
- 5156/5157 WFP connection allowed/blocked → flow start/message. 5158 bind →
  socket/bind.
- 5058 crypto key-FILE operation → file/read (best-effort; the acting process is
  usually SYSTEM/absent — honest null).
"""
from __future__ import annotations

import json

from ..normalize import (basename, const, ext, host_label,  # noqa: F401
                         hex_int, map_value, payload, regex1)


def _eid(rec):
    try:
        return int(rec.get("EventId"))
    except (TypeError, ValueError):
        return None


def _ch(rec, needle):
    return needle in str(rec.get("Channel", ""))


def _pf(rec, name):
    """An EventData/Data @Name value out of the Payload blob (gating only)."""
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


def _mask(rec):
    v = _pf(rec, "AccessMask")
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except (ValueError, AttributeError):
        return 0


# --- object-access (4663) / share (5140/5145): action from AccessMask --------
_DELETE, _WRITE, _READ = 0x10000, 0x0002 | 0x0004, 0x0001


def _is(eid, ch):
    def pred(rec):
        return _eid(rec) == eid and _ch(rec, ch)
    return pred


def au_4663_delete(rec):
    return _eid(rec) == 4663 and _ch(rec, "Security") and _pf(rec, "ObjectType") == "File" and (_mask(rec) & _DELETE)


def au_4663_write(rec):
    return _eid(rec) == 4663 and _ch(rec, "Security") and _pf(rec, "ObjectType") == "File" \
        and not (_mask(rec) & _DELETE) and (_mask(rec) & _WRITE)


def au_4663_read(rec):
    return _eid(rec) == 4663 and _ch(rec, "Security") and _pf(rec, "ObjectType") == "File" \
        and not (_mask(rec) & (_DELETE | _WRITE)) and (_mask(rec) & _READ)


def _share_write(rec, eid):
    return _eid(rec) == eid and _ch(rec, "Security") and (_mask(rec) & (_DELETE | _WRITE))


def _share_read(rec, eid):
    return _eid(rec) == eid and _ch(rec, "Security") and not (_mask(rec) & (_DELETE | _WRITE)) and (_mask(rec) & _READ)


def au_5140_write(rec): return _share_write(rec, 5140)
def au_5140_read(rec):  return _share_read(rec, 5140)
def au_5145_write(rec): return _share_write(rec, 5145)
def au_5145_read(rec):  return _share_read(rec, 5145)


def au_4660(rec):  return _eid(rec) == 4660 and _ch(rec, "Security")
def au_4670_file(rec):
    return _eid(rec) == 4670 and _ch(rec, "Security") and _pf(rec, "ObjectType") == "File"
def au_4689(rec):  return _eid(rec) == 4689 and _ch(rec, "Security")
def au_5058(rec):  return _eid(rec) == 5058 and _ch(rec, "Security")


# 4657 registry value: OperationType token decides add / value_edit / remove
def au_4657_add(rec):
    return _eid(rec) == 4657 and _ch(rec, "Security") and "1904" in _pf(rec, "OperationType")
def au_4657_edit(rec):
    return _eid(rec) == 4657 and _ch(rec, "Security") and "1905" in _pf(rec, "OperationType")
def au_4657_remove(rec):
    return _eid(rec) == 4657 and _ch(rec, "Security") and "1906" in _pf(rec, "OperationType")


def au_5156(rec): return _eid(rec) == 5156 and _ch(rec, "Security")
def au_5157(rec): return _eid(rec) == 5157 and _ch(rec, "Security")
def au_5158(rec): return _eid(rec) == 5158 and _ch(rec, "Security")


PREDICATES = {
    "au_4663_delete": au_4663_delete, "au_4663_write": au_4663_write,
    "au_4663_read": au_4663_read, "au_4660": au_4660, "au_4670_file": au_4670_file,
    "au_4689": au_4689, "au_5058": au_5058,
    "au_5140_write": au_5140_write, "au_5140_read": au_5140_read,
    "au_5145_write": au_5145_write, "au_5145_read": au_5145_read,
    "au_4657_add": au_4657_add, "au_4657_edit": au_4657_edit,
    "au_4657_remove": au_4657_remove,
    "au_5156": au_5156, "au_5157": au_5157, "au_5158": au_5158,
}

_HOST = host_label("Computer")
_FQDN = regex1("Computer", r"^([^.]+\..+)$")
_GUID = {"fields": ["Computer", "Channel", "EventRecordId"]}
_KEEP = ["EventId", "EventRecordId", "Channel", "Computer", "Provider",
         "Payload", "SourceFile", "MapDescription", "UserName"]


def _file_access(action, share=False):
    """4663 / 5140 / 5145 file-access block. 5140/5145 have no acting process
    (server-side) — owner is honest-null; 4663 carries ProcessId (hex)."""
    path = payload("RelativeTargetName") if share else payload("ObjectName")
    m = {
        "object": "file", "action": action, "ts": "TimeCreated",
        "guid": _GUID, "host": _HOST,
        "props": {
            "file_path": payload("ShareName") if share else payload("ObjectName"),
            "file_name": basename(path),
            "extension": ext(path),
            "user": payload("SubjectUserName"),
            "uid": payload("SubjectUserSid"),
            "hostname": _HOST, "fqdn": _FQDN,
        },
        "keep": _KEEP,
        "native_extract": {
            "AccessMask": payload("AccessMask"), "AccessList": payload("AccessList"),
            "HandleId": payload("HandleId"), "IpAddress": payload("IpAddress"),
            "IpPort": payload("IpPort"), "ShareLocalPath": payload("ShareLocalPath"),
            "RelativeTargetName": payload("RelativeTargetName"),
            "SubjectLogonId": payload("SubjectLogonId"),
        },
    }
    if not share:
        m["owning_pid"] = payload("ProcessId")
        m["props"]["image_path"] = payload("ProcessName")
        m["props"]["pid"] = hex_int(payload("ProcessId"))
    return m


def _wfp_flow(action):
    """5156/5157 WFP connection → flow. ProcessID is DECIMAL (not hex)."""
    return {
        "object": "flow", "action": action, "ts": "TimeCreated",
        "guid": _GUID, "host": _HOST,
        "owning_pid": payload("ProcessID"),
        "props": {
            "src_ip": payload("SourceAddress"), "src_port": payload("SourcePort"),
            "dest_ip": payload("DestAddress"), "dest_port": payload("DestPort"),
            "transport_protocol": map_value(payload("Protocol"),
                                            {"6": "tcp", "17": "udp"}),
            "network_direction": map_value(
                payload("Direction"),
                {"%%14593": "outbound", "%%14592": "inbound"}),
            "image_path": payload("Application"),
            "pid": payload("ProcessID"),
            "hostname": _HOST, "fqdn": _FQDN,
        },
        "keep": _KEEP,
        "native_extract": {"FilterRTID": payload("FilterRTID"),
                           "LayerName": payload("LayerName")},
    }


MAPPINGS = {
    "evtx_audit": {
        "variants": [
            # ---- 4663 object access (File) → file read/write/delete ---------
            ("au_4663_delete", _file_access("delete")),
            ("au_4663_write", _file_access("write")),
            ("au_4663_read", _file_access("read")),
            # ---- 4660 object deleted (path in the paired 4663 via HandleId) -
            ("au_4660", {
                "object": "file", "action": "delete", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST,
                "owning_pid": payload("ProcessId"),
                "props": {
                    "user": payload("SubjectUserName"),
                    "uid": payload("SubjectUserSid"),
                    "image_path": payload("ProcessName"),
                    "pid": hex_int(payload("ProcessId")),
                    "hostname": _HOST, "fqdn": _FQDN,
                    # file_path is honest-null: 4660 carries no ObjectName
                },
                "keep": _KEEP,
                "native_extract": {"HandleId": payload("HandleId"),
                                   "SubjectLogonId": payload("SubjectLogonId")},
            }),
            # ---- 4670 permissions changed (File) → file/acl_modify ---------
            ("au_4670_file", {
                "object": "file", "action": "acl_modify", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST,
                "owning_pid": payload("ProcessId"),
                "props": {
                    "file_path": payload("ObjectName"),
                    "file_name": basename(payload("ObjectName")),
                    "extension": ext(payload("ObjectName")),
                    "image_path": payload("ProcessName"),
                    "pid": hex_int(payload("ProcessId")),
                    "user": payload("SubjectUserName"),
                    "hostname": _HOST, "fqdn": _FQDN,
                },
                "keep": _KEEP,
                "native_extract": {"OldSd": payload("OldSd"), "NewSd": payload("NewSd"),
                                   "HandleId": payload("HandleId")},
            }),
            # ---- 4689 process exit → process/terminate --------------------
            ("au_4689", {
                "object": "process", "action": "terminate", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST,
                "props": {
                    "pid": hex_int(payload("ProcessId")),
                    "image_path": payload("ProcessName"),
                    "exe": basename(payload("ProcessName")),
                    "user": payload("SubjectUserName"),
                    "sid": payload("SubjectUserSid"),
                    "hostname": _HOST, "fqdn": _FQDN,
                },
                "keep": _KEEP,
                "native_extract": {"ExitStatus": payload("Status"),
                                   "SubjectLogonId": payload("SubjectLogonId")},
            }),
            # ---- 4657 registry value modified → registry ------------------
            ("au_4657_add", _registry_variant := {
                "object": "registry", "action": "add", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST, "owning_pid": payload("ProcessId"),
                "props": {
                    "key": payload("ObjectName"), "value": payload("ObjectValueName"),
                    "data": payload("NewValue"), "new_content": payload("NewValue"),
                    "type": payload("NewValueType"), "image_path": payload("ProcessName"),
                    "pid": hex_int(payload("ProcessId")), "user": payload("SubjectUserName"),
                    "hostname": _HOST,
                },
                "keep": _KEEP,
                "native_extract": {"OldValue": payload("OldValue"),
                                   "HandleId": payload("HandleId")},
            }),
            ("au_4657_edit", dict(_registry_variant, action="value_edit")),
            ("au_4657_remove", dict(_registry_variant, action="remove")),
            # ---- 5140/5145 file share access → file -----------------------
            ("au_5140_write", _file_access("write", share=True)),
            ("au_5140_read", _file_access("read", share=True)),
            ("au_5145_write", _file_access("write", share=True)),
            ("au_5145_read", _file_access("read", share=True)),
            # ---- 5156/5157 WFP connection → flow; 5158 bind → socket ------
            ("au_5156", _wfp_flow("start")),
            ("au_5157", _wfp_flow("message")),
            ("au_5158", {
                "object": "socket", "action": "bind", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST, "owning_pid": payload("ProcessID"),
                "props": {
                    "local_address": payload("SourceAddress"),
                    "local_port": payload("SourcePort"),
                    "protocol": payload("Protocol"),
                    "image_path": payload("Application"),
                    "pid": payload("ProcessID"),
                    "success": const(True),
                },
                "keep": _KEEP,
                "native_extract": {"LayerName": payload("LayerName")},
            }),
            # ---- 5058 crypto key-FILE operation → file/read (best-effort) --
            ("au_5058", {
                "object": "file", "action": "read", "ts": "TimeCreated",
                "guid": _GUID, "host": _HOST,
                "props": {
                    "file_path": payload("KeyFilePath"),
                    "file_name": basename(payload("KeyFilePath")),
                    "user": payload("SubjectUserName"),
                    "hostname": _HOST, "fqdn": _FQDN,
                },
                "keep": _KEEP,
                "native_extract": {"Operation": payload("Operation"),
                                   "KeyName": payload("KeyName")},
            }),
        ],
        "default": None,
    },
}
