"""The spindle row identity (ids.py + normalize's `spindle` guid form).

Every Plaso/l2t-derived CAR row used to carry guid=None, so it could neither
dedupe (enrich._dedupe), relate (superset edges need a guid on both ends;
derive links skip guid-less rows) nor export to STIX as anything but a
positional observation. Each now gets a deterministic guid minted exactly the
way stix.py mints §2.9 ids — uuid5 over a namespace and the canonical JSON of
the record's OWN stable-identity fields, keyed by name — so two tools parsing
the same image converge. Sysmon / EVTX guids (already stable cross-tool keys)
are untouched. Rows are shaped like the wrapped l2t JSONL split_l2t emits, with
field values from the real-evidence fixtures of the sibling test modules. The
registry that says WHICH fields (spindle.yml) has its own tests in
test_spindle_model.py.
"""
import json
import uuid

import pytest

from piiat_mitrecar import (derive, enrich, ids, mappings, normalize, pipeline, sources_model,
                            spindle, stix, store, superset)
from piiat_mitrecar.adapters import jlecmd, l2t_split, winevt as winevt_adapter
from piiat_mitrecar.mappings import _common

_TS = "2020-09-16T13:14:30.462820Z"


def _wrap(parser, record, ts=_TS, source="M57-JO.jsonl", record_id=7):
    """A wrapped l2t row exactly as split_l2t emits it (RecordId = its line)."""
    row = {"SourceImage": source, "RecordId": record_id, "Parser": parser,
           "Record": dict(record, parser=parser)}
    if ts:
        row["Timestamp"] = ts
    return row


_USN = {  # real M57-JO usnjrnl row
    "data_type": "fs:ntfs:usn_change", "display_name": "NTFS:\\$Extend\\$UsnJrnl:$J",
    "filename": "a15f3474-ab93-46b9-8834-124287ab1646.tmp", "image_hostname": "M57-JO",
    "file_reference": 281474976727294, "parent_file_reference": 281474976725861,
    "timestamp_desc": "Metadata Modification Time", "update_reason_flags": 2147484416,
    "update_source_flags": 0, "update_sequence_number": 1048576, "username": "-",
}
_MFT = {  # synthetic, per the plaso mft parser's documented fields
    "data_type": "fs:stat:ntfs", "display_name": "NTFS:\\$MFT", "filename": "\\$MFT",
    "name": "notes.txt", "path_hints": ["\\Users\\jo\\notes.txt"], "file_reference": 843,
    "parent_file_reference": 29, "image_hostname": "M57-JO", "is_allocated": True,
    "timestamp_desc": "Creation Time", "username": "-",
}
_FILESTAT = {  # real M57-JO filestat row
    "data_type": "fs:stat", "display_name": "NTFS:\\Program Files\\app\\FPEXT.MSG",
    "filename": "\\Program Files\\app\\FPEXT.MSG", "file_entry_type": "file",
    "file_size": 78706, "file_system_type": "NTFS", "image_hostname": "M57-JO",
    "is_allocated": True, "inode": "281474976721211",
    "timestamp_desc": "Content Modification Time", "username": "-",
}
_AMCACHE = {  # synthetic, the plaso AMCacheFileEventData shape
    "data_type": "windows:registry:amcache",
    "display_name": "NTFS:\\Windows\\appcompat\\Programs\\Amcache.hve",
    "full_path": "c:\\users\\bob\\downloads\\evil.exe", "image_hostname": "M57-JO",
    "program_identifier": "0006a1c48f048a1c",
    "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "timestamp_desc": "Content Modification Time",     # the key write: the execution row
    "username": "-",
}
_PREFETCH = {  # real M57-JO prefetch execution row
    "data_type": "windows:prefetch:execution",
    "display_name": "NTFS:\\WINDOWS\\Prefetch\\SVCHOST.EXE-3530F672.pf",
    "executable": "SVCHOST.EXE", "image_hostname": "M57-JO", "path_hints": [],
    "prefetch_hash": 892401266, "run_count": 3, "timestamp_desc": "Last Time Executed",
    "username": "-", "version": 17,
}
_REGISTRY = {
    "data_type": "windows:registry:key_value",
    "display_name": "NTFS:\\WINDOWS\\system32\\config\\software",
    "key_path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "image_hostname": "M57-JO", "values": [{"name": "x", "data": "y"}],
}


def _canonical_uuid(obj, key, version=1):
    """The recipe by hand: uuid5(SPINDLE_NS, canonical JSON of {"_obj": obj, "_v": version, **key})."""
    payload = json.dumps(dict(key, _obj=obj, _v=version), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
    return str(uuid.uuid5(ids.SPINDLE_NS, payload))


# --------------------------------------------------------------------------- #
# the recipe: shared with stix, namespaced under CAR_NS, deterministic
# --------------------------------------------------------------------------- #
def test_recipe_is_the_stix_one_and_namespaced_under_car_ns():
    assert stix.canonical_json is ids.canonical_json
    assert stix.CAR_NS == ids.CAR_NS and stix.STIX_NS == ids.STIX_NS
    assert ids.SPINDLE_NS == uuid.uuid5(ids.CAR_NS, "spindle")
    assert ids.SPINDLE_NS not in (ids.CAR_NS, ids.STIX_NS)
    # §2.9 canonical JSON: sorted keys, no whitespace, UTF-8 kept
    assert ids.canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'


def test_minting_is_deterministic_and_order_and_rendering_free():
    key = {"file_reference": "843", "event_time": _TS}
    want = _canonical_uuid("file", key)
    # the ONE seam — ids.mint(obj, identity, version) -> (guid, key): the same
    # identity is the same guid however it is spelled (int or str, any order)
    assert ids.mint("file", {"file_reference": 843, "event_time": _TS}, 1)[0] == want
    assert ids.mint("file", {"event_time": _TS, "file_reference": "843"}, 1)[0] == want
    guid, minted = ids.mint("file", {"file_reference": 843, "event_time": _TS}, 1)
    assert minted == {"_obj": "file", "_v": 1, "file_reference": "843", "event_time": _TS}
    assert ids.guid_of(minted) == guid == want           # a key re-mints to its guid
    # the identity-key VERSION is hashed: a bump re-mints every guid of the entry
    assert ids.mint("file", {"file_reference": 843, "event_time": _TS}, 2)[0] != want
    # the two reserved keys are typed (_obj str, _v int); a field may render json
    assert ids.mint("file", {"n": 843}, 1, {"n": "json"})[1]["n"] == "843"
    assert ids.mint("file", {"s": "x"}, 1, {"s": "json"})[1]["s"] == '"x"'
    # and through the map: two normalizations of one record agree with the recipe
    a = normalize.normalize("l2t_mft", _wrap("mft", _MFT))
    b = normalize.normalize("l2t_mft", _wrap("mft", _MFT))
    assert a["guid"] == b["guid"] == want
    assert uuid.UUID(a["guid"]).version == 5
    # the readable key + its scope ride native; nothing else about the row changed
    assert a["_native"]["spindle_key"] == {"_obj": "file", "_v": 1, "file_reference": "843",
                                           "event_time": _TS}
    assert a["_native"]["spindle_scope"] == "intrinsic"
    assert (a["car_object"], a["car_action"], a["file_path"], a["timestamp"]) == \
        ("file", "create", "notes.txt", _TS)


# --------------------------------------------------------------------------- #
# cross-tool convergence: position, container and parser name are not hashed
# --------------------------------------------------------------------------- #
def test_same_identity_converges_across_position_source_and_parser():
    one = normalize.normalize("l2t_usnjrnl", _wrap("usnjrnl", _USN, source="plaso-run-1.jsonl",
                                                   record_id=3))
    two = normalize.normalize("l2t_usnjrnl", _wrap("usnjrnl/other-tool", _USN,
                                                   source="another-tool.jsonl", record_id=9000))
    assert one["guid"] == two["guid"] == _canonical_uuid(
        "file", {"usn": "1048576", "file_reference": "281474976727294"})
    key = one["_native"]["spindle_key"]
    assert set(key) == {"_obj", "_v", "usn", "file_reference"}   # no SourceImage / Parser / RecordId
    # a different USN record of the same entry is another event
    other = normalize.normalize("l2t_usnjrnl", _wrap("usnjrnl", dict(_USN, update_sequence_number=1048608)))
    assert other["guid"] != one["guid"]
    # a Plaso prefetch run: exe + hash + THIS run time (a .pf holds up to eight)
    p1 = normalize.normalize("plaso_exec_prefetch", _wrap("prefetch", _PREFETCH, record_id=1))
    p2 = normalize.normalize("plaso_exec_prefetch", _wrap("prefetch", _PREFETCH, record_id=2,
                                                          source="other.jsonl"))
    p3 = normalize.normalize("plaso_exec_prefetch", _wrap("prefetch", _PREFETCH,
                                                          ts="2009-11-20T09:31:29.671875Z"))
    assert p1["guid"] == p2["guid"] != p3["guid"]
    assert p1["_native"]["spindle_key"] == {"_obj": "process", "_v": 1, "exe": "SVCHOST.EXE",
                                            "prefetch_hash": "892401266", "run_time": _TS}


# --------------------------------------------------------------------------- #
# domain separation: field names and the object are part of the identity
# --------------------------------------------------------------------------- #
def test_different_objects_and_field_names_never_collide():
    v = "281474976727294"
    assert ids.mint("file", {"file_reference": v}, 1)[0] != ids.mint("file", {"usn": v}, 1)[0]
    assert ids.mint("file", {"key": v}, 1)[0] != ids.mint("registry", {"key": v}, 1)[0]
    assert ids.mint("file", {"a": "1", "b": "2"}, 1)[0] != ids.mint("file", {"a": "2", "b": "1"}, 1)[0]
    # through the maps: a registry key row and a shell-item file row that share
    # the same key_path/path string and time are two identities
    reg = normalize.normalize("plaso_registry", _wrap("winreg/winreg_default", _REGISTRY))
    shell = normalize.normalize("plaso_shellitem", _wrap("lnk/shell_items", {
        "data_type": "windows:shell_item:file_entry", "timestamp_desc": "Creation Time",
        "origin": _REGISTRY["display_name"], "shell_item_path": _REGISTRY["key_path"],
        "image_hostname": "M57-JO"}))
    assert reg["guid"] and shell["guid"] and reg["guid"] != shell["guid"]
    assert reg["_native"]["spindle_key"] == {
        "_obj": "registry", "_v": 1, "hive": _REGISTRY["display_name"],
        "key_path": _REGISTRY["key_path"], "last_write": _TS}


# --------------------------------------------------------------------------- #
# dedupe: duplicate disk rows collapse, distinct ones never do
# --------------------------------------------------------------------------- #
def test_dedupe_collapses_duplicate_disk_rows():
    dupes = [normalize.normalize("l2t_usnjrnl", _wrap("usnjrnl", _USN, record_id=i)) for i in (1, 2)]
    other = normalize.normalize("l2t_usnjrnl", _wrap(
        "usnjrnl", dict(_USN, update_sequence_number=1048608), record_id=3))
    assert all(e["guid"] for e in dupes + [other])
    out = enrich.enrich(dupes + [other])
    assert [e["guid"] for e in out] == [dupes[0]["guid"], other["guid"]]
    # the additive D4 fold sees ONE event too (it was two rows with no identity before)
    assert len(derive.coalesce(dupes)) == 1
    # an $MFT entry's $SI and $FN rows at the SAME time are one observation; at
    # different times (the timestomp tell) they both survive
    si = normalize.normalize("l2t_mft", _wrap("mft", _MFT, record_id=10))
    fn = normalize.normalize("l2t_mft", _wrap("mft", dict(_MFT, name=None), record_id=11))
    stomped = normalize.normalize("l2t_mft", _wrap("mft", _MFT, ts="2019-01-01T00:00:00.000000Z"))
    assert len(enrich.enrich([si, fn, stomped])) == 2


def test_additive_fold_keeps_every_contribution_and_counts_the_contributors():
    """The fold is ADDITIVE by default (relationships.yml dedupe.fold): rows of
    one identity become one row that keeps what every contributor carried,
    with the contributors counted — a time-free entity's several stamp rows,
    an $MFT entry's $SI/$FN twins. Distinct identities never fold; the
    most-populated fold stays selectable."""
    pe = {"data_type": "pe_coff:file", "display_name": "NTFS:\\Windows\\System32\\evil.dll",
          "image_hostname": "M57-JO", "sha256_hash": "b5de10a0" + "0" * 56}
    rows = [normalize.normalize("plaso_pecoff", _wrap("pe", dict(pe, timestamp_desc=desc), ts=ts, record_id=i))
            for i, (desc, ts) in enumerate([("Creation Time", "2019-06-01T12:34:56.000000Z"),
                                            ("Content Modification Time", "2019-06-01T12:35:00.000000Z"),
                                            ("Not a time", "1970-01-01T00:00:00.000000Z")], 1)]
    assert len({r["guid"] for r in rows}) == 1                    # one PE entity, three stamp rows
    assert [r["_native"]["spindle_ref"] for r in rows] == \
        [{"SourceImage": "M57-JO.jsonl", "RecordId": i} for i in (1, 2, 3)]
    (one,) = enrich.enrich(rows)
    nat = one["_native"]
    # both stamps survive on the one row: nothing a loser carried is lost
    assert nat["compile_time"] == "2019-06-01T12:34:56.000000Z"
    assert nat["pe_table_time"] == "2019-06-01T12:35:00.000000Z"
    assert nat["contributions"] == 3 and nat["coalesced_sources"] == ["plaso_pecoff"]
    assert nat["contributed_by"] == [{"source_artefact": "plaso_pecoff",
                                      "spindle_ref": {"SourceImage": "M57-JO.jsonl", "RecordId": i}} for i in (1, 2, 3)]
    assert nat["coalesced_conflicts"]["native.timestamp_desc"] == [
        {"source_artefact": "plaso_pecoff", "value": "Content Modification Time"},
        {"source_artefact": "plaso_pecoff", "value": "Not a time"}]
    assert "native.spindle_ref" not in nat["coalesced_conflicts"]  # provenance is listed, never a conflict
    assert nat["spindle_ref"] == {"SourceImage": "M57-JO.jsonl", "RecordId": 1}
    assert spindle.validate_record(one) == []
    # the $MFT entry's $SI and $FN rows at the SAME time: one row, both natives, two contributors
    si = normalize.normalize("l2t_mft", _wrap("mft", _MFT, record_id=10))
    fn = normalize.normalize("l2t_mft", _wrap("mft", dict(_MFT, name=None), record_id=11))
    (m,) = enrich.enrich([si, fn])
    assert m["file_path"] == "notes.txt" and m["_native"]["contributions"] == 2
    assert m["_native"]["coalesced_conflicts"]["file_path"] == [{"source_artefact": "l2t_mft", "value": "\\$MFT"}]
    assert [c["spindle_ref"]["RecordId"] for c in m["_native"]["contributed_by"]] == [10, 11]
    # distinct positional rows never fold; a lone row is not stamped
    rec = {k: v for k, v in _MFT.items() if k != "file_reference"}
    out = enrich.enrich([normalize.normalize("l2t_mft", _wrap("mft", rec, record_id=42)),
                         normalize.normalize("l2t_mft", _wrap("mft", rec, record_id=43))])
    assert len(out) == 2 and all("contributions" not in e["_native"] for e in out)
    # a second fold over an already-folded row keeps counting, never double-lists
    again = normalize.normalize("plaso_pecoff", _wrap("pe", dict(pe, timestamp_desc="Not a time"),
                                                      ts="1970-01-01T00:00:00.000000Z", record_id=4))
    (refold,) = enrich.fold([one, again])
    assert refold["_native"]["contributions"] == 4 and len(refold["_native"]["contributed_by"]) == 4
    # the fold is a RULE: additive is the default; most_populated stays selectable
    assert enrich.dedupe_rules()["fold"] == enrich.FOLD_ADDITIVE == "additive"
    assert enrich.dedupe_key() == ["source_host", "car_object", "guid", "car_action", "target_guid", "access_level"]
    fresh = [normalize.normalize("plaso_pecoff", _wrap("pe", dict(pe, timestamp_desc=d), ts=t, record_id=i))
             for i, (d, t) in enumerate([("Creation Time", "2019-06-01T12:34:56.000000Z"),
                                         ("Content Modification Time", "2019-06-01T12:35:00.000000Z")], 1)]
    (best,) = enrich.fold(fresh, enrich.FOLD_MOST_POPULATED)
    assert "contributions" not in best["_native"] and "pe_table_time" not in best["_native"]
    with pytest.raises(ValueError):
        enrich.fold(fresh, "majority")
    # derive.coalesce is the same fold by its derive-side name
    assert derive.coalesce(fresh)[0]["_native"]["contributions"] == 2


# --------------------------------------------------------------------------- #
# relationships: an edge between two disk rows now has guids to name
# --------------------------------------------------------------------------- #
def test_edge_between_two_disk_rows_materialises():
    proc = normalize.normalize("plaso_exec_winreg", _wrap("amcache", _AMCACHE, record_id=1))
    on_disk = dict(_FILESTAT, filename=_AMCACHE["full_path"], sha1_hash=_AMCACHE["sha1"],
                   timestamp_desc="Creation Time")
    file = normalize.normalize("l2t_filestat", _wrap("filestat", on_disk, record_id=2))
    assert proc["guid"] and file["guid"]
    events = enrich.enrich([proc, file])
    f = next(e for e in events if e["car_object"] == "file")
    # the cascade's file -> executing-process link (CAR-2014-02-001) names a real guid
    assert f["_native"]["executed_as_process_guid"] == proc["guid"]
    # DECLARED: process --executed--> file, both ends disk rows
    edges = superset.edges_from_events(events)
    assert [(e["source_object"], e["relationship"], e["target_object"],
             e["source_guid"], e["target_guid"]) for e in edges] == \
        [("process", "executed", "file", proc["guid"], file["guid"])]
    # DERIVED: the 1:1 link on the shared program hash, both ends disk rows
    (d,) = derive.link_edges(events)
    assert (d["source_guid"], d["target_guid"], d["method"], d["identity_key"]) == \
        (proc["guid"], file["guid"], "shared_hash", "sha1_hash")
    assert d["corroborated_by"] == [proc["guid"], file["guid"]]


# --------------------------------------------------------------------------- #
# the positional fallback: deterministic, per record, flagged positional
# --------------------------------------------------------------------------- #
def test_positional_fallback_is_stable_and_flagged_when_no_identity():
    rec = dict(_MFT)
    del rec["file_reference"]                    # the intrinsic identity is incomplete
    a = normalize.normalize("l2t_mft", _wrap("mft", rec, record_id=42))
    b = normalize.normalize("l2t_mft", _wrap("mft", rec, record_id=42))
    want = _canonical_uuid("file", {"SourceImage": "M57-JO.jsonl", "RecordId": "42"})
    assert a["guid"] == b["guid"] == want
    assert a["_native"]["spindle_scope"] == "positional"
    assert a["_native"]["spindle_key"] == {"_obj": "file", "_v": 1, "SourceImage": "M57-JO.jsonl",
                                           "RecordId": "42"}
    # another line of the container is another row; so is the same line of another container
    assert normalize.normalize("l2t_mft", _wrap("mft", rec, record_id=43))["guid"] != want
    assert normalize.normalize("l2t_mft", _wrap("mft", rec, source="other.jsonl",
                                                record_id=42))["guid"] != want
    # a blank component (a zeroed timestamp) also falls back, never a half identity
    z = normalize.normalize("l2t_mft", _wrap("mft", _MFT, ts=None, record_id=5))
    assert z["timestamp"] is None and z["_native"]["spindle_scope"] == "positional"
    # no per-record index at all (a bare wrapped row): honestly no guid, nothing minted
    bare = normalize.normalize("l2t_mft", {"SourceImage": "x", "Parser": "mft",
                                           "Record": rec, "Timestamp": _TS})
    assert bare["guid"] is None and "spindle_key" not in bare["_native"]


def test_split_l2t_stamps_the_physical_line_as_record_id(tmp_path):
    raw = tmp_path / "img.jsonl"
    lines = [json.dumps(dict(_USN, parser="usnjrnl", timestamp=1600262070462820)),
             "",                                             # a blank line: counted, not a record
             "{not json",                                    # a bad line: skipped, still counted
             json.dumps(dict(_MFT, parser="mft", timestamp=1600262070462820)),
             json.dumps(dict(_USN, parser="usnjrnl", timestamp=1600262070462821))]
    raw.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def split(out):
        out.mkdir()
        tables = l2t_split.split_l2t(str(raw), "img.jsonl", str(out), "img.jsonl")
        return {t: [json.loads(x) for x in open(p, encoding="utf-8")] for t, p in tables.items()}

    first, again = split(tmp_path / "a"), split(tmp_path / "b")
    assert first == again                                    # stable across re-splits
    assert [r["RecordId"] for r in first["L2tUsnjrnl"]] == [1, 5]
    assert [r["RecordId"] for r in first["L2tMft"]] == [4]
    row = first["L2tUsnjrnl"][0]
    assert list(row) == ["SourceImage", "RecordId", "Parser", "Record", "Timestamp"]
    # the wrapped row feeds the map: the intrinsic identity wins, RecordId stays out of it
    ev = normalize.normalize("l2t_usnjrnl", row)
    assert ev["_native"]["spindle_scope"] == "intrinsic" and "RecordId" not in ev["_native"]["spindle_key"]
    # a caller with no index (the dry-run table scan) still gets the old shape
    _table, line = l2t_split._l2t_row(dict(_USN, parser="usnjrnl"), "img.jsonl")
    assert "RecordId" not in json.loads(line)


# --------------------------------------------------------------------------- #
# Sysmon / EVTX (and the non-l2t EZ maps) are exactly as they were
# --------------------------------------------------------------------------- #
def _sysmon(eid, data, record_id="4857"):
    return {"Computer": "IEWIN7", "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon", "EventId": eid, "EventRecordId": record_id,
            "TimeCreated": "2019-05-26T04:01:42+00:00",
            "Payload": json.dumps({"EventData": {"Data": [{"@Name": k, "#text": v}
                                                          for k, v in data.items()]}})}


def test_sysmon_and_evtx_guids_are_unchanged_and_never_wrapped():
    guid = "365abb72-0fa6-5cea-0000-001049b50a00"
    assert _common.EVTX_RECORD_GUID == {"fields": ["Computer", "Channel", "EventRecordId"]}
    proc = normalize.normalize("evtx_sysmon", _sysmon(1, {"ProcessGuid": guid, "ProcessId": "3836",
                                                          "Image": r"C:\x.exe"}))
    assert proc["guid"] == guid and "spindle_key" not in proc["_native"]      # raw ProcessGuid
    flow = normalize.normalize("evtx_sysmon", _sysmon(3, {"ProcessGuid": guid, "Protocol": "tcp"}))
    assert flow["guid"] == "flow-IEWIN7-Microsoft-Windows-Sysmon/Operational-4857"
    auth = normalize.normalize("evtx_security", {
        "EventId": 4624, "Channel": "Security", "Computer": "HOST1.example.com", "EventRecordId": 14,
        "TimeCreated": "2019-01-28T19:40:32+00:00",
        "Payload": json.dumps({"EventData": {"Data": [{"@Name": "TargetUserName", "#text": "Steve"}]}})})
    assert auth["guid"] == "authentication-HOST1.example.com-Security-14"
    # Plaso's parse of the same log (the l2t_winevt route) keeps the EVTX record guid
    shaped = winevt_adapter.adapt({
        "SourceImage": "LoneWolf.E01", "RecordId": 77, "Timestamp": "2018-03-27T12:11:42.0Z",
        "Parser": "winevtx",
        "Record": {"data_type": "windows:evtx:record", "event_identifier": 4688,
                   "strings": ["S-1-5-18", "-", "-", "0x3e7", "0x174", r"C:\Windows\System32\smss.exe",
                               "%%1936", "0x4", None, "S-1-0-0", "-", "-", "0x0", None, "S-1-16-16384"],
                   "xml_string": "<Event><System><Channel>Security</Channel>"
                                 "<Computer>WIN-1M3263ACE5D</Computer></System></Event>",
                   "source_name": "Microsoft-Windows-Security-Auditing", "record_number": 2623,
                   "hostname": "WIN-1M3263ACE5D"}})
    ev = normalize.normalize("evtx_process", shaped)
    assert ev["guid"] == "process-WIN-1M3263ACE5D-Security-2623" and "spindle_key" not in ev["_native"]
    # the EZ-tool maps that are not l2t-fed keep their field guids
    jl = normalize.normalize("jlecmd_dest", next(jlecmd.flatten({
        "AppId": {"AppId": "fb3b", "Description": "Word"}, "SourceFile": "/in/fb3b.automaticDestinations-ms",
        "DestListEntries": [{"Path": r"C:\Users\j\Planning.docx", "EntryNumber": 1,
                             "LastModified": "/Date(1522917168677)/", "Hostname": "desktop-1"}]})))
    assert jl["guid"] == "file-/in/fb3b.automaticDestinations-ms-1"
    rc = normalize.normalize("recmd_batch", {
        "HivePath": "/in/UsrClass.dat", "HiveType": "UsrClass", "KeyPath": r"S-1-5-21-1_Classes\X",
        "ValueName": "LangID", "ValueType": "RegBinary", "ValueData": "(Binary data)",
        "Deleted": False, "LastWriteTimestamp": "2018-04-02 01:15:16.9540407"})
    assert rc["guid"] == r"registry-/in/UsrClass.dat-S-1-5-21-1_Classes\X-LangID"


def test_every_plaso_map_leaf_names_a_registry_entry_and_evtx_never_does():
    """The completeness lock (spindle.verify_registry is the full guard): every
    l2t/Plaso-derived leaf mints from the registry by name only — no field is
    spelled in a map — and every EVTX-family leaf keeps its raw record /
    Sysmon guid form."""
    assert spindle.verify_registry() == []
    plaso = {k for k, d in sources_model.DERIVATIONS.items() if d.tool == sources_model.PLASO_TOOL}
    assert len(plaso) >= 20
    for key in sorted(plaso):
        for leaf in sources_model._leaves(mappings.MAPPINGS[key]):   # noqa: SLF001
            spec = leaf.get("guid")
            assert spec and set(spec) == {"spindle"}, (key, leaf["object"])
            assert spec["spindle"] in spindle.identities(), (key, spec)
    for key in pipeline.EVTX_MAPS:
        for leaf in sources_model._leaves(mappings.MAPPINGS[key]):   # noqa: SLF001
            spec = leaf.get("guid") or {}
            assert "spindle" not in spec and (set(spec) & {"fields", "marker"}), key


# --------------------------------------------------------------------------- #
# STIX: the observation keys off the row's guid, which is now a real one
# --------------------------------------------------------------------------- #
def test_stix_observation_and_entity_key_off_the_spindle_guid(tmp_path):
    events = enrich.enrich([
        normalize.normalize("plaso_exec_prefetch", _wrap("prefetch", _PREFETCH, record_id=1,
                                                         ts="2009-11-20T09:31:29.671875Z")),
        normalize.normalize("l2t_filestat", _wrap("filestat", _FILESTAT, record_id=2))])
    st = store.CarStore(str(tmp_path / "car.db"))
    st.insert_events(events)
    st.close()
    sup = superset.build_superset_db(str(tmp_path), events)
    derive.derive(events, sup["superset_db"], str(tmp_path))
    summary = stix.export(str(tmp_path), case="c")
    with open(summary["bundle"], encoding="utf-8") as fh:
        objects = json.load(fh)["objects"]
    by_obj = {e["car_object"]: e for e in events}
    obs = {o["x_car_object"]: o for o in objects if o["type"] == "observed-data"}
    assert set(obs) == {"process", "file"}
    for obj, o in obs.items():
        assert o["x_car_event_id"] == by_obj[obj]["guid"]           # guid <-> event.id, no row{n}
        assert o["x_car_native"]["spindle_key"]["_obj"] == obj
        assert o["x_car_native"]["spindle_scope"] == "intrinsic"
    (p,) = [o for o in objects if o["type"] == "process"]
    assert p["x_car_entity_id"] == by_obj["process"]["guid"]
    assert not [o for o in objects if o["type"] == "x-car-record"]
    # another case scopes the observation ids differently; the row guid does not move
    other = stix.export(str(tmp_path), out_path=str(tmp_path / "other.json"), case="d")
    with open(other["bundle"], encoding="utf-8") as fh:
        other_obs = {o["x_car_object"]: o for o in json.load(fh)["objects"] if o["type"] == "observed-data"}
    for obj in obs:
        assert other_obs[obj]["id"] != obs[obj]["id"]
        assert other_obs[obj]["x_car_event_id"] == obs[obj]["x_car_event_id"]
