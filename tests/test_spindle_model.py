"""The spindle identity model as DATA.

piiat_mitrecar/spindle.yml is the single source of the per-artefact identity
rules the engine mints disk-image guids from (the relationships.yml discipline:
rules are data, the engine is mechanics); model/spindle/ holds its deterministic
snapshot plus the spindle record's shape, generated like model/generate.py
generates the CAR objects. These tests hold the three — registry, maps/engine,
committed snapshot — in step, the way test_car_sources holds sources/ to the maps.
"""
import json
import os
import pathlib
import subprocess
import sys
import uuid

import yaml

from piiat_mitrecar import ids, mappings, normalize, pipeline, sources_model, spindle, store

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL_SPINDLE = ROOT / "model" / "spindle"
_TS = "2020-09-16T13:14:30.462820Z"


def _wrap(parser, record, ts=_TS, record_id=7):
    row = {"SourceImage": "M57-JO.jsonl", "RecordId": record_id, "Parser": parser,
           "Record": dict(record, parser=parser)}
    if ts:
        row["Timestamp"] = ts
    return row


_ROWS = {  # one real-shaped record per artefact family (values from the sibling fixtures)
    "l2t_mft": ("mft", {"data_type": "fs:stat:ntfs", "display_name": "NTFS:\\$MFT", "filename": "\\$MFT",
                        "name": "notes.txt", "file_reference": 843, "image_hostname": "M57-JO",
                        "timestamp_desc": "Creation Time"}),
    "l2t_usnjrnl": ("usnjrnl", {"data_type": "fs:ntfs:usn_change", "filename": "a.tmp",
                                "image_hostname": "M57-JO", "file_reference": 281474976727294,
                                "update_reason_flags": 0x100, "update_sequence_number": 1048576,
                                "timestamp_desc": "Metadata Modification Time"}),
    "plaso_exec_prefetch": ("prefetch", {"data_type": "windows:prefetch:execution",
                                         "display_name": "NTFS:\\WINDOWS\\Prefetch\\SVCHOST.EXE-3530F672.pf",
                                         "executable": "SVCHOST.EXE", "image_hostname": "M57-JO",
                                         "prefetch_hash": 892401266}),
    "plaso_registry": ("winreg/winreg_default", {"data_type": "windows:registry:key_value",
                                                 "display_name": "NTFS:\\WINDOWS\\system32\\config\\software",
                                                 "key_path": "HKEY_LOCAL_MACHINE\\Software\\X",
                                                 "image_hostname": "M57-JO"}),
    "l2t_utmp": ("utmp", {"data_type": "linux:utmp:event", "hostname": "localhost", "image_hostname": "",
                          "ip_address": "0.0.0.0", "login_type": 7, "pid": 3401, "terminal": "tty7",
                          "username": "logserv"}),
    "l2t_msiecf": ("msiecf", {"data_type": "msiecf:url", "timestamp_desc": "Last Visited Time",
                              "url": "Visited: Administrator@http://windowsupdate.microsoft.com/x",
                              "image_hostname": "M57-JO", "display_name": "NTFS:\\...\\index.dat"}),
    "l2t_srum": ("esedb/srum", {"data_type": "windows:srum:network_usage", "application": "DiagTrack",
                                "bytes_received": 1, "bytes_sent": 2, "user_identifier": "S-1-5-21-1-2-3-1001",
                                "interface_luid": 19985273102270464}),
}


# --------------------------------------------------------------------------- #
# the registry: consistent with the maps and the engine constants
# --------------------------------------------------------------------------- #
def test_registry_is_consistent_with_maps_and_engine():
    assert spindle.verify_registry() == []


def test_registry_declares_the_recipe_the_engine_uses():
    r = spindle.rules()["spindle"]
    assert uuid.uuid5(ids.CAR_NS, r["namespace"]["label"]) == ids.SPINDLE_NS
    assert r["namespace"]["parent"] == "CAR_NS" and r["object_key"] == ids.OBJECT_KEY == "_obj"
    assert r["version_key"] == ids.VERSION_KEY == "_v"
    assert r["rendering"] == ids.RENDER_STR and r["normalize"] == list(ids.RENDERINGS) == ["str", "json"]
    assert spindle.positional() == ["SourceImage", "RecordId"] and spindle.positional_version() == 1
    assert set(r["entry_scopes"]) == {"cross_source", "within_source_fallback"}
    assert set(r["row_scopes"]) == {"cross_source", "within_source"}
    # every entry: a CAR object, a scope, a version, an ordered identity of event paths
    for name, e in spindle.identities().items():
        assert e["scope"] == "cross_source" and e["identity"], name
        assert isinstance(e["version"], int) and e["version"] >= 1, name
        for iname, source, mode in spindle.identity_fields(e):
            assert mode is None, (name, iname)                 # no rendering override in v1
            assert source in ("timestamp", "owning_pid") or source.startswith("native.") \
                or source in store.HEADER or "_" in source or source.isalpha(), (name, source)


def test_every_plaso_map_mints_from_the_registry_and_no_evtx_map_does():
    plaso = {k for k, d in sources_model.DERIVATIONS.items() if d.tool == sources_model.PLASO_TOOL}
    named = set()
    for key in plaso:
        for leaf in sources_model._leaves(mappings.MAPPINGS[key]):   # noqa: SLF001
            name = leaf["guid"]["spindle"]
            assert name == key or name.startswith(key + "/"), (key, name)
            assert spindle.entry(name)["object"] == leaf["object"]
            named.add(name)
    assert named == set(spindle.identities())                      # no unused entry, no unnamed leaf
    for key in pipeline.EVTX_MAPS:
        for leaf in sources_model._leaves(mappings.MAPPINGS[key]):   # noqa: SLF001
            assert "spindle" not in (leaf.get("guid") or {}), key


def test_registry_drift_is_caught(monkeypatch):
    """A map naming an unregistered entry, an entry nobody names, an entry of
    the wrong object, a source the leaf does not emit — each is a problem."""
    import copy
    good = copy.deepcopy(spindle.rules())
    bad = copy.deepcopy(good)
    bad["identities"]["l2t_mft"]["object"] = "registry"
    bad["identities"]["l2t_usnjrnl"]["identity"]["usn"] = "native.no_such_key"
    bad["identities"]["nobody_names_me"] = {"object": "file", "scope": "cross_source",
                                            "version": 1, "identity": {"x": "file_path"}}
    del bad["identities"]["l2t_lnk"]
    bad["identities"]["l2t_text"]["version"] = "one"
    bad["identities"]["l2t_utmp"]["identity"]["pid"] = {"source": "owning_pid", "normalize": "hex"}
    monkeypatch.setattr(spindle, "_rules_cache", bad)
    problems = "\n".join(spindle.verify_registry())
    assert "l2t_mft" in problems and "declared for 'registry'" in problems
    assert "native.no_such_key" in problems
    assert "nobody_names_me" in problems and "referenced by no map" in problems
    assert "l2t_lnk" in problems and "unregistered" in problems
    assert "l2t_text: version must be an int" in problems
    assert "l2t_utmp: identity 'pid' normalize 'hex'" in problems
    monkeypatch.setattr(spindle, "_rules_cache", good)
    assert spindle.verify_registry() == []


# --------------------------------------------------------------------------- #
# the snapshot: deterministic, committed in sync, drift caught
# --------------------------------------------------------------------------- #
def test_snapshot_is_deterministic_and_the_committed_one_is_in_sync(tmp_path):
    first = spindle.write_snapshot(str(tmp_path / "a"))
    again = spindle.write_snapshot(str(tmp_path / "b"))
    assert [os.path.basename(p) for p in first] == ["identity.yml", "record.yml"]
    for p, q in zip(first, again):
        assert open(p, encoding="utf-8").read() == open(q, encoding="utf-8").read()
    assert spindle.verify_snapshot(str(tmp_path / "a")) == []
    # the COMMITTED snapshot matches what the registry + maps + engine render now
    assert spindle.verify_snapshot(str(MODEL_SPINDLE)) == []
    # drift is caught, missing files too
    (tmp_path / "a" / "identity.yml").write_text("identities: []\n", encoding="utf-8")
    (tmp_path / "a" / "record.yml").unlink()
    problems = spindle.verify_snapshot(str(tmp_path / "a"))
    assert len(problems) == 2 and any("drifted" in p for p in problems) and any("missing" in p for p in problems)


def test_snapshot_registry_materializes_the_resolved_identities():
    doc = yaml.safe_load((MODEL_SPINDLE / "identity.yml").read_text(encoding="utf-8"))
    spec = doc["spindle"]
    assert spec["namespace"] == {"STIX_NS": str(ids.STIX_NS), "CAR_NS": str(ids.CAR_NS),
                                 "SPINDLE_NS": str(ids.SPINDLE_NS)}
    assert spec["recipe"]["SPINDLE_NS"] == 'uuid5(CAR_NS, "spindle")'
    assert spec["mint"].startswith('uuid5(SPINDLE_NS, canonical_json({"_obj": <car_object>, "_v": <version>')
    assert spec["positional"] == {"fields": ["SourceImage", "RecordId"], "version": 1}
    assert spec["object_key"] == "_obj" and spec["version_key"] == "_v"
    assert spec["rendering"] == "str" and spec["normalize"] == ["str", "json"]
    entries = {e["name"]: e for e in doc["identities"]}
    assert list(entries) == sorted(entries) and set(entries) == set(spindle.identities())
    assert entries["l2t_mft"] == {
        "name": "l2t_mft", "map": "l2t_mft",
        "variants": ["l2t_td_create", "l2t_td_delete", "l2t_td_modify", "l2t_td_read"],
        "car_object": "file", "car_action": ["create", "delete", "modify", "read"],
        "scope": "cross_source", "version": 1,
        "identity": [{"name": "file_reference", "source": "native.file_reference"},
                     {"name": "event_time", "source": "timestamp"}],
        "fallback": {"scope": "within_source", "fields": ["SourceImage", "RecordId"], "version": 1}}
    assert entries["plaso_exec_winreg/amcache"]["variants"] == ["plaso_is_amcache"]
    assert entries["l2t_srum/network_usage"]["car_object"] == "flow"
    # a minted row's key reads _obj, _v, then the entry's declared order, values as strings
    for name, (parser, rec) in _ROWS.items():
        ev = normalize.normalize(name, _wrap(parser, rec))
        entry = next(e for e in doc["identities"]
                     if e["map"] == name and set(ev["_native"]["spindle_key"]) - {"_obj", "_v"}
                     == {i["name"] for i in e["identity"]})
        assert list(ev["_native"]["spindle_key"]) == ["_obj", "_v"] + [i["name"] for i in entry["identity"]]
        assert ev["_native"]["spindle_key"]["_v"] == entry["version"] == 1


# --------------------------------------------------------------------------- #
# the record shape: what a spindle IS, and rows validate against it
# --------------------------------------------------------------------------- #
def test_record_shape_is_the_car_row_plus_the_two_native_keys():
    doc = yaml.safe_load((MODEL_SPINDLE / "record.yml").read_text(encoding="utf-8"))
    assert doc["name"] == "spindle" and doc["properties"]["common_header"] == list(store.HEADER)
    fields = {f["name"]: f for f in doc["properties"]["spindle"]}
    assert {"guid", "car_object", "car_action", "host", "timestamp", "contributing_artefact",
            "spindle_key", "spindle_scope", "container"} <= set(fields)
    assert fields["spindle_scope"]["values"] == ["cross_source", "within_source"]
    assert fields["spindle_key"]["shape"] == {"_obj": "car_object", "_v": "identity-key version (int)",
                                              "<name>": "string"}
    assert fields["spindle_key"]["positional_names"] == ["SourceImage", "RecordId"]
    assert {"file_reference", "usn", "url", "last_write", "run_time"} <= set(fields["spindle_key"]["names"])
    assert fields["contributing_artefact"]["column"] == "source_artefact"
    assert any("re-mint" in i or "uuid5(SPINDLE_NS" in i for i in doc["invariants"])


def test_rows_validate_against_the_record_shape_and_tampering_is_caught():
    for name, (parser, rec) in _ROWS.items():
        ev = normalize.normalize(name, _wrap(parser, rec))
        assert spindle.validate_record(ev) == [], name
        # the stored form (native, not _native) validates the same way
        stored = dict(ev, native=ev["_native"])
        del stored["_native"]
        assert spindle.validate_record(stored) == [], name
    ev = normalize.normalize("l2t_mft", _wrap(*_ROWS["l2t_mft"]))
    # a positional row validates too
    pos = normalize.normalize("l2t_mft", _wrap("mft", {k: v for k, v in _ROWS["l2t_mft"][1].items()
                                                       if k != "file_reference"}))
    assert pos["_native"]["spindle_scope"] == "within_source" and spindle.validate_record(pos) == []
    # tampering: a non-v5 guid, a foreign v5 guid, a wrong scope, a key naming no entry, a wrong object
    assert any("version-5" in p for p in spindle.validate_record(dict(ev, guid=str(uuid.uuid4()))))
    foreign = ids.mint("file", {"file_reference": "844", "event_time": _TS}, 1)[0]
    assert any("re-mint" in p for p in spindle.validate_record(dict(ev, guid=foreign)))
    nat = dict(ev["_native"], spindle_scope="artefact")
    assert any("spindle_scope" in p for p in spindle.validate_record(dict(ev, _native=nat)))
    nat = dict(ev["_native"], spindle_key={"_obj": "file", "_v": 1, "something_else": "1"})
    problems = spindle.validate_record(dict(ev, _native=nat))
    assert any("match no registry entry" in p for p in problems) and any("re-mint" in p for p in problems)
    assert any("!= car_object" in p for p in spindle.validate_record(dict(ev, car_object="registry")))
    # a key at another identity-key version than the entry's: neither re-mints nor matches
    nat = dict(ev["_native"], spindle_key=dict(ev["_native"]["spindle_key"], _v=2))
    problems = spindle.validate_record(dict(ev, _native=nat))
    assert any("re-mint" in p for p in problems) and any("version 2" in p for p in problems)
    nat = dict(ev["_native"], spindle_key={k: v for k, v in ev["_native"]["spindle_key"].items() if k != "_v"})
    assert any("_v: missing" in p for p in spindle.validate_record(dict(ev, _native=nat)))
    # a row that never had a minted identity (Sysmon) is not a spindle
    assert spindle.validate_record({"car_object": "process", "guid": "{x}", "_native": {}})


def _raw_l2t(rec, parser, ts_us=1600262070462820):
    return json.dumps(dict(rec, parser=parser, timestamp=ts_us))


def test_every_minted_row_of_a_full_pipeline_run_remints_from_its_own_key(tmp_path):
    """The invariant over a REAL run — a raw l2t container split, routed,
    normalized, enriched, stored — read back from car.db: every row carrying
    native.spindle_key re-mints to its guid (ids.guid_of == the one seam),
    validates as a spindle, and every other row (Sysmon) keeps its raw guid."""
    from piiat_mitrecar import derive, pipeline
    src = tmp_path / "in"
    src.mkdir()
    rows = [_raw_l2t(_ROWS["l2t_usnjrnl"][1], "usnjrnl"),
            _raw_l2t(_ROWS["l2t_usnjrnl"][1], "usnjrnl"),                   # a duplicate line
            _raw_l2t(_ROWS["l2t_mft"][1], "mft"),
            _raw_l2t(dict(_ROWS["l2t_mft"][1], name=None), "mft"),           # the $FN twin, same time
            _raw_l2t(_ROWS["plaso_exec_prefetch"][1], "prefetch"),
            _raw_l2t(_ROWS["plaso_registry"][1], "winreg/winreg_default"),
            _raw_l2t(_ROWS["l2t_msiecf"][1], "msiecf"),
            _raw_l2t(_ROWS["l2t_utmp"][1], "utmp"),
            _raw_l2t({"data_type": "pe_coff:file", "display_name": "NTFS:\\Windows\\System32\\evil.dll",
                      "image_hostname": "M57-JO", "sha256_hash": "b5de10a0" + "0" * 56,
                      "timestamp_desc": "Creation Time"}, "pe"),
            _raw_l2t({"data_type": "pe_coff:file", "display_name": "NTFS:\\Windows\\System32\\evil.dll",
                      "image_hostname": "M57-JO", "sha256_hash": "b5de10a0" + "0" * 56,
                      "timestamp_desc": "Content Modification Time"}, "pe", 1600262070462821),
            _raw_l2t(dict(_ROWS["l2t_mft"][1], file_reference=None), "mft")]   # -> positional
    (src / "image.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (src / "Sysmon_EvtxECmd_Output.json").write_text(json.dumps({
        "EventId": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "M57-JO",
        "Provider": "Microsoft-Windows-Sysmon", "EventRecordId": 7, "TimeCreated": "2020-09-16T13:00:00Z",
        "Payload": json.dumps({"EventData": {"Data": [{"@Name": "ProcessGuid", "#text": "{P-1}"},
                                                      {"@Name": "ProcessId", "#text": "100"},
                                                      {"@Name": "Image", "#text": r"C:\a.exe"}]}})}) + "\n",
        encoding="utf-8")
    s = pipeline.process_file(str(src), str(tmp_path / "out"))
    events = derive.load_events(str(tmp_path / "out" / "car.db"))
    assert s["events"] == len(events) >= 8
    minted = [e for e in events if "spindle_key" in e["_native"]]
    assert len(minted) >= 7 and all(e["guid"] for e in events)
    for ev in minted:
        assert ev["guid"] == ids.guid_of(ev["_native"]["spindle_key"]), ev["source_artefact"]
        assert spindle.validate_record(ev) == [], ev["source_artefact"]
    assert {e["_native"]["spindle_scope"] for e in minted} == {"cross_source", "within_source"}
    sysmon = [e for e in events if "spindle_key" not in e["_native"]]
    assert [e["guid"] for e in sysmon] == ["{P-1}"]


# --------------------------------------------------------------------------- #
# the generator wiring: the CLI --check (CI) and model/generate.py
# --------------------------------------------------------------------------- #
def test_check_cli_passes_and_model_generate_wires_the_same_writer():
    r = subprocess.run([sys.executable, "-m", "piiat_mitrecar.spindle", "--check"],
                       capture_output=True, text=True, check=False, cwd=str(ROOT))
    assert r.returncode == 0 and "OK" in r.stdout, r.stdout + r.stderr
    src = (ROOT / "model" / "generate.py").read_text(encoding="utf-8")
    assert "spindle.write_snapshot" in src and "spindle.verify_registry" in src
    # the committed snapshot is exactly the CLI's rendering (the --check contract)
    assert json.dumps(yaml.safe_load(spindle.render("identity.yml")), sort_keys=True) == \
        json.dumps(yaml.safe_load((MODEL_SPINDLE / "identity.yml").read_text(encoding="utf-8")),
                   sort_keys=True)
