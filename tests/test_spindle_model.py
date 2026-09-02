"""The spindle identity model as DATA.

piiat_mitrecar/spindle.yml is the single source of the per-artefact identity
rules the engine mints disk-image guids from (the relationships.yml discipline:
rules are data, the engine is mechanics); model/spindle/ holds its deterministic
snapshot plus the spindle record's shape, generated like model/generate.py
generates the CAR objects. These tests hold the three — registry, maps/engine,
committed snapshot — in step, the way test_car_sources holds sources/ to the maps.
"""
import copy
import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest
import yaml

from piiat_mitrecar import enrich, ids, mappings, normalize, pipeline, sources_model, spindle, store

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
    assert set(r["scopes"]) == set(spindle.SCOPES) == {"intrinsic", "positional"}
    assert set(r["kinds"]) == set(spindle.KINDS) == {"record", "entity"}
    # every entry: a CAR object, a kind, a scope, a version, what it is validated
    # against (plaso only — cross-run within the tool — until a second tool's
    # map renders the same key on a real record), what it holds across, an
    # ordered identity of event paths
    for name, e in spindle.identities().items():
        assert e["kind"] in spindle.KINDS and e["scope"] == "intrinsic" and e["identity"], name
        assert isinstance(e["version"], int) and e["version"] >= 1, name
        assert e["validated_against"] == ["plaso"] and e["stable_across"].strip(), name
        for iname, source, mode in spindle.identity_fields(e):
            assert mode is None, (name, iname)                 # no rendering override in v1
            assert source in ("timestamp", "owning_pid") or source.startswith("native.") \
                or source in store.HEADER or "_" in source or source.isalpha(), (name, source)
        # a golden sample for every identity name, labelled real or synthetic
        g = spindle.golden(e)
        assert g["source"] in spindle.GOLDEN_SOURCES and set(g["values"]) == set(e["identity"]), name


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
    good = copy.deepcopy(spindle.rules())
    bad = copy.deepcopy(good)
    bad["identities"]["l2t_mft"]["object"] = "registry"
    bad["identities"]["l2t_usnjrnl"]["identity"]["usn"] = "native.no_such_key"
    bad["identities"]["nobody_names_me"] = {"object": "file", "scope": "intrinsic",
                                            "version": 1, "identity": {"x": "file_path"}}
    del bad["identities"]["l2t_lnk"]
    bad["identities"]["l2t_text"]["version"] = "one"
    bad["identities"]["l2t_utmp"]["identity"]["pid"] = {"source": "owning_pid", "normalize": "hex"}
    bad["identities"]["plaso_olecf"]["golden"]["source"] = "guess"
    bad["identities"]["l2t_javaidx"]["golden"]["values"]["visit_time"] = ""
    del bad["identities"]["l2t_recyclebin"]["golden"]["values"]["file_path"]
    bad["spindle"]["positional"]["golden"]["values"] = {"SourceImage": "x"}
    bad["identities"]["plaso_olecf"]["kind"] = "thing"
    del bad["identities"]["plaso_fseventsd"]["validated_against"]
    bad["identities"]["plaso_fseventsd"]["stable_across"] = ""
    monkeypatch.setattr(spindle, "_rules_cache", bad)
    problems = "\n".join(spindle.verify_registry())
    assert "plaso_olecf: kind must be one of ['record', 'entity']" in problems
    assert "plaso_fseventsd: validated_against must be" in problems
    assert "plaso_fseventsd: stable_across must" in problems
    assert "l2t_mft" in problems and "declared for 'registry'" in problems
    assert "native.no_such_key" in problems
    assert "nobody_names_me" in problems and "referenced by no map" in problems
    assert "l2t_lnk" in problems and "unregistered" in problems
    assert "l2t_text: version must be an int" in problems
    assert "l2t_utmp: identity 'pid' normalize 'hex'" in problems
    assert "plaso_olecf: golden.source" in problems
    assert "l2t_javaidx: a golden value is blank" in problems
    assert "l2t_recyclebin: golden.values names" in problems
    assert "spindle.positional.golden.values" in problems
    monkeypatch.setattr(spindle, "_rules_cache", good)
    assert spindle.verify_registry() == []


# --------------------------------------------------------------------------- #
# the snapshot: deterministic, committed in sync, drift caught
# --------------------------------------------------------------------------- #
def test_snapshot_is_deterministic_and_the_committed_one_is_in_sync(tmp_path):
    first = spindle.write_snapshot(str(tmp_path / "a"))
    again = spindle.write_snapshot(str(tmp_path / "b"))
    assert [os.path.basename(p) for p in first] == ["identity.yml", "record.yml", "golden.yml"]
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
        "kind": "record", "scope": "intrinsic", "version": 1, "validated_against": ["plaso"],
        "stable_across": spindle.entry("l2t_mft")["stable_across"],
        "identity": [{"name": "file_reference", "source": "native.file_reference"},
                     {"name": "event_time", "source": "timestamp"}],
        "fallback": {"scope": "positional", "fields": ["SourceImage", "RecordId"], "version": 1}}
    assert entries["plaso_exec_winreg/amcache"]["variants"] == ["plaso_is_amcache"]
    assert entries["l2t_srum/network_usage"]["car_object"] == "flow"
    assert {e["kind"] for e in entries.values()} == {"record", "entity"}
    assert {n for n, e in entries.items() if e["kind"] == "record"} == {"l2t_mft", "l2t_usnjrnl", "plaso_fseventsd"}
    # the external forms, resolved to the maps that carry them; the equality rule as data
    ext = {e["name"]: e for e in doc["external"]}
    assert set(ext) == set(spindle.externals()) and list(ext) == sorted(ext)
    assert ext["evtx_record"]["form"] == {"fields": ["Computer", "Channel", "EventRecordId"]}
    assert set(pipeline.EVTX_MAPS) <= set(ext["evtx_record"]["maps"]) and "process" in ext["evtx_record"]["car_object"]
    assert ext["sysmon_process_guid"] == {"name": "sysmon_process_guid", "kind": "entity",
                                          "form": {"marker": {"payload": "ProcessGuid"}}, "maps": ["evtx_sysmon"],
                                          "car_object": ["process"],
                                          "stable_across": spindle.externals()["sysmon_process_guid"]["stable_across"]}
    assert ext["zeek_uid"]["maps"] == ["zeek_conn"] and ext["zeek_fuid"]["maps"] == ["zeek_files"]
    assert ext["zeek_uid_trans_depth"]["maps"] == ["zeek_http", "zeek_smtp"]
    assert ext["jlecmd_entry"]["maps"] == ["jlecmd_dest"] and ext["recmd_value"]["maps"] == ["recmd_batch"]
    assert ext["memory_proc_offset"] ["maps"] == [] and ext["memory_proc_offset"]["form"] == {"form": "proc-{hex}"}
    assert doc["equality"]["rule"] == "exact" and doc["equality"]["key"] == ["case", "source_host", "car_object", "guid"]
    assert doc["equality"]["requires"] == {"scope": "intrinsic", "kind": ["record", "entity"], "same_version": True}
    assert doc["equality"]["never"] == "positional"
    # a minted row's key reads _obj, _v, then the entry's declared order, values as strings
    for name, (parser, rec) in _ROWS.items():
        ev = normalize.normalize(name, _wrap(parser, rec))
        entry = next(e for e in doc["identities"]
                     if e["map"] == name and set(ev["_native"]["spindle_key"]) - {"_obj", "_v"}
                     == {i["name"] for i in e["identity"]})
        assert list(ev["_native"]["spindle_key"]) == ["_obj", "_v"] + [i["name"] for i in entry["identity"]]
        assert ev["_native"]["spindle_key"]["_v"] == entry["version"] == 1


# --------------------------------------------------------------------------- #
# the golden vectors: the mint pinned per entry, and the change protocol's gate
# --------------------------------------------------------------------------- #
def test_golden_vectors_pin_the_mint_and_gate_the_change_protocol(tmp_path, monkeypatch):
    doc = yaml.safe_load((MODEL_SPINDLE / "golden.yml").read_text(encoding="utf-8"))
    recipe = doc["spindle"]["recipe"]
    assert recipe["canonical_json"] == {"input": {"b": 1, "a": "é"}, "output": '{"a":"é","b":1}'}
    assert recipe["namespaces"] == {"STIX_NS": str(ids.STIX_NS), "CAR_NS": str(ids.CAR_NS),
                                    "SPINDLE_NS": str(ids.SPINDLE_NS)}
    entries = {e["name"]: e for e in doc["identities"]}
    assert list(entries) == sorted(entries) and set(entries) == set(spindle.identities())
    # every vector is what the ONE seam yields for the entry's sample at its version
    for name, g in entries.items():
        e = spindle.entry(name)
        guid, key = ids.mint(e["object"], e["golden"]["values"], e["version"])
        assert (g["guid"], g["key"], g["version"], g["source"]) == \
            (guid, key, e["version"], e["golden"]["source"]), name
        assert ids.guid_of(g["key"]) == g["guid"] and g["key"]["_v"] == g["version"]
    assert {g["source"] for g in entries.values()} == {"real", "synthetic"}
    assert doc["positional"] == {"version": 1, "fields": ["SourceImage", "RecordId"], "source": "synthetic",
                                 "key": {"_obj": "file", "_v": 1, "SourceImage": "M57-JO.jsonl", "RecordId": "42"},
                                 "guid": ids.mint("file", {"SourceImage": "M57-JO.jsonl", "RecordId": 42}, 1)[0]}
    # the engine mints the SAME guid for a row carrying the sample (the real M57 rows)
    usn = normalize.normalize("l2t_usnjrnl", _wrap(*_ROWS["l2t_usnjrnl"]))
    assert usn["guid"] == entries["l2t_usnjrnl"]["guid"]
    pf = normalize.normalize("plaso_exec_prefetch", _wrap("prefetch", _ROWS["plaso_exec_prefetch"][1],
                                                          ts="2009-11-20T09:31:29.671875Z"))
    assert pf["guid"] == entries["plaso_exec_prefetch"]["guid"]
    fs = normalize.normalize("l2t_filestat", _wrap("filestat", {
        "data_type": "fs:stat", "display_name": "NTFS:\\Program Files\\app\\FPEXT.MSG",
        "filename": "\\Program Files\\app\\FPEXT.MSG", "image_hostname": "M57-JO",
        "timestamp_desc": "Content Modification Time"}))
    assert fs["guid"] == entries["l2t_filestat"]["guid"]
    pos = normalize.normalize("l2t_mft", _wrap("mft", {k: v for k, v in _ROWS["l2t_mft"][1].items()
                                                       if k != "file_reference"}, record_id=42))
    assert pos["guid"] == doc["positional"]["guid"]
    # the gate: against a committed table, a sample (or identity) that moves
    # the guid without a version bump is refused — by the check AND the writer
    out = tmp_path / "m"
    spindle.write_snapshot(str(out))
    assert spindle.verify_golden(str(out)) == []
    good = spindle.rules()
    bad = copy.deepcopy(good)
    bad["identities"]["l2t_mft"]["golden"]["values"]["file_reference"] = 844
    monkeypatch.setattr(spindle, "_rules_cache", bad)
    problems = spindle.verify_golden(str(out))
    assert len(problems) == 1 and problems[0].startswith("l2t_mft:") and "without a version bump" in problems[0]
    with pytest.raises(ValueError, match="l2t_mft"):
        spindle.write_snapshot(str(out))
    # bumped with it: legitimate (the snapshot is then merely out of date)
    bad["identities"]["l2t_mft"]["version"] = 2
    assert spindle.verify_golden(str(out)) == [] and spindle.verify_snapshot(str(out))
    # the positional vector is gated the same way
    bad["spindle"]["positional"]["golden"]["values"]["RecordId"] = 43
    assert [p for p in spindle.verify_golden(str(out)) if p.startswith("positional:")]
    monkeypatch.setattr(spindle, "_rules_cache", good)
    # a committed vector whose version moved without its guid, and a moved recipe
    stale = yaml.safe_load((out / "golden.yml").read_text(encoding="utf-8"))
    next(e for e in stale["identities"] if e["name"] == "l2t_usnjrnl")["version"] = 2
    stale["spindle"]["recipe"]["namespaces"]["SPINDLE_NS"] = str(uuid.uuid4())
    (out / "golden.yml").write_text(yaml.safe_dump(stale, allow_unicode=True), encoding="utf-8")
    problems = spindle.verify_golden(str(out))
    assert any("recipe vector moved" in p for p in problems)
    assert any(p.startswith("l2t_usnjrnl:") and "stale" in p for p in problems)
    # the CLI refuses the same way (INVALID, before the snapshot comparison)
    r = subprocess.run([sys.executable, "-m", "piiat_mitrecar.spindle", "--check", "--out", str(out)],
                       capture_output=True, text=True, check=False, cwd=str(ROOT))
    assert r.returncode == 1 and "INVALID" in r.stderr and "recipe vector" in r.stderr


# --------------------------------------------------------------------------- #
# the external forms: every raw guid form a map carries, as data, drift-tested
# --------------------------------------------------------------------------- #
def test_external_forms_are_exactly_the_raw_guid_forms_the_maps_carry():
    forms = {n: spindle._form_of(e) for n, e in spindle.externals().items()}   # noqa: SLF001
    assert all(f is not None for f in forms.values())
    plaso = {k for k, d in sources_model.DERIVATIONS.items() if d.tool == sources_model.PLASO_TOOL}
    carried = set()
    for key in set(mappings.MAPPINGS) - plaso:
        for leaf in sources_model._leaves(mappings.MAPPINGS[key]):   # noqa: SLF001
            form = spindle._leaf_form(leaf["guid"])                  # noqa: SLF001
            hits = [n for n, f in forms.items() if f == form]
            assert len(hits) == 1, (key, leaf["guid"])               # exactly one declared form
            carried.add(hits[0])
    # every map-shaped form is carried; the memory form is the derive rule's
    assert carried == set(forms) - {"memory_proc_offset"}
    assert forms["memory_proc_offset"]["form"] == enrich.rules()["derived"]["identities"]["offset"]["guid_form"]
    assert {e["kind"] for e in spindle.externals().values()} == {"record", "entity"}
    # the golden vectors are what the engine renders for the samples
    doc = yaml.safe_load((MODEL_SPINDLE / "golden.yml").read_text(encoding="utf-8"))
    vectors = {e["name"]: e["guid"] for e in doc["external"]}
    assert vectors == {
        "evtx_record": "process-WIN-1M3263ACE5D-Security-2623",         # the real LoneWolf 4688 record
        "sysmon_process_guid": "{DFAE8213-70EB-5CDD-0000-0010F66D0A00}",  # a real Sysmon ProcessGuid
        "zeek_uid": "CtEReq24zLXEGt4V67", "zeek_uid_trans_depth": "http-Cno6-1", "zeek_fuid": "file-FdEQ",
        "jlecmd_entry": "file-/in/fb3b.automaticDestinations-ms-1",
        "recmd_value": "registry-/in/UsrClass.dat-S-1-5-21-1_Classes\\X-LangID",
        "memory_proc_offset": "proc-1a2b"}
    for e in doc["external"]:
        assert e["guid"] == spindle.external_vector(spindle.externals()[e["name"]])
        assert e["kind"] == spindle.externals()[e["name"]]["kind"] and e["source"] in ("real", "synthetic")
    # through the maps: the Sysmon row carries the ProcessGuid form, the EVTX record form
    ev = normalize.normalize("evtx_process", {
        "EventId": 4688, "Channel": "Security", "Computer": "WIN-1M3263ACE5D", "EventRecordId": 2623,
        "TimeCreated": "2018-03-27T12:11:42Z",
        "Payload": json.dumps({"EventData": {"Data": [{"@Name": "NewProcessName", "#text": r"C:\smss.exe"},
                                                      {"@Name": "NewProcessId", "#text": "0x174"}]}})})
    assert ev["guid"] == vectors["evtx_record"]


def test_external_and_equality_drift_is_caught(monkeypatch):
    good = copy.deepcopy(spindle.rules())
    bad = copy.deepcopy(good)
    del bad["external"]["zeek_fuid"]                                     # a leaf's form now undeclared
    bad["external"]["nobody_carries_me"] = dict(bad["external"]["jlecmd_entry"], form={"field": "Nope"})
    bad["external"]["memory_proc_offset"]["form"] = {"form": "eprocess-{hex}"}
    bad["external"]["recmd_value"]["kind"] = "row"
    bad["external"]["zeek_uid"]["golden"]["values"] = {"uid": "", "extra": 1}
    bad["external"]["evtx_record"]["form"] = {"fields": [], "field": "x"}
    bad["equality"]["requires"]["same_version"] = False
    bad["equality"]["never"] = "nothing"
    bad["spindle"]["kinds"] = {"record": "x"}
    monkeypatch.setattr(spindle, "_rules_cache", bad)
    problems = "\n".join(spindle.verify_registry())
    assert any(p.startswith("zeek_files") and "raw guid form {'fields': ['fuid']} matches 0 external entries" in p
               for p in problems.splitlines())
    assert "external nobody_carries_me: carried by no map leaf" in problems
    assert "external memory_proc_offset: form 'eprocess-{hex}' != relationships.yml" in problems
    assert "external recmd_value: kind must be one of" in problems
    assert "external zeek_uid: golden.values must sample exactly ['uid']" in problems
    assert "external evtx_record: form must be exactly one of" in problems
    assert "equality.requires must be" in problems and "equality.never must be positional" in problems
    assert "spindle.kinds must be exactly" in problems
    # a leaf that declares no guid form at all: no mapped row may be guid-less
    monkeypatch.setattr(spindle, "_rules_cache", good)
    leaf = sources_model._leaves(mappings.MAPPINGS["zeek_conn"])[0]    # noqa: SLF001
    monkeypatch.setitem(leaf, "guid", {"none": True})
    assert any("zeek_conn" in p and "no mapped row is guid-less" in p for p in spindle.verify_registry())


# --------------------------------------------------------------------------- #
# the #41 predicate: what may be equated across sources
# --------------------------------------------------------------------------- #
def test_equatable_across_sources_is_intrinsic_record_or_entity_or_an_external_form():
    intrinsic = normalize.normalize("l2t_usnjrnl", _wrap(*_ROWS["l2t_usnjrnl"]))
    assert spindle.entry_of(intrinsic) is spindle.entry("l2t_usnjrnl")
    assert spindle.equatable_across_sources(intrinsic)
    # its stored form too
    assert spindle.equatable_across_sources(dict(intrinsic, native=intrinsic["_native"], _native=None))
    # an entity-kind spindle (a PE, no time) is equatable; a positional row never is
    pe = normalize.normalize("plaso_pecoff", _wrap("pe", {
        "data_type": "pe_coff:file", "display_name": "NTFS:\\Windows\\System32\\evil.dll",
        "image_hostname": "M57-JO", "sha256_hash": "b5de10a0" + "0" * 56, "timestamp_desc": "Creation Time"}))
    assert spindle.entry_of(pe)["kind"] == "entity" and spindle.equatable_across_sources(pe)
    pos = normalize.normalize("l2t_mft", _wrap("mft", {k: v for k, v in _ROWS["l2t_mft"][1].items()
                                                       if k != "file_reference"}))
    assert pos["_native"]["spindle_scope"] == "positional" and spindle.entry_of(pos) is None
    assert not spindle.equatable_across_sources(pos)
    # an intrinsic-looking key that matches no entry resolves to no kind: not equatable
    nat = dict(intrinsic["_native"], spindle_key={"_obj": "file", "_v": 1, "something": "1"})
    assert not spindle.equatable_across_sources(dict(intrinsic, _native=nat))
    # an external form (a sensor's own id) equates by exact value; a guid-less row never
    assert spindle.equatable_across_sources({"car_object": "process", "guid": "{P-1}", "_native": {}})
    assert spindle.equatable_across_sources({"car_object": "process", "guid": "proc-1a2b", "_native": {}})
    assert not spindle.equatable_across_sources({"car_object": "process", "guid": None, "_native": {}})
    assert not spindle.equatable_across_sources(dict(intrinsic, guid=None))


# --------------------------------------------------------------------------- #
# the record shape: what a spindle IS, and rows validate against it
# --------------------------------------------------------------------------- #
def test_record_shape_is_the_car_row_plus_the_two_native_keys():
    doc = yaml.safe_load((MODEL_SPINDLE / "record.yml").read_text(encoding="utf-8"))
    assert doc["name"] == "spindle" and doc["properties"]["common_header"] == list(store.HEADER)
    fields = {f["name"]: f for f in doc["properties"]["spindle"]}
    assert {"guid", "car_object", "car_action", "host", "timestamp", "contributing_artefact",
            "spindle_key", "spindle_scope", "spindle_ref", "container"} <= set(fields)
    assert fields["spindle_ref"]["column"] == "native.spindle_ref" and \
        set(fields["spindle_ref"]["shape"]) == {"SourceImage", "RecordId"}
    assert fields["spindle_scope"]["values"] == ["intrinsic", "positional"]
    assert fields["kind"]["values"] == ["record", "entity"]
    assert any("equatable across sources" in i for i in doc["invariants"])
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
    assert pos["_native"]["spindle_scope"] == "positional" and spindle.validate_record(pos) == []
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
    # the provenance outside the key is part of the shape: every minted row carries it
    assert ev["_native"]["spindle_ref"] == {"SourceImage": "M57-JO.jsonl", "RecordId": 7}
    nat = {k: v for k, v in ev["_native"].items() if k != "spindle_ref"}
    assert any("spindle_ref: missing" in p for p in spindle.validate_record(dict(ev, _native=nat)))
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
        assert ev["_native"]["spindle_ref"]["SourceImage"] == "image.jsonl"        # provenance, outside the key
    assert {e["_native"]["spindle_scope"] for e in minted} == {"intrinsic", "positional"}
    # the duplicate usnjrnl line, the $SI/$FN mft twins and the two PE stamp rows
    # FOLDED additively, each counting its contributors
    folded = {e["source_artefact"]: e["_native"] for e in minted if "contributions" in e["_native"]}
    assert set(folded) == {"l2t_usnjrnl", "l2t_mft", "plaso_pecoff"}
    assert folded["l2t_mft"]["contributions"] == 2
    assert folded["l2t_usnjrnl"]["contributions"] == 2 and \
        [c["spindle_ref"]["RecordId"] for c in folded["l2t_usnjrnl"]["contributed_by"]] == [1, 2]
    assert folded["plaso_pecoff"]["contributions"] == 2 and "compile_time" in folded["plaso_pecoff"] \
        and "pe_table_time" in folded["plaso_pecoff"]
    sysmon = [e for e in events if "spindle_key" not in e["_native"]]
    assert [e["guid"] for e in sysmon] == ["{P-1}"] and "spindle_ref" not in sysmon[0]["_native"]


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
