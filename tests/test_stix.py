"""The STIX 2.1 projection: derived from car.db + superset.db at export —
spec-deterministic global ids for content, case-scoped ids for instances, both
relationship classes as labelled SROs, inferred ends flagged, never asserted."""
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import uuid

from piiat_mitrecar import derive, enrich, pipeline, stix, store, superset

ROOT = pathlib.Path(__file__).resolve().parent.parent
_H = "H"
_T0 = "2020-01-01T00:00:00Z"
_SHA = "a" * 64
_MD5 = "b" * 32
_ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _proc(guid, ts=_T0, **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": _H, "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


def _ev(obj, action, guid, ts=_T0, **kw):
    return dict({"car_object": obj, "car_action": action, "guid": guid,
                 "source_host": _H, "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


def _build(d, events):
    """The stores the pipeline leaves behind: car.db + superset.db with both classes."""
    d.mkdir(parents=True, exist_ok=True)
    events = enrich.enrich(events)
    st = store.CarStore(str(d / "car.db"))
    st.insert_events(events)
    st.close()
    sup = superset.build_superset_db(str(d), events)
    derive.derive(events, sup["superset_db"], str(d))
    return d


def _bundle(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _of(b, t):
    return [o for o in b["objects"] if o["type"] == t]


def _validator():
    spec = importlib.util.spec_from_file_location("car_stix_validate", ROOT / "model" / "stix" / "validate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# ids: content-keyed = spec-deterministic global; instances = case-scoped
# --------------------------------------------------------------------------- #
def test_content_keyed_file_gets_spec_global_id_across_runs_and_cases(tmp_path):
    events = [_proc("P1", image_path=r"C:\a.exe", sha256_hash=_SHA.upper(), md5_hash=_MD5,
                    sid="S-1-5-21-1-2-3-1001", user="alice"),
              _ev("file", "create", "F1", ts="2020-01-01T00:00:01Z", file_path=r"C:\a.exe",
                  sha256_hash=_SHA)]
    a, b = _build(tmp_path / "a", events), _build(tmp_path / "b", events)
    s1 = stix.export(str(a), case="case-one")
    s2 = stix.export(str(b), case="case-two")
    b1, b2 = _bundle(s1["bundle"]), _bundle(s2["bundle"])

    # ONE content file, all the hashes the co-referencing records carried, and
    # the §2.9 id from the preferred hash alone (MD5 before SHA-256), no name
    content = [o for o in _of(b1, "file") if o.get("x_car_content")]
    assert len(content) == 1
    f = content[0]
    assert f["hashes"] == {"MD5": _MD5, "SHA-256": _SHA} and "name" not in f
    expect = "file--" + str(uuid.uuid5(stix.STIX_NS, '{"hashes":{"MD5":"' + _MD5 + '"}}'))
    assert f["id"] == expect and f["x_car_ref_count"] == 3
    assert set(f["x_car_paths"]) == {r"C:\a.exe"} and f["x_car_names"] == ["a.exe"]
    # the same content in ANOTHER case (another run) is the same object
    assert [o["id"] for o in _of(b2, "file") if o.get("x_car_content")] == [expect]
    # the file-at-path instance binds to it and is itself case-scoped
    inst1 = [o for o in _of(b1, "file") if o.get("x_car_path") == r"C:\a.exe"]
    inst2 = [o for o in _of(b2, "file") if o.get("x_car_path") == r"C:\a.exe"]
    assert len(inst1) == len(inst2) == 1
    assert inst1[0]["x_car_content_ref"] == inst2[0]["x_car_content_ref"] == expect
    assert inst1[0]["id"] != inst2[0]["id"]
    # the instance at that path is ONE SCO filled from both rows (the process
    # image and the file event): additive, the MD5 only the process row carried included
    assert inst1[0]["hashes"] == {"MD5": _MD5, "SHA-256": _SHA} and "x_car_conflicts" not in inst1[0]
    # the account by real SID is global too (the SID alone contributes); the process is case-scoped
    expect_u = "user-account--" + str(uuid.uuid5(stix.STIX_NS, '{"user_id":"S-1-5-21-1-2-3-1001"}'))
    ids1, ids2 = {o["id"] for o in b1["objects"]}, {o["id"] for o in b2["objects"]}
    assert expect_u in ids1 and expect_u in ids2
    u = next(o for o in b1["objects"] if o["id"] == expect_u)
    assert u["display_name"] == "alice" and "account_login" not in u
    (p1,), (p2,) = _of(b1, "process"), _of(b2, "process")
    assert p1["id"] != p2["id"] and p1["creator_user_ref"] == expect_u
    assert p1["x_car_entity_id"] == p2["x_car_entity_id"] == "P1"
    # a re-export of the same case is byte-identical
    again = tmp_path / "again.json"
    stix.export(str(a), out_path=str(again), case="case-one")
    assert again.read_bytes() == pathlib.Path(s1["bundle"]).read_bytes()


# --------------------------------------------------------------------------- #
# both relationship classes are SROs, labelled by class + method
# --------------------------------------------------------------------------- #
def test_declared_and_derived_relationships_are_sros_labelled_by_class(tmp_path):
    events = [_proc("P1", image_path=r"C:\a.exe", sha256_hash=_SHA, pid=10),
              _ev("file", "create", "F1", ts="2020-01-01T00:00:01Z", file_path=r"C:\a.exe",
                  sha256_hash=_SHA),
              _ev("module", "load", "M1", ts="2020-01-01T00:00:02Z", owning_guid_native="P1",
                  image_path=r"C:\a.exe", module_path=r"C:\x.dll", pid=10)]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])
    rels = _of(b, "relationship")
    by = {(r["x_car_class"], r["relationship_type"], r["x_car_method"]): r for r in rels}
    assert set(by) == {("declared", "executed", "image_path"),     # the cascade: file_path == image_path
                       ("derived", "executed", "shared_hash"),     # derive: the same bytes, 1:1
                       ("declared", "loaded", "native_guid")}      # the cascade: owner by ProcessGuid
    (proc,) = _of(b, "process")
    exe = next(o for o in _of(b, "file") if o.get("x_car_path") == r"C:\a.exe")
    dll = next(o for o in _of(b, "file") if o.get("x_car_path") == r"C:\x.dll")
    declared, derived = by[("declared", "executed", "image_path")], by[("derived", "executed", "shared_hash")]
    for r in (declared, derived):
        assert (r["source_ref"], r["target_ref"]) == (proc["id"], exe["id"])
        assert r["created_by_ref"] == stix.PRODUCER["id"] and "x_car_inferred_end" not in r
    assert declared["id"] != derived["id"]
    assert declared["labels"] == ["car:declared", "car:image_path"] and declared["confidence"] == 50
    assert derived["labels"] == ["car:derived", "car:shared_hash"] and derived["confidence"] == 100
    assert derived["x_car_identity_key"] == "sha256_hash" and derived["x_car_corroborated_by"] == ["P1", "F1"]
    loaded = by[("declared", "loaded", "native_guid")]
    assert (loaded["source_ref"], loaded["target_ref"]) == (proc["id"], dll["id"])
    assert loaded["start_time"] == "2020-01-01T00:00:02.000Z" and loaded["confidence"] == 100
    # the spoke's observation references the OWNING process (owning_guid -> process.entity_id)
    obs = next(o for o in _of(b, "observed-data") if o["x_car_object"] == "module")
    assert obs["x_car_process_entity_id"] == "P1" and proc["id"] in obs["object_refs"]
    assert obs["x_car_roles"][proc["id"]] == ["owning_guid"] and obs["x_car_event_id"] == "M1"
    # the cascade's trace rides in native, verbatim — it made no SRO of its own
    fobs = next(o for o in _of(b, "observed-data") if o["x_car_object"] == "file")
    assert fobs["x_car_native"]["executed_as_process_guid"] == "P1"
    assert len(rels) == 3


# --------------------------------------------------------------------------- #
# an inferred end is a flagged, opinion-style object — never an assertion
# --------------------------------------------------------------------------- #
def test_inferred_end_is_flagged_never_asserted(tmp_path):
    gone = "{GONE-0001}"
    events = [_ev("module", "load", "M1", owning_pid=4242, owning_guid_native=gone,
                  image_path=r"C:\evil.exe", module_path=r"C:\x.dll", pid=4242),
              _proc("P2", ts="2020-01-01T00:00:05Z", ppid=4242, parent_image_path=r"C:\evil.exe",
                    _native={"ParentProcessGuid": gone})]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])
    (n,) = _of(b, "x-car-inferred-node")
    assert n["x_car_inferred"] is True and n["x_car_asserted"] is False
    assert n["x_car_would_be"] == "process" and n["x_car_node_id"] == gone
    assert n["confidence"] == 20 and n["labels"] == ["car:inferred", "car:reconstructed"]
    assert "reconstructed, not evidence" in n["x_car_reason"] and n["x_car_method"] == "native_guid"
    assert n["x_car_properties"]["pid"] == 4242 and n["x_car_properties"]["image_path"] == r"C:\evil.exe"
    assert set(n["x_car_corroborated_by"]) == {"M1", "P2"}
    obs = _of(b, "observed-data")
    assert set(n["x_car_corroborating_refs"]) == {o["id"] for o in obs}
    # never a process SCO, never inside an observation
    assert [p["x_car_entity_id"] for p in _of(b, "process")] == ["P2"]
    assert all(n["id"] not in o["object_refs"] for o in obs)
    # the derived SROs end on the flag and say so
    inf = [r for r in _of(b, "relationship") if r.get("x_car_inferred_end")]
    assert {(r["relationship_type"], r["x_car_inferred_end"], r["x_car_class"], r["x_car_confidence"])
            for r in inf} == {("loaded", "source", "derived", "inferred"),
                              ("created", "source", "derived", "inferred")}
    assert all(r["source_ref"] == n["id"] and r["confidence"] == 20 for r in inf)
    # the spoke's unresolved acting columns stay on its observation: nothing minted from the spoke
    m = next(o for o in obs if o["x_car_object"] == "module")
    assert "x_car_process_entity_id" not in m and m["x_car_fields"]["image_path"] == r"C:\evil.exe"
    # the child names its lost parent as data, not as a parent_ref
    (p2,) = _of(b, "process")
    assert "parent_ref" not in p2 and p2["x_car_parent"] == {"pid": 4242, "image_path": r"C:\evil.exe"}


def test_thread_src_pid_is_consumed_not_duplicated_in_x_car_fields(tmp_path):
    # A thread with no owning_guid: _acting never runs to claim src_pid, so
    # _b_thread must consume the column it homes onto the x-car-thread SCO —
    # otherwise it leaks (duplicates) into the observation's x_car_fields.
    events = [_ev("thread", "create", "T1", src_pid=1234, src_tid=7, tgt_pid=99)]
    b = _bundle(stix.export(str(_build(tmp_path, events)), case="c")["bundle"])
    (t,) = _of(b, "x-car-thread")
    assert t["src_pid"] == 1234
    (obs,) = _of(b, "observed-data")
    # with src_pid (and the other columns) consumed, leftovers is empty and the
    # export prunes x_car_fields entirely; pre-fix it would carry {"src_pid": ...}.
    assert "src_pid" not in obs.get("x_car_fields", {})


# --------------------------------------------------------------------------- #
# the contract snapshot is in step with the engine
# --------------------------------------------------------------------------- #
def test_contract_snapshot_is_in_step_with_the_engine():
    v = _validator()
    car = v.load_car_model()
    conventions, objects = v.load_contract()
    assert v.validate(car, conventions, objects) == []
    assert set(objects) == set(stix.OBJECTS) == set(car)
    for obj, spec in stix.OBJECTS.items():
        for k in ("sco", "sro_end", "hash_subject", "acting"):
            assert objects[obj][k] == spec[k], (obj, k)
    assert conventions["engine_declarations"]["hash_subject"] == \
        {o: s["hash_subject"] for o, s in stix.OBJECTS.items() if s["hash_subject"]}
    # drift is caught: a field without a decision, a decision without a field, a wrong join key
    objects["process"]["properties"].pop("pid")
    objects["file"]["properties"]["not_a_field"] = "x_car_fields"
    conventions["engine_declarations"]["native_only_join_keys"][0]["key"] = "native.uid"
    errors = v.validate(car, conventions, objects)
    assert any("process.pid" in e and "no projection entry" in e for e in errors)
    assert any("not_a_field" in e and "orphan" in e for e in errors)
    assert any("http_file_transfer" in e and "native.uid" in e for e in errors)
    r = subprocess.run([sys.executable, str(ROOT / "model" / "stix" / "validate.py")],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "car-stix projection OK" in r.stdout, r.stdout + r.stderr


# --------------------------------------------------------------------------- #
# the export step: CLI + pipeline flag, on a tiny fixture; bundle integrity
# --------------------------------------------------------------------------- #
def _sysmon(eid, rid, data):
    payload = {"EventData": {"Data": [{"@Name": k, "#text": v} for k, v in data.items()]}}
    return {"EventId": eid, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "HOSTA",
            "Provider": "Microsoft-Windows-Sysmon", "EventRecordId": rid,
            "TimeCreated": f"2020-01-01T00:00:0{rid}Z", "Payload": json.dumps(payload)}


def test_export_step_cli_and_pipeline_flag(tmp_path, capsys):
    src = tmp_path / "in"
    src.mkdir()
    recs = [_sysmon(1, 1, {"UtcTime": "2020-01-01 00:00:01.000", "ProcessGuid": "{P-1}", "ProcessId": "100",
                           "Image": r"C:\evil.exe", "CommandLine": "evil.exe /x", "User": r"CORP\alice",
                           "Hashes": "SHA256=" + _SHA + ",MD5=" + _MD5, "ParentProcessGuid": "{LOST}",
                           "ParentProcessId": "4", "ParentImage": r"C:\Windows\explorer.exe"}),
            _sysmon(7, 2, {"UtcTime": "2020-01-01 00:00:02.000", "ProcessGuid": "{P-1}", "ProcessId": "100",
                           "Image": r"C:\evil.exe", "ImageLoaded": r"C:\x.dll", "Hashes": "SHA256=" + _SHA,
                           "Signed": "false"})]
    (src / "Sysmon_EvtxECmd_Output.json").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    out = tmp_path / "out"
    s = pipeline.process_file(str(src), str(out), derive_pass=True)
    assert s["events"] == 2 and s["inferred_nodes"] == 1

    r = subprocess.run([sys.executable, "-m", "piiat_mitrecar.stix", "export", str(out), "--case", "smoke"],
                       capture_output=True, text=True, check=False, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr
    summary = json.loads(r.stdout)
    assert summary["bundle"] == str(out / "stix_bundle.json") and summary["case"] == "smoke"
    assert summary["relationships_declared"] >= 1 and summary["relationships_derived"] >= 1
    assert summary["by_type"]["observed-data"] == 2 and summary["by_type"]["x-car-inferred-node"] == 1
    b = _bundle(summary["bundle"])
    assert b["type"] == "bundle" and b["objects"][0] == stix.PRODUCER
    ids = [o["id"] for o in b["objects"]]
    assert len(ids) == len(set(ids)) and all(_ID_RE.match(i) for i in ids)
    # every embedded reference resolves inside the bundle; observations never
    # reference an inferred node and always reference something
    known = set(ids)
    for o in b["objects"]:
        for k, v in o.items():
            refs = v if k.endswith("_refs") else [v] if k.endswith("_ref") else []
            assert all(x in known for x in refs), (o["type"], k, v)
        if o["type"] == "observed-data":
            assert o["object_refs"] and not any(x.startswith("x-car-inferred-node--") for x in o["object_refs"])
            assert o["first_observed"].endswith("Z") and o["number_observed"] == 1
    # the process is one SCO filled from both rows; its image binds to the global content file
    (p,) = _of(b, "process")
    assert p["pid"] == 100 and p["command_line"] == "evil.exe /x"
    image = next(o for o in b["objects"] if o["id"] == p["image_ref"])
    assert image["x_car_content_ref"] == "file--" + str(uuid.uuid5(stix.STIX_NS, '{"hashes":{"MD5":"' + _MD5 + '"}}'))
    # the same export as a pipeline step
    rc = pipeline.main(["--in", str(src), "--out", str(tmp_path / "out2"), "--derive", "--stix"])
    ps = json.loads(capsys.readouterr().out)
    assert rc == 0 and ps["stix"]["bundle"] == str(tmp_path / "out2" / "stix_bundle.json")
    assert os.path.isfile(ps["stix"]["bundle"]) and ps["stix"]["case"] == "out2"
