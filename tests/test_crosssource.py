"""The OPT-IN cross-source correlation end-stage: content nodes unioned across
finished per-source stores, cross-source derived edges carrying a stored source
boundary, the per-source stores never written. Default off."""
import hashlib
import json
import os
import sqlite3

import pytest

from piiat_mitrecar import crosssource, derive, enrich, pipeline, store, superset

_T0 = "2020-01-01T00:00:00Z"
_T1 = "2020-01-02T00:00:00Z"
_SHA = "a" * 64
_SID = "S-1-5-21-1-2-3-1001"


def _ev(obj, action, guid, host, ts=_T0, **kw):
    return dict({"car_object": obj, "car_action": action, "guid": guid, "source_host": host,
                 "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


def _build(d, events, derive_pass=True):
    """The stores the per-source pipeline leaves behind: car.db + superset.db,
    with the derived content layer when the (optional) derive pass ran."""
    d.mkdir(parents=True, exist_ok=True)
    events = enrich.enrich(events)
    st = store.CarStore(str(d / "car.db"))
    st.insert_events(events)
    st.close()
    sup = superset.build_superset_db(str(d), events)
    if derive_pass:
        derive.derive(events, sup["superset_db"], str(d))
    return d


def _digest(d):
    """The per-source store bytes — the proof the stage never wrote them."""
    return {f: hashlib.sha256((d / f).read_bytes()).hexdigest() for f in ("car.db", "superset.db")}


def _memory_host_a(tree):
    # a memory image: the running process, its image hash, its account
    return _build(tree / "memory_hostA", [
        _ev("process", "create", "P1", "HOSTA", image_path=r"C:\tools\evil.exe",
            sha256_hash=_SHA.upper(), sid=_SID, user="alice")])


def _disk_host_b(tree, derive_pass=True):
    # a disk image of ANOTHER host: the same bytes at another path, owned by the same account
    return _build(tree / "l2t_hostB", [
        _ev("file", "create", "F1", "HOSTB", ts=_T1, file_path=r"D:\staging\evil.exe",
            sha256_hash=_SHA, owner_uid=_SID)], derive_pass)


# --------------------------------------------------------------------------- #
# shared strong identities -> one entity, one cross-source edge per source pair
# --------------------------------------------------------------------------- #
def test_shared_hash_and_sid_union_into_one_entity_with_cross_source_edges(tmp_path):
    tree = tmp_path / "car"
    a, b = _memory_host_a(tree), _disk_host_b(tree)
    before = (_digest(a), _digest(b))

    out = crosssource.run(str(tree))
    assert out["sources"] == ["l2t_hostB", "memory_hostA"]      # by path under the tree
    assert out["content_layers"] == {"l2t_hostB": "superset.db", "memory_hostA": "superset.db"}
    assert out["content_nodes"] == 2 and out["cross_source_nodes"] == 2
    assert out["entity_refs"] == 4 and out["relationships"] == 2 and out["exported"] == 4
    db = tree / "crosssource" / "crosssource.db"
    assert out["crosssource_db"] == str(db) and db.is_file()

    c = sqlite3.connect(str(db))
    nodes = {r[0]: r for r in c.execute(
        "SELECT node_id, kind, ref_count, properties, first_seen, last_seen, sources, "
        "source_count, per_source, identity_value FROM content_node")}
    assert set(nodes) == {f"sha256:{_SHA}", f"sid:{_SID}"}
    # ONE unified entity per identity: case-normalized by content, both sources
    # in its provenance, properties unioned additively — neither source's
    # contribution is dropped, and each stays legible per source
    h = nodes[f"sha256:{_SHA}"]
    assert h[1] == "file_content" and h[2] == 2 and h[9] == _SHA
    props = json.loads(h[3])
    assert props["image_path"] == [r"C:\tools\evil.exe"] and props["file_path"] == [r"D:\staging\evil.exe"]
    assert (h[4], h[5]) == (_T0, _T1)
    assert json.loads(h[6]) == ["l2t_hostB", "memory_hostA"] and h[7] == 2
    per = json.loads(h[8])
    assert per["memory_hostA"] == {"identity_key": "sha256_hash", "ref_count": 1, "first_seen": _T0,
                                   "last_seen": _T0, "hosts": ["HOSTA"]}
    assert per["l2t_hostB"]["hosts"] == ["HOSTB"] and per["l2t_hostB"]["ref_count"] == 1
    s = nodes[f"sid:{_SID}"]
    assert s[1] == "user_account" and json.loads(s[6]) == ["l2t_hostB", "memory_hostA"]
    assert json.loads(s[3])["user"] == ["alice"]
    assert {json.loads(s[8])[k]["identity_key"] for k in ("memory_hostA", "l2t_hostB")} == {"sid", "owner_uid"}

    # the cross-source DERIVED edge: one per (entity, source pair), heuristic,
    # corroborated by the guids of BOTH sources, the boundary stored on it
    edges = {r[3]: r for r in c.execute(
        'SELECT "class", relationship, source_object, source_guid, target_object, target_guid, '
        "confidence, method, identity_key, inferred_end, corroborated_by, sources, "
        "source_boundary, corroboration, timestamp, source_host FROM relationship")}
    assert len(edges) == 2
    e = edges[f"sha256:{_SHA}"]
    assert e[:10] == ("derived", "corroborated", "file_content", f"sha256:{_SHA}", "file_content",
                      f"sha256:{_SHA}", "heuristic", "cross_source_hash", "hash", None)
    assert json.loads(e[10]) == ["F1", "P1"]
    assert json.loads(e[11]) == ["l2t_hostB", "memory_hostA"]
    assert json.loads(e[12]) == {"source": "l2t_hostB", "target": "memory_hostA"}
    assert json.loads(e[13]) == {"l2t_hostB": {"records": 1, "hosts": ["HOSTB"]},
                                 "memory_hostA": {"records": 1, "hosts": ["HOSTA"]}}
    assert e[14] == _T1 and e[15] == "HOSTB"           # stamped when BOTH had seen it
    u = edges[f"sid:{_SID}"]
    assert (u[1], u[7], u[8], u[6]) == ("corroborated", "cross_source_sid", "sid", "heuristic")
    assert sorted(json.loads(u[10])) == ["F1", "P1"]
    assert "definitive" not in {r[0] for r in c.execute("SELECT confidence FROM relationship")}

    # every ref carries its source (the boundary) and the record's role
    refs = set(c.execute("SELECT source, source_host, object, guid, node_id, identity_key FROM entity_ref"))
    assert ("memory_hostA", "HOSTA", "process", "P1", f"sid:{_SID}", "sid") in refs
    assert ("l2t_hostB", "HOSTB", "file", "F1", f"sid:{_SID}", "owner_uid") in refs
    assert ("l2t_hostB", "HOSTB", "file", "F1", f"sha256:{_SHA}", "sha256_hash") in refs
    # the source-boundary registry
    reg = {r[0]: r[1:] for r in c.execute("SELECT name, content_layer, hosts, content_nodes FROM source")}
    assert reg["memory_hostA"] == ("superset.db", '["HOSTA"]', 2)
    assert reg["l2t_hostB"] == ("superset.db", '["HOSTB"]', 2)
    c.close()

    # the stream: typed rows, entities then relationships, every row bounded
    lines = [json.loads(ln) for ln in open(tree / "crosssource" / "car_crosssource.jsonl")]
    assert [ln["type"] for ln in lines] == ["content_node"] * 2 + ["relationship"] * 2
    assert all(ln["sources"] == ["l2t_hostB", "memory_hostA"] for ln in lines)
    rel = [ln for ln in lines if ln["type"] == "relationship"]
    assert {ln["method"] for ln in rel} == {"cross_source_hash", "cross_source_sid"}
    assert all(ln["class"] == "derived" and ln["confidence"] == "heuristic"
               and ln["source_boundary"] == {"source": "l2t_hostB", "target": "memory_hostA"}
               and set(ln["corroborated_by"]) == {"F1", "P1"} for ln in rel)
    assert lines[0]["per_source"]["memory_hostA"]["hosts"] == ["HOSTA"]

    # the per-source stores are UNTOUCHED — byte-identical, nothing cross-source in them
    assert (_digest(a), _digest(b)) == before
    for d in (a, b):
        pc = sqlite3.connect(str(d / "superset.db"))
        assert pc.execute("SELECT count(*) FROM relationship WHERE method LIKE 'cross_source%'").fetchone() == (0,)
        assert "sources" not in [r[1] for r in pc.execute("PRAGMA table_info(content_node)")]
        assert pc.execute("SELECT count(*) FROM content_node").fetchone() == (2,)
        pc.close()
    assert not (a / "car_crosssource.jsonl").exists() and not (b / "car_crosssource.jsonl").exists()

    # idempotent: a re-run rebuilds the same aggregate
    assert crosssource.run(str(tree))["relationships"] == 2


def test_no_shared_identity_makes_no_cross_source_edge(tmp_path):
    tree = tmp_path / "car"
    a = _memory_host_a(tree)
    b = _build(tree / "l2t_hostB", [
        _ev("file", "create", "F9", "HOSTB", file_path=r"D:\other.bin", sha256_hash="b" * 64,
            owner_uid="S-1-5-21-9-9-9-500")])
    before = (_digest(a), _digest(b))
    out = crosssource.run(str(tree))
    # the aggregate still unions every entity (with ONE source each); no edge
    assert out["content_nodes"] == 4 and out["cross_source_nodes"] == 0
    assert out["relationships"] == 0 and out["exported"] == 4
    c = sqlite3.connect(out["crosssource_db"])
    assert {r[0] for r in c.execute("SELECT source_count FROM content_node")} == {1}
    assert c.execute("SELECT count(*) FROM relationship").fetchone() == (0,)
    c.close()
    lines = [json.loads(ln) for ln in open(out["jsonl"])]
    assert {ln["type"] for ln in lines} == {"content_node"}
    assert (_digest(a), _digest(b)) == before


def test_content_layer_is_derived_in_memory_when_the_derive_pass_did_not_run(tmp_path):
    """A source built WITHOUT --derive has no content layer in its superset.db:
    the stage derives it in memory by the same per-source rules, read-only —
    the source's stores stay byte-identical, nothing is written back."""
    tree = tmp_path / "car"
    a, b = _memory_host_a(tree), _disk_host_b(tree, derive_pass=False)
    before = (_digest(a), _digest(b))
    out = crosssource.run(str(tree))
    assert out["content_layers"] == {"l2t_hostB": "car.db (derived in memory, read-only)",
                                     "memory_hostA": "superset.db"}
    assert out["cross_source_nodes"] == 2 and out["relationships"] == 2
    assert (_digest(a), _digest(b)) == before
    pc = sqlite3.connect(str(b / "superset.db"))
    assert pc.execute("SELECT count(*) FROM content_node").fetchone() == (0,)
    pc.close()


def test_cli_and_out_dir(tmp_path, capsys):
    tree = tmp_path / "car"
    _memory_host_a(tree), _disk_host_b(tree)
    out = tmp_path / "elsewhere"
    assert crosssource.main([str(tree), "--out", str(out)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["relationships"] == 2 and (out / "crosssource.db").is_file()
    assert (out / "car_crosssource.jsonl").is_file() and not (tree / "crosssource").exists()
    with pytest.raises(SystemExit):
        crosssource.main([str(tmp_path / "nothing-here")])


# --------------------------------------------------------------------------- #
# opt-in: nothing in the per-source path runs it
# --------------------------------------------------------------------------- #
def _sysmon_image_load(host, hashes):
    return {"EventId": 7, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": host,
            "Provider": "Microsoft-Windows-Sysmon", "EventRecordId": 7,
            "TimeCreated": "2020-01-01T00:00:00Z",
            "Payload": json.dumps({"EventData": {"Data": [
                {"@Name": "UtcTime", "#text": "2020-01-01 00:00:00.000"},
                {"@Name": "ProcessGuid", "#text": "{OWNER-" + host + "}"},
                {"@Name": "ProcessId", "#text": "4242"},
                {"@Name": "Image", "#text": r"C:\host.exe"},
                {"@Name": "ImageLoaded", "#text": r"C:\shared.dll"},
                {"@Name": "Hashes", "#text": "SHA256=" + hashes},
                {"@Name": "Signed", "#text": "false"}]}})}


def test_pipeline_flag_is_opt_in_and_batch_only(tmp_path, capsys):
    # a mini processed tree: two hosts' event logs loading the same bytes
    for host in ("hostA", "hostB"):
        d = tmp_path / "windows_logs" / host
        d.mkdir(parents=True)
        (d / "Sysmon_EvtxECmd_Output.json").write_text(
            json.dumps(_sysmon_image_load(host.upper(), _SHA)) + "\n")
    out = tmp_path / "car"
    # default: the per-source batch only — no cross-source stage, no aggregate
    assert pipeline.main(["--batch", str(tmp_path), "--out", str(out), "--derive"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert {r["source"] for r in results} == {"windows_logs_hostA", "windows_logs_hostB"}
    assert not (out / "crosssource").exists()
    per_source = {n: _digest(out / n) for n in ("windows_logs_hostA", "windows_logs_hostB")}
    # opted in: the end-stage runs over the aggregate AFTER the sources
    assert pipeline.main(["--batch", str(tmp_path), "--out", str(out), "--derive", "--crosssource"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert [r.get("skipped") for r in results[:2]] == ["exists", "exists"]   # idempotent batch
    stage = results[-1]
    assert stage["stage"] == "crosssource" and "error" not in stage
    assert stage["sources"] == ["windows_logs_hostA", "windows_logs_hostB"]
    assert stage["cross_source_nodes"] == 1 and stage["relationships"] == 1
    assert (out / "crosssource" / "crosssource.db").is_file()
    ln = [json.loads(x) for x in open(out / "crosssource" / "car_crosssource.jsonl")]
    e = [x for x in ln if x["type"] == "relationship"][0]
    assert e["method"] == "cross_source_hash" and e["source_guid"] == f"sha256:{_SHA}"
    assert e["source_boundary"] == {"source": "windows_logs_hostA", "target": "windows_logs_hostB"}
    assert e["corroboration"]["windows_logs_hostA"]["hosts"] == ["HOSTA"]
    # the per-source stores the batch built are exactly what they were
    assert per_source == {n: _digest(out / n) for n in per_source}
    # batch-only: the single-source path has no cross-source stage
    with pytest.raises(SystemExit):
        pipeline.main(["--in", str(tmp_path / "windows_logs" / "hostA"), "--out", str(tmp_path / "x"),
                       "--crosssource"])
    assert not os.path.exists(tmp_path / "x")
