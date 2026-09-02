"""The DERIVED relationship class (D4): additive coalescing, strong-identity
1:1 links, and reconstruction into flagged inferred nodes — never CAR rows."""
import json
import os
import sqlite3

from piiat_mitrecar import derive, enrich, store, superset

_H = "H"
_T0 = "2020-01-01T00:00:00Z"
_SHA = "a" * 64


def _proc(guid, ts=_T0, **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": _H, "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


def _ev(obj, action, guid, ts=_T0, **kw):
    return dict({"car_object": obj, "car_action": action, "guid": guid,
                 "source_host": _H, "timestamp": ts, "source_artefact": "evtx_sysmon"}, **kw)


# --------------------------------------------------------------------------- #
# additive coalescing
# --------------------------------------------------------------------------- #
def test_coalesce_is_additive_no_source_removed_conflicts_in_native():
    a = _ev("process", "create", "P1", pid=10, image_path=r"C:\a.exe", user="alice",
            source_artefact="evtx_sysmon", _native={"EventId": 1, "LogonId": "0x1"})
    b = _ev("process", "create", "P1", pid=10, command_line="a.exe /x", user="Alice",
            sha256_hash=_SHA, source_artefact="l2t_winevt",
            _native={"EventId": 1, "LogonId": "0x2", "parser": "winevtx"})
    out = derive.coalesce([a, b])
    assert len(out) == 1
    ev = out[0]
    # every property either source supplied is on the ONE entry
    assert ev["image_path"] == r"C:\a.exe" and ev["command_line"] == "a.exe /x"
    assert ev["sha256_hash"] == _SHA and ev["pid"] == 10
    # the prior source's value is never overwritten; the disagreeing value is
    # preserved in native — never nulled, never dropped
    assert ev["user"] == "alice"
    nat = ev["_native"]
    assert nat["coalesced_sources"] == ["evtx_sysmon", "l2t_winevt"]
    assert nat["coalesced_conflicts"]["user"] == [{"value": "Alice", "source_artefact": "l2t_winevt"}]
    assert nat["coalesced_conflicts"]["native.LogonId"] == [{"value": "0x2", "source_artefact": "l2t_winevt"}]
    # native fills additively too
    assert nat["LogonId"] == "0x1" and nat["parser"] == "winevtx"
    # enrich's dedupe then has nothing to drop: the coalesced row survives intact
    enriched = enrich.enrich(out)
    assert len(enriched) == 1 and enriched[0]["command_line"] == "a.exe /x"


def test_coalesce_never_collapses_identity_less_rows():
    rows = [_ev("file", "create", None, file_path="x"), _ev("file", "create", None, file_path="y")]
    assert len(derive.coalesce(rows)) == 2


# --------------------------------------------------------------------------- #
# derived 1:1 links on a shared strong identity
# --------------------------------------------------------------------------- #
def test_derived_link_on_shared_hash_and_content_entities(tmp_path):
    events = [
        _proc("P1", image_path=r"C:\tools\evil.exe", sha256_hash=_SHA.upper(),
              sid="S-1-5-21-1-2-3-1001", user="alice"),
        _ev("file", "create", "F1", ts="2019-12-31T23:59:00Z", file_path=r"C:\Tools\EVIL.EXE",
            sha256_hash=_SHA, owner_uid="S-1-5-21-1-2-3-1001"),
        # a second file record with the same bytes at ANOTHER path: not the 1:1 end
        _ev("file", "create", "F2", file_path=r"C:\backup\evil.bak", sha256_hash=_SHA),
        # a well-known SID identifies no account: no content node
        _ev("user_session", "login", "U1", uid="S-1-5-18", user="SYSTEM"),
    ]
    sup = str(tmp_path / "superset.db")
    superset.SupersetStore(sup).close()
    out = derive.derive(events, sup, str(tmp_path))
    assert out["derived"] == 1 and out["content_nodes"] == 2
    c = sqlite3.connect(sup)
    row = c.execute('SELECT "class", relationship, source_object, source_guid, target_object, '
                    "target_guid, confidence, method, identity_key, inferred_end, corroborated_by "
                    "FROM relationship").fetchone()
    assert row[:10] == ("derived", "executed", "process", "P1", "file", "F1",
                        "definitive", "shared_hash", "sha256_hash", None)
    assert json.loads(row[10]) == ["P1", "F1"]
    # content-keyed entities: deterministic by content, case-normalized
    nodes = {r[0]: r for r in c.execute("SELECT node_id, kind, ref_count, properties FROM content_node")}
    assert set(nodes) == {f"sha256:{_SHA}", "sid:S-1-5-21-1-2-3-1001"}
    assert nodes[f"sha256:{_SHA}"][1:3] == ("file_content", 3)
    props = json.loads(nodes[f"sha256:{_SHA}"][3])
    assert set(props["file_path"]) == {r"C:\Tools\EVIL.EXE", r"C:\backup\evil.bak"}
    assert json.loads(nodes["sid:S-1-5-21-1-2-3-1001"][3])["user"] == ["alice"]
    # every record carrying the identity references the node, with its ROLE
    refs = set(c.execute("SELECT object, guid, node_id, identity_key FROM entity_ref"))
    assert ("process", "P1", "sid:S-1-5-21-1-2-3-1001", "sid") in refs
    assert ("file", "F1", "sid:S-1-5-21-1-2-3-1001", "owner_uid") in refs
    assert ("file", "F2", f"sha256:{_SHA}", "sha256_hash") in refs
    # the exported timeline carries the class label and a decoded corroboration list
    lines = [json.loads(l) for l in open(tmp_path / "car_relationships.jsonl")]
    assert lines[0]["class"] == "derived" and lines[0]["corroborated_by"] == ["P1", "F1"]
    # nothing was reconstructed
    assert out["inferred_nodes"] == 0 and os.path.getsize(tmp_path / "car_inferred.jsonl") == 0


def test_derived_link_on_shared_guid_zeek_fuid():
    events = [
        _ev("http", "get", "C1-1", url_domain="x.example", _native={"uid": "C1", "resp_fuids": ["Fabc", "Fdef"]}),
        _ev("file", "create", "Fabc", file_name="payload.bin", _native={"fuid": "Fabc", "uid": "C1"}),
    ]
    edges = derive.link_edges(events)
    assert len(edges) == 1
    e = edges[0]
    assert (e["source_guid"], e["relationship"], e["target_guid"]) == ("C1-1", "contained", "Fabc")
    assert e["class"] == "derived" and e["method"] == "shared_fuid"
    assert e["identity_key"] == "native.resp_fuids" and e["inferred_end"] is None


def test_ambiguous_hash_makes_no_edge():
    events = [_proc("P1", image_path=r"C:\a.exe", sha256_hash=_SHA),
              _ev("file", "create", "F1", file_path=r"C:\b.exe", sha256_hash=_SHA),
              _ev("file", "create", "F2", file_path=r"C:\c.exe", sha256_hash=_SHA)]
    assert derive.link_edges(events) == []


def test_prefer_field_still_ambiguous_makes_no_edge():
    # Two files share the hash AND both match the preferred field (image_path ==
    # file_path), so narrowing does not resolve to one: the 1:1 rule yields NO
    # edge, not one edge per matching candidate.
    events = [_proc("P1", image_path=r"C:\a.exe", sha256_hash=_SHA),
              _ev("file", "create", "F1", file_path=r"C:\a.exe", sha256_hash=_SHA),
              _ev("file", "create", "F2", file_path=r"C:\a.exe", sha256_hash=_SHA)]
    assert derive.link_edges(events) == []


def test_all_derived_verbs_are_attack_vocabulary():
    """Every verb the derived rules can emit is a real ATT&CK verb — the same
    typed-edge contract the declared cascade is held to."""
    from piiat_mitrecar import build_data_model
    _, rels = build_data_model.build_superset()
    vocab = {r["relationship"] for r in rels}
    verbs = {r["relationship"] for r in derive.rules()["links"]}
    verbs |= {r["relationship"] for r in derive.rules()["reconstruct"]
              if r["relationship"] != "spoke_owner"}
    assert verbs and verbs <= vocab, f"verbs not in ATT&CK vocabulary: {verbs - vocab}"


# --------------------------------------------------------------------------- #
# reconstruction: a flagged inferred node, never a CAR row
# --------------------------------------------------------------------------- #
def test_reconstruction_creates_flagged_inferred_node_not_car_row(tmp_path):
    gone = "{GONE-0001}"
    events = [
        # a module load whose Sysmon ProcessGuid names an owner NO process event
        # carries (the create was cleared) — the cascade resolved nothing
        _ev("module", "load", "M1", owning_pid=4242, owning_guid_native=gone,
            image_path=r"C:\evil.exe", module_path=r"C:\x.dll"),
        _ev("file", "write", "F1", ts="2020-01-01T00:00:05Z", owning_pid=4242,
            owning_guid_native=gone, image_path=r"C:\evil.exe", file_path=r"C:\drop.bin"),
        # a child whose ParentProcessGuid is that same lost process
        _proc("P2", ppid=4242, parent_image_path=r"C:\evil.exe",
              _native={"ParentProcessGuid": gone}),
        # a memory spoke owned by an _EPROCESS at an offset PIIAT-Mem never listed
        _ev("thread", "remote_create", "T1", owning_pid=99, owning_offset=0x1a2b,
            source_artefact="memory/windows.piiat.threads"),
        # an owner the cascade DID resolve (observed): nothing to reconstruct
        _proc("P9"),
        _ev("registry", "add", "R1", owning_guid_native="P9", owning_guid="P9",
            link_confidence="definitive"),
        # a process naming itself as owner is a self-reference, never a node
        _ev("process", "terminate", "P9", owning_guid_native="P9"),
    ]
    events = enrich.enrich(events)
    car = store.CarStore(str(tmp_path / "car.db"))
    car.insert_events(events)
    sup = superset.build_superset_db(str(tmp_path), events)
    out = derive.derive(events, sup["superset_db"], str(tmp_path))
    assert out["inferred_nodes"] == 2 and out["derived"] == 4

    c = sqlite3.connect(sup["superset_db"])
    nodes = {r[0]: r for r in c.execute(
        "SELECT node_id, object, identity_key, identity_value, method, corroborated_by, "
        "properties, reason, first_seen, last_seen FROM inferred_node")}
    n = nodes[gone]
    assert n[1:5] == ("process", "guid", gone, "native_guid")
    assert json.loads(n[5]) == ["M1", "F1", "P2"]           # every corroborating record
    props = json.loads(n[6])
    assert props["pid"] == 4242 and props["image_path"] == r"C:\evil.exe"
    assert "reconstructed, not evidence" in n[7] and "owning_process+parent_process" in n[7]
    assert (n[8], n[9]) == (_T0, "2020-01-01T00:00:05Z")
    # the memory owner: the guid PIIAT-Mem would have minted for that offset
    m = nodes["proc-1a2b"]
    assert m[1:5] == ("process", "offset", str(0x1a2b), "memory_offset")
    assert json.loads(m[6]) == {"pid": 99}

    edges = set(c.execute(
        'SELECT "class", relationship, source_object, source_guid, target_object, target_guid, '
        "confidence, inferred_end, identity_key FROM relationship WHERE \"class\" = 'derived'"))
    assert ("derived", "loaded", "process", gone, "module", "M1", "inferred", "source", "guid") in edges
    assert ("derived", "modified", "process", gone, "file", "F1", "inferred", "source", "guid") in edges
    assert ("derived", "created", "process", gone, "process", "P2", "inferred", "source", "guid") in edges
    assert ("derived", "created", "process", "proc-1a2b", "thread", "T1", "inferred", "source", "offset") in edges
    # the declared cascade edge for the RESOLVED owner is untouched, and no
    # derived row was made for it
    assert c.execute("SELECT count(*) FROM relationship WHERE \"class\"='declared' "
                     "AND source_guid='P9' AND target_guid='R1'").fetchone()[0] == 1
    assert not [e for e in edges if "P9" in e]

    # NEVER a fabricated CAR row: car.db holds only the observed processes
    procs = {r[0] for r in car.conn.execute("SELECT guid FROM process")}
    assert procs == {"P2", "P9"}
    car.close()
    # the inferred nodes go to their OWN stream, flagged, not to car_process
    lines = [json.loads(l) for l in open(tmp_path / "car_inferred.jsonl")]
    assert {l["node_id"] for l in lines} == {gone, "proc-1a2b"}
    assert all(l["object"] == "process" and "reconstructed" in l["reason"] for l in lines)
    assert not os.path.exists(tmp_path / "car_process.jsonl")


def test_reconstruction_skips_nodes_observed_or_already_linked():
    events = [_proc("P1", _native={"ParentProcessGuid": "PP"}, parent_guid="PP"),   # linked by the cascade
              _proc("PX"), _ev("file", "create", "F", owning_guid_native="PX")]      # owner observed
    nodes, edges = derive.reconstruct(events, {(_H, "process", "PX"), (_H, "process", "P1")})
    assert nodes == [] and edges == []


def test_rederive_over_a_store_is_idempotent(tmp_path):
    events = enrich.enrich([
        _proc("P1", image_path=r"C:\a.exe", sha256_hash=_SHA),
        _ev("file", "create", "F1", file_path=r"C:\a.exe", sha256_hash=_SHA),
        _proc("P2", _native={"ParentProcessGuid": "{LOST}"}),
    ])
    st = store.CarStore(str(tmp_path / "car.db"))
    st.insert_events(events)
    st.close()
    superset.build_superset_db(str(tmp_path), events)
    first = derive.run(str(tmp_path))            # from the store, natively kept refs only
    again = derive.run(str(tmp_path))
    assert first["derived"] == again["derived"] == 2
    assert first["inferred_nodes"] == again["inferred_nodes"] == 1
    assert first["relationships"] == again["relationships"]


# --------------------------------------------------------------------------- #
# superset.db shape: backward-compatible
# --------------------------------------------------------------------------- #
def test_superset_schema_is_backward_compatible(tmp_path):
    old = str(tmp_path / "old.db")
    c = sqlite3.connect(old)
    c.executescript("""
        CREATE TABLE relationship (
            id INTEGER PRIMARY KEY, timestamp TEXT, source_host TEXT, relationship TEXT,
            source_object TEXT, source_guid TEXT, target_object TEXT, target_guid TEXT,
            confidence TEXT, method TEXT);
        INSERT INTO relationship VALUES (1,'t','H','created','process','P','file','F','definitive','native_guid');
    """)
    c.commit(); c.close()
    st = superset.SupersetStore(old)             # opens the old shape in place
    cols = [r[1] for r in st.conn.execute("PRAGMA table_info(relationship)")]
    assert cols[:10] == ["id", "timestamp", "source_host", "relationship", "source_object",
                         "source_guid", "target_object", "target_guid", "confidence", "method"]
    assert cols[10:] == ["class", "identity_key", "inferred_end", "corroborated_by"]
    # the pre-existing row is intact; a cascade edge inserted now is DECLARED
    assert st.conn.execute("SELECT source_guid, \"class\" FROM relationship").fetchone() == ("P", None)
    st.insert_edges(superset.edges_from_events([_ev("module", "load", "M", owning_guid="P")]))
    assert st.conn.execute("SELECT \"class\" FROM relationship WHERE id=2").fetchone() == ("declared",)
    for t in ("inferred_node", "content_node", "entity_ref"):
        assert st.conn.execute(f"SELECT count(*) FROM {t}").fetchone() == (0,)
    assert st.counts()["relationships"] == 2 and st.counts()["derived"] == 0
    st.close()


def test_pipeline_derive_stage_is_optional(tmp_path):
    from piiat_mitrecar import pipeline
    src = tmp_path / "in"
    src.mkdir()
    rec = {"EventId": 7, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "HOSTA",
           "Provider": "Microsoft-Windows-Sysmon", "EventRecordId": 7,
           "TimeCreated": "2020-01-01T00:00:00Z",
           "Payload": json.dumps({"EventData": {"Data": [
               {"@Name": "UtcTime", "#text": "2020-01-01 00:00:00.000"},
               {"@Name": "ProcessGuid", "#text": "{LOST-OWNER}"},
               {"@Name": "ProcessId", "#text": "4242"},
               {"@Name": "Image", "#text": r"C:\evil.exe"},
               {"@Name": "ImageLoaded", "#text": r"C:\x.dll"},
               {"@Name": "Hashes", "#text": "SHA256=" + _SHA},
               {"@Name": "Signed", "#text": "false"}]}})}
    (src / "Sysmon_EvtxECmd_Output.json").write_text(json.dumps(rec) + "\n")
    # default: no derived layer at all (behaviour unchanged)
    s = pipeline.process_file(str(src), str(tmp_path / "off"))
    assert s["objects"] == {"module": 1} and "derived" not in s
    assert not os.path.exists(tmp_path / "off" / "car_inferred.jsonl")
    # opted in: the module's lost owner is reconstructed, flagged, not a CAR row
    s = pipeline.process_file(str(src), str(tmp_path / "on"), derive_pass=True)
    assert s["objects"] == {"module": 1} and s["derived"] == 1 and s["inferred_nodes"] == 1
    inf = json.loads(open(tmp_path / "on" / "car_inferred.jsonl").readline())
    assert inf["node_id"] == "{LOST-OWNER}" and inf["object"] == "process"
    # what the spoke said about its owner, verbatim (Sysmon renders the pid as text)
    assert inf["properties"]["pid"] == "4242" and inf["properties"]["image_path"] == r"C:\evil.exe"
    assert not os.path.exists(tmp_path / "on" / "car_process.jsonl")
