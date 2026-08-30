"""The superset-model database + relationship timeline (epic #12).

car.db holds object events; superset.db holds the superset data model + the
relationship INSTANCES the cascade produces between those events — each a
timestamped edge linking car.db rows by guid (the granular relationship timeline).
"""
import os

from piiat_mitrecar import superset


def _proc(guid, host="H", ts="2020-01-01T00:00:00Z", **kw):
    return dict({"car_object": "process", "car_action": "create", "guid": guid,
                 "source_host": host, "timestamp": ts}, **kw)


def test_edges_from_cascade_links():
    events = [
        _proc("P1"),
        # spoke owned by P1 (definitive) -> process --loaded--> module
        {"car_object": "module", "car_action": "load", "guid": "M1", "source_host": "H",
         "timestamp": "2020-01-01T00:00:01Z", "owning_guid": "P1",
         "link_confidence": "definitive"},
        # child process with parent -> process --created--> process
        _proc("P2", parent_guid="P1", link_confidence="heuristic"),
        # file executed as a process (image_path) -> process --executed--> file
        {"car_object": "file", "car_action": "create", "guid": "F1", "source_host": "H",
         "timestamp": "2020-01-01T00:00:02Z",
         "_native": {"executed_as_process_guid": "P1", "executed_as_process_link": "heuristic"}},
        # auth -> logon session by LUID
        {"car_object": "authentication", "car_action": "success", "guid": "A1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:03Z",
         "_native": {"target_session_guid": "S1", "target_session_link": "definitive"}},
    ]
    edges = superset.edges_from_events(events)
    triples = {(e["source_object"], e["relationship"], e["target_object"],
                e["source_guid"], e["target_guid"]) for e in edges}
    assert ("process", "loaded", "module", "P1", "M1") in triples
    assert ("process", "created", "process", "P1", "P2") in triples
    assert ("process", "executed", "file", "P1", "F1") in triples
    assert ("authentication", "created", "user_session", "A1", "S1") in triples
    # no edge falls back to a raw action name
    assert all(e["relationship"] not in ("login", "success") for e in edges)
    # no self-loops
    assert all(e["source_guid"] != e["target_guid"] for e in edges)


def test_no_process_owner_self_loops():
    from piiat_mitrecar import superset
    # a process event's owning_guid is itself -> must NOT emit a self-loop edge
    edges = superset.edges_from_events([
        {"car_object": "process", "car_action": "create", "guid": "P1",
         "source_host": "H", "timestamp": "t", "owning_guid": "P1"},
        {"car_object": "process", "car_action": "terminate", "guid": "P1",
         "source_host": "H", "timestamp": "t", "owning_guid": "P1"},
    ])
    assert edges == []


def test_process_access_edges_source_to_target():
    from piiat_mitrecar import superset
    # Sysmon 10: source --accessed--> TARGET (target_guid), not the record guid
    edges = superset.edges_from_events([
        {"car_object": "process", "car_action": "access", "guid": "REC1",
         "source_host": "H", "timestamp": "t", "owning_guid": "SRC",
         "target_guid": "TGT", "link_confidence": "definitive"}])
    assert len(edges) == 1
    e = edges[0]
    assert (e["source_guid"], e["relationship"], e["target_guid"]) == ("SRC", "accessed", "TGT")


def test_all_emittable_verbs_are_attack_vocabulary():
    """Every relationship verb the cascade can emit must be a real ATT&CK verb
    (in the seeded catalogue) — the 'typed edge' contract, self-enforcing."""
    from piiat_mitrecar import build_data_model, superset
    _, rels = build_data_model.build_superset()
    vocab = {r["relationship"] for r in rels}
    # exercise every edge branch to collect the verbs actually emitted
    events = [
        {"car_object": "module", "car_action": "load", "guid": "M", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "file", "car_action": "read", "guid": "F", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "file", "car_action": "delete", "guid": "F2", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "registry", "car_action": "value_edit", "guid": "R", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "flow", "car_action": "start", "guid": "FL", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "service", "car_action": "stop", "guid": "SV", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "socket", "car_action": "bind", "guid": "SK", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "thread", "car_action": "remote_create", "guid": "TH", "owning_guid": "P",
         "source_host": "H", "timestamp": "t", "_native": {"target_process_guid": "PT"}},
        {"car_object": "user_session", "car_action": "login", "guid": "U", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "user_session", "car_action": "logout", "guid": "U2", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "user_session", "car_action": "unlock", "guid": "U3", "owning_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "authentication", "car_action": "success", "guid": "A", "owning_guid": "P",
         "source_host": "H", "timestamp": "t", "_native": {"target_session_guid": "S"}},
        {"car_object": "process", "car_action": "create", "guid": "C", "parent_guid": "P",
         "source_host": "H", "timestamp": "t"},
        {"car_object": "process", "car_action": "access", "guid": "REC", "owning_guid": "P",
         "target_guid": "PT2", "source_host": "H", "timestamp": "t"},
        {"car_object": "file", "car_action": "create", "guid": "FX", "source_host": "H",
         "timestamp": "t", "_native": {"executed_as_process_guid": "P"}},
    ]
    emitted = {e["relationship"] for e in superset.edges_from_events(events)}
    assert emitted, "no edges emitted"
    assert emitted <= vocab, f"verbs not in ATT&CK vocabulary: {emitted - vocab}"


def test_superset_db_seeds_model_and_stores_edges(tmp_path):
    events = [_proc("P1"),
              {"car_object": "file", "car_action": "create", "guid": "F1",
               "source_host": "H", "timestamp": "2020-01-01T00:00:01Z",
               "owning_guid": "P1", "link_confidence": "definitive"}]
    out = superset.build_superset_db(str(tmp_path), events)
    assert out["relationships"] >= 1
    assert os.path.exists(os.path.join(tmp_path, "superset.db"))
    assert os.path.exists(os.path.join(tmp_path, "car_relationships.jsonl"))

    import sqlite3
    c = sqlite3.connect(os.path.join(tmp_path, "superset.db"))
    # the model + ATT&CK edge-types are seeded as reference data
    assert c.execute("select count(*) from model_object").fetchone()[0] == 38
    assert c.execute("select count(*) from relationship_type").fetchone()[0] > 100
    # the process--created-->file relationship instance is stored, linking guids
    row = c.execute("select relationship, source_guid, target_guid, confidence "
                    "from relationship").fetchone()
    assert row == ("created", "P1", "F1", "definitive")
