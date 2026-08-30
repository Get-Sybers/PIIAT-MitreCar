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
    assert ("authentication", "created logon session", "user_session", "A1", "S1") in triples
    # no edge falls back to a raw action name
    assert all(e["relationship"] not in ("login", "success") for e in edges)


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
