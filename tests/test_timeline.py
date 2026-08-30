"""The unified CAR timeline: objects (car.db) + relationship edges (superset.db)
merged into one property-rich, time-ordered stream (epic #12)."""
import json
import os

from piiat_mitrecar import store, superset, timeline


def _events():
    return [
        {"car_object": "process", "car_action": "create", "guid": "P1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00Z",
         "exe": r"C:\a.exe", "command_line": "a -x", "_native": {"EventId": 1}},
        {"car_object": "module", "car_action": "load", "guid": "M1",
         "source_host": "H", "timestamp": "2020-01-01T00:00:01Z",
         "owning_guid": "P1", "link_confidence": "definitive",
         "image_path": r"C:\a.exe"},
    ]


def _make(tmp: str):
    st = store.CarStore(os.path.join(tmp, "car.db"))
    st.insert_events(_events())
    st.close()
    superset.build_superset_db(tmp, _events())


def test_timeline_merges_objects_and_edges_ordered(tmp_path):
    _make(str(tmp_path))
    rows = timeline.build_timeline(str(tmp_path))
    kinds = {r["kind"] for r in rows}
    assert kinds == {"object", "relationship"}
    assert [r["timestamp"] for r in rows] == sorted(r["timestamp"] for r in rows)
    # property-rich: the process entry carries its full CAR props + native
    proc = next(r for r in rows if r["kind"] == "object" and r["object"] == "process")
    assert proc["exe"] == r"C:\a.exe" and proc["command_line"] == "a -x"
    assert proc.get("native", {}).get("EventId") == 1
    # the edge carries the ATT&CK verb + confidence + endpoints
    edge = next(r for r in rows if r["kind"] == "relationship")
    assert edge["relationship"] == "loaded" and edge["confidence"] == "definitive"
    assert (edge["source_object"], edge["target_object"]) == ("process", "module")


def test_timeline_filters_and_writes(tmp_path):
    _make(str(tmp_path))
    assert timeline.build_timeline(str(tmp_path), host="NOPE") == []
    assert all(r["kind"] == "object"
               for r in timeline.build_timeline(str(tmp_path), objects_only=True))
    out = os.path.join(tmp_path, "timeline.jsonl")
    n = timeline.write_jsonl(timeline.build_timeline(str(tmp_path)), out)
    assert n > 0 and len([json.loads(x) for x in open(out)]) == n
