"""The unified CAR timeline: objects (car.db) + relationship edges (superset.db)
merged into one property-rich, time-ordered stream (epic #12)."""
import json
import os

import pytest

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


def test_timeline_edges_only(tmp_path):
    _make(str(tmp_path))
    rows = timeline.build_timeline(str(tmp_path), edges_only=True)
    assert rows and all(r["kind"] == "relationship" for r in rows)


def test_timeline_after_before_by_instant(tmp_path):
    # fixture: process object @00:00:00, module object + `loaded` edge @00:00:01.
    _make(str(tmp_path))
    mid = "2020-01-01T00:00:00.500Z"          # a Z-suffixed, fractional bound
    after = timeline.build_timeline(str(tmp_path), after=mid)
    assert {(r["kind"], r.get("object", r.get("relationship")))
            for r in after} == {("object", "module"), ("relationship", "loaded")}
    before = timeline.build_timeline(str(tmp_path), before=mid)
    assert [r["kind"] for r in before] == ["object"]
    assert before[0]["object"] == "process"


def test_timeline_bad_bound_is_rejected(tmp_path):
    _make(str(tmp_path))
    with pytest.raises(SystemExit):
        timeline.build_timeline(str(tmp_path), after="not-a-timestamp")


def test_parse_ts_orders_mixed_iso_formats():
    # lexicographic string order would put ".500Z" before the bare second and
    # sort by wall-clock across offsets; the true instant must win.
    p = timeline._parse_ts
    assert p("2020-01-01T00:00:00Z") == p("2020-01-01T00:00:00+00:00")
    assert p("2020-01-01T00:00:00.500Z") > p("2020-01-01T00:00:00Z")
    # 04:00-02:00 == 06:00Z is later than 05:00Z despite sorting earlier as text
    assert p("2020-01-01T04:00:00-02:00") > p("2020-01-01T05:00:00+00:00")
    assert p("garbage") is None and p(None) is None


def test_sort_orders_by_instant_not_string(tmp_path):
    events = [
        {"car_object": "process", "car_action": "create", "guid": "B",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00.500Z"},
        {"car_object": "process", "car_action": "create", "guid": "A",
         "source_host": "H", "timestamp": "2020-01-01T00:00:00Z"},
    ]
    st = store.CarStore(os.path.join(str(tmp_path), "car.db"))
    st.insert_events(events)
    st.close()
    rows = timeline.build_timeline(str(tmp_path), objects_only=True)
    assert [r["guid"] for r in rows] == ["A", "B"]   # 00.000 before 00.500
