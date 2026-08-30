"""Regression tests over MITRE CAR's own true-positive events (epic #86).

CAR ships real Mordor events in docs/true_positives/. We vendor the relevant
ones and exercise our maps + the guid cascade against them, so a proven
artefact relationship (Sysmon CreateRemoteThread: source process injects a
thread into a target process) is regression-tested on genuine telemetry.

Mordor events use the OSSEM field vocabulary (process_guid, process_target_guid,
…), not EvtxECmd's Payload/EventData/@Name shape our maps consume, so a tiny
shaper adapts one to the other — that is exactly the shape our EvtxECmd lane
produces for the same event.
"""
import json
import os

from piiat_mitrecar import enrich, normalize

_FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _evtxecmd(record_id, eid, provider, data: dict, computer="TESTHOST"):
    """An EvtxECmd-shaped record from named EventData fields."""
    return {
        "EventId": eid, "Provider": provider, "Computer": computer,
        "EventRecordId": str(record_id), "TimeCreated": "2019-05-18T22:15:33Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Payload": {"EventData": {"Data": [{"@Name": k, "#text": v}
                                           for k, v in data.items()]}},
    }


def _mordor_thread_to_evtxecmd(m: dict) -> dict:
    """Sysmon EID 8 in Mordor/OSSEM shape -> the EvtxECmd shape our map reads."""
    return _evtxecmd(1, 8, "Microsoft-Windows-Sysmon", {
        "UtcTime": m.get("@event_date_creation"),
        "SourceProcessGuid": m["process_guid"],
        "SourceProcessId": m["process_id"],
        "SourceImage": m["process_path"],
        "TargetProcessGuid": m["process_target_guid"],
        "TargetProcessId": m["process_target_id"],
        "TargetImage": m["process_target_path"],
        "NewThreadId": m.get("thread_new_id", "0"),
    }, computer=m.get("host_name") or "TESTHOST")


def test_createremotethread_guid_cascade():
    """CAR-2013-10-002 CreateRemoteThread: the thread links DEFINITIVELY to its
    source process (owner) and, once the target process exists, to the injected
    target — the injection relationship, on real true-positive telemetry."""
    m = json.load(open(os.path.join(_FIX, "CAR-2013-10-002-mordor-01-snippet.json")))
    assert m["event_id"] == 8

    thread = normalize.normalize("evtx_sysmon", _mordor_thread_to_evtxecmd(m))
    assert thread is not None
    assert thread["car_object"] == "thread"
    assert thread["car_action"] == "remote_create"
    # the acting SOURCE process is the owner (native guid, tier-1 definitive)
    assert thread["owning_guid_native"] == m["process_guid"]
    assert thread["_native"]["TargetProcessGuid"] == m["process_target_guid"]

    # give the cascade the two processes this event names, then enrich
    src = normalize.normalize("evtx_sysmon", _evtxecmd(2, 1, "Microsoft-Windows-Sysmon", {
        "ProcessGuid": m["process_guid"], "ProcessId": m["process_id"],
        "Image": m["process_path"]}))
    tgt = normalize.normalize("evtx_sysmon", _evtxecmd(3, 1, "Microsoft-Windows-Sysmon", {
        "ProcessGuid": m["process_target_guid"], "ProcessId": m["process_target_id"],
        "Image": m["process_target_path"]}))
    out = enrich.enrich([thread, src, tgt])
    t = [e for e in out if e["car_object"] == "thread"][0]
    # definitive owner = source process; R5 target link = injected process
    assert t["owning_guid"] == m["process_guid"]
    assert t["link_confidence"] == "definitive"
    assert t["_native"]["target_process_guid"] == m["process_target_guid"]
    assert t["_native"]["target_process_link"] == "definitive"
