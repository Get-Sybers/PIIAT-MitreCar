"""The superset-model database: the data model + relationships as data, and the
RELATIONSHIP INSTANCES we enter from the artefacts (epic #86).

car.db holds the OBJECT events (process create, file write, logon…). This holds
the SUPERSET MODEL (CAR + ATT&CK objects/actions + the ATT&CK relationship
edge-types) AND the relationship INSTANCES the cascade produces between those
events — each a `source object → relationship → target object` edge, timestamped
and pointing back at the car.db rows by guid. That edge table is a second, more
GRANULAR timeline than the object-level car.db: it times the *relationships*
themselves (P created F, parent created child, user created logon session,
process executed file), and either LINKS the car.db entries (by guid) or is
WATERFALLED (cascaded) from them.

Built per source alongside car.db, so a source's events and their relationship
timeline stay together. Reference model + edge-types are seeded from
build_data_model (generated), so this DB always reflects the current superset.
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import build_data_model, carmodel

# how a spoke's (object, action) reads as an ATT&CK relationship verb, acted BY
# its owning process (process --verb--> spoke). Falls back to the action itself.
_VERB = {
    ("file", "create"): "created", ("file", "read"): "accessed",
    ("file", "write"): "modified", ("file", "modify"): "modified",
    ("file", "delete"): "deleted", ("file", "acl_modify"): "modified",
    ("file", "timestomp"): "modified",
    ("registry", "add"): "created", ("registry", "remove"): "deleted",
    ("registry", "value_edit"): "modified", ("registry", "key_edit"): "modified",
    ("module", "load"): "loaded", ("driver", "load"): "loaded",
    ("flow", "start"): "created", ("flow", "message"): "created",
    ("flow", "end"): "created",
    ("service", "create"): "created", ("service", "stop"): "stopped",
    ("service", "start"): "started",
    ("thread", "remote_create"): "created", ("process", "access"): "accessed",
    ("http", "get"): "created", ("http", "post"): "created",
    ("socket", "bind"): "bound to",
    # a process is the OWNER of the session it requested / the auth it made
    ("user_session", "login"): "created", ("user_session", "reconnect"): "created",
    ("user_session", "logout"): "closed", ("user_session", "unlock"): "unlocked",
    ("user_session", "lock"): "locked",
    ("authentication", "success"): "requested",
    ("authentication", "failure"): "requested", ("authentication", "error"): "requested",
}


def _method(ev: dict) -> str | None:
    c = ev.get("link_confidence")
    return {"definitive": "native_guid", "heuristic": "pid_window"}.get(c)


def _edge(ts, host, rel, s_obj, s_guid, t_obj, t_guid, conf, method):
    return {"timestamp": ts, "source_host": host, "relationship": rel,
            "source_object": s_obj, "source_guid": s_guid,
            "target_object": t_obj, "target_guid": t_guid,
            "confidence": conf, "method": method}


def edges_from_events(events: list[dict]) -> list[dict]:
    """The relationship instances (timeline edges) implied by the enriched
    events' cascade links. Typed against the ATT&CK relationship vocabulary."""
    out = []
    for ev in events:
        g, obj, act = ev.get("guid"), ev["car_object"], ev.get("car_action")
        host, ts = ev.get("source_host"), ev.get("timestamp")
        nat = ev.get("_native") or {}
        # spoke -> owning process (P --verb--> spoke)
        og = ev.get("owning_guid")
        if og and g:
            out.append(_edge(ts, host, _VERB.get((obj, act), act or "accessed"),
                             "process", og, obj, g, ev.get("link_confidence"), _method(ev)))
        # parent process -> child process
        if obj == "process" and act == "create" and ev.get("parent_guid"):
            out.append(_edge(ts, host, "created", "process", ev["parent_guid"],
                             "process", g, ev.get("link_confidence"), _method(ev)))
        # file -> the process that executed it (CAR-2014-02-001, image_path)
        ep = nat.get("executed_as_process_guid")
        if ep and g:
            out.append(_edge(ts, host, "executed", "process", ep, "file", g,
                             nat.get("executed_as_process_link"), "image_path"))
        # CreateRemoteThread: source process -> injected target process
        tg = nat.get("target_process_guid")
        if tg and og:
            out.append(_edge(ts, host, "created remote thread in", "process", og,
                             "process", tg, nat.get("target_process_link"), "native_guid"))
        # authentication -> the logon session it opened / was requested from
        for gk, lk in (("target_session_guid", "target_session_link"),
                       ("subject_session_guid", "subject_session_link")):
            sg = nat.get(gk)
            if sg and g:
                out.append(_edge(ts, host, "created logon session", obj, g,
                                 "user_session", sg, nat.get(lk), "luid"))
    return out


class SupersetStore:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self._create()

    def _create(self):
        cur = self.conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS model_object (
            name TEXT PRIMARY KEY, source TEXT, actions TEXT, definition TEXT);
        CREATE TABLE IF NOT EXISTS relationship_type (
            source_element TEXT, relationship TEXT, target_element TEXT);
        CREATE TABLE IF NOT EXISTS relationship (
            id INTEGER PRIMARY KEY, timestamp TEXT, source_host TEXT,
            relationship TEXT,
            source_object TEXT, source_guid TEXT,
            target_object TEXT, target_guid TEXT,
            confidence TEXT, method TEXT);
        CREATE INDEX IF NOT EXISTS ix_rel_ts ON relationship (timestamp);
        CREATE INDEX IF NOT EXISTS ix_rel_src ON relationship (source_guid);
        CREATE INDEX IF NOT EXISTS ix_rel_tgt ON relationship (target_guid);
        """)
        self.conn.commit()

    def seed_model(self):
        """Enter the superset data model + ATT&CK relationship edge-types."""
        model, rels = build_data_model.build()
        cur = self.conn.cursor()
        for o in model["objects"]:
            name = o["name"][0] if isinstance(o["name"], list) else o["name"]
            cur.execute("INSERT OR REPLACE INTO model_object VALUES (?,?,?,?)",
                        (name, o.get("source"), json.dumps(o.get("actions", [])),
                         o.get("definition")))
        for r in rels:
            cur.execute("INSERT INTO relationship_type VALUES (?,?,?)",
                        (r["source"], r["relationship"], r["target"]))
        self.conn.commit()

    def insert_edges(self, edges: list[dict]) -> int:
        cur = self.conn.cursor()
        for e in edges:
            cur.execute(
                "INSERT INTO relationship (timestamp, source_host, relationship, "
                "source_object, source_guid, target_object, target_guid, "
                "confidence, method) VALUES (?,?,?,?,?,?,?,?,?)",
                (e["timestamp"], e["source_host"], e["relationship"],
                 e["source_object"], e["source_guid"], e["target_object"],
                 e["target_guid"], e["confidence"], e["method"]))
        self.conn.commit()
        return len(edges)

    def export_jsonl(self, out_dir: str) -> int:
        """The granular relationship timeline as JSONL (the ADX/timeline contract)."""
        rows = [dict(zip([c[0] for c in cur.description], r))
                for cur in [self.conn.execute("SELECT * FROM relationship ORDER BY timestamp")]
                for r in cur.fetchall()]
        with open(os.path.join(out_dir, "car_relationships.jsonl"), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, default=str) + "\n")
        return len(rows)

    def counts(self) -> dict:
        c = self.conn.execute("SELECT count(*) FROM relationship").fetchone()[0]
        return {"relationships": c}

    def close(self):
        self.conn.close()


def build_superset_db(out_dir: str, events: list[dict]) -> dict:
    """Build superset.db beside car.db: seed the model + edge-types, materialize
    the relationship instances from the enriched events, export the timeline."""
    path = os.path.join(out_dir, "superset.db")
    if os.path.exists(path):
        os.remove(path)
    st = SupersetStore(path)
    st.seed_model()
    edges = edges_from_events(events)
    st.insert_edges(edges)
    written = st.export_jsonl(out_dir)
    counts = st.counts()
    st.close()
    return {"superset_db": path, "relationships": counts["relationships"],
            "relationships_exported": written}
