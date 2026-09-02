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

Relationship instances come in two CLASSES (the D4 relationship model):

- DECLARED (`class=declared`): the validated cascade edges that edges_from_events
  materializes from enrich's links — rule-driven, credible for inference.
- DERIVED (`class=derived`): data-driven 1:1 links derive.py infers on a shared
  strong identity (guid / hash / real SID / memory offset), each naming its
  `identity_key`, `method` and the `corroborated_by` guids. A derived edge may
  end on an `inferred_node` — a node reconstructed from what other records
  reference but no source observed (antiforensics / partial recovery); it is
  flagged through `inferred_end` and NEVER written as a car.db event row.
  Content-keyed identities (a hash, a real SID) become `content_node` rows with
  an `entity_ref` from every record carrying them (the attribution layer).
"""
from __future__ import annotations

import json
import os
import sqlite3

from . import build_data_model

# the two relationship classes; every row carries one
DECLARED, DERIVED = "declared", "derived"

# columns added to `relationship` after its first shape — applied as ALTER TABLE
# when an older superset.db is opened, so an existing store keeps working
_RELATIONSHIP_ADDED = [("class", "TEXT"), ("identity_key", "TEXT"),
                       ("inferred_end", "TEXT"), ("corroborated_by", "TEXT")]
# JSON-text columns, decoded on export
_JSON_COLS = {"corroborated_by", "properties"}

# relationship-instance verbs are DATA (cascade_relationships.yml), validated
# against the ATT&CK catalogue by test_superset.
_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "cascade_relationships.yml")
_rules_cache: dict | None = None


def rules() -> dict:
    global _rules_cache
    if _rules_cache is None:
        import yaml
        with open(_RULES_PATH, encoding="utf-8") as fh:
            _rules_cache = yaml.safe_load(fh)
    return _rules_cache


def _spoke_verb(obj: str, act: str) -> str:
    r = rules()
    return (r["spoke_owner"].get(obj) or {}).get(act) or r["default_spoke_verb"]


def _edge_verb(name: str) -> str:
    return rules()["edges"][name]


def _method(ev: dict) -> str | None:
    c = ev.get("link_confidence")
    return {"definitive": "native_guid", "heuristic": "pid_window"}.get(c)


def _edge(ts, host, rel, s_obj, s_guid, t_obj, t_guid, conf, method):
    return {"timestamp": ts, "source_host": host, "relationship": rel,
            "source_object": s_obj, "source_guid": s_guid,
            "target_object": t_obj, "target_guid": t_guid,
            "confidence": conf, "method": method, "class": DECLARED}


def _json_text(v):
    """A list/dict column value as JSON text (None stays NULL)."""
    if v is None:
        return None
    return v if isinstance(v, str) else json.dumps(v, default=str)


def _row_dict(cols, row):
    d = dict(zip(cols, row))
    for c in _JSON_COLS:
        if isinstance(d.get(c), str):
            try:
                d[c] = json.loads(d[c])
            except ValueError:
                pass
    return d


def edges_from_events(events: list[dict]) -> list[dict]:
    """The relationship instances (timeline edges) implied by the enriched
    events' cascade links. Typed against the ATT&CK relationship vocabulary."""
    out = []
    for ev in events:
        g, obj, act = ev.get("guid"), ev["car_object"], ev.get("car_action")
        host, ts = ev.get("source_host"), ev.get("timestamp")
        nat = ev.get("_native") or {}
        og = ev.get("owning_guid")
        # SPOKE -> owning process (P --verb--> spoke). Only for non-process
        # spokes: a process event's owning_guid is itself, which would emit a
        # meaningless self-loop; process relationships are handled explicitly
        # below (parent, access).
        if og and g and obj != "process" and og != g:
            out.append(_edge(ts, host, _spoke_verb(obj, act),
                             "process", og, obj, g, ev.get("link_confidence"), _method(ev)))
        # process create -> its parent process
        if obj == "process" and act == "create" and ev.get("parent_guid") \
                and ev["parent_guid"] != g:
            out.append(_edge(ts, host, _edge_verb("parent_process"), "process",
                             ev["parent_guid"], "process", g,
                             ev.get("link_confidence"), _method(ev)))
        # process ACCESS (Sysmon 10): source process -> the target it opened
        # (target_guid is a canonical process field, not the record guid)
        if obj == "process" and act == "access" and og and ev.get("target_guid") \
                and og != ev["target_guid"]:
            out.append(_edge(ts, host, _edge_verb("process_access"), "process", og,
                             "process", ev["target_guid"], ev.get("link_confidence"),
                             _method(ev)))
        # file -> the process that executed it (CAR-2014-02-001, image_path)
        ep = nat.get("executed_as_process_guid")
        if ep and g and ep != g:
            out.append(_edge(ts, host, _edge_verb("file_executed"), "process", ep,
                             "file", g, nat.get("executed_as_process_link"), "image_path"))
        # CreateRemoteThread injection: source process -> target process
        tg = nat.get("target_process_guid")
        if tg and og and tg != og:
            out.append(_edge(ts, host, _edge_verb("thread_injection"), "process", og,
                             "process", tg, nat.get("target_process_link"), "native_guid"))
        # authentication -> the logon session it opened / was requested from
        for gk, lk in (("target_session_guid", "target_session_link"),
                       ("subject_session_guid", "subject_session_link")):
            sg = nat.get(gk)
            if sg and g and sg != g:
                out.append(_edge(ts, host, _edge_verb("auth_session"), obj, g,
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
            source_element TEXT, relationship TEXT, target_element TEXT,
            PRIMARY KEY (source_element, relationship, target_element));
        CREATE TABLE IF NOT EXISTS relationship (
            id INTEGER PRIMARY KEY, timestamp TEXT, source_host TEXT,
            relationship TEXT,
            source_object TEXT, source_guid TEXT,
            target_object TEXT, target_guid TEXT,
            confidence TEXT, method TEXT,
            "class" TEXT, identity_key TEXT, inferred_end TEXT, corroborated_by TEXT);
        CREATE INDEX IF NOT EXISTS ix_rel_ts ON relationship (timestamp);
        CREATE INDEX IF NOT EXISTS ix_rel_src ON relationship (source_guid);
        CREATE INDEX IF NOT EXISTS ix_rel_tgt ON relationship (target_guid);
        -- a node no source OBSERVED, reconstructed from what other records
        -- reference (flagged; never a car.db event row). node_id is the
        -- deterministic handle a derived relationship's inferred end resolves to.
        CREATE TABLE IF NOT EXISTS inferred_node (
            id INTEGER PRIMARY KEY, node_id TEXT UNIQUE, source_host TEXT,
            object TEXT, identity_key TEXT, identity_value TEXT,
            reason TEXT, method TEXT, corroborated_by TEXT, properties TEXT,
            first_seen TEXT, last_seen TEXT);
        -- a content-keyed entity (the same bytes / the same account), identified
        -- deterministically by its content: sha256:<hex>, sid:<S-1-5-21-...>
        CREATE TABLE IF NOT EXISTS content_node (
            node_id TEXT PRIMARY KEY, kind TEXT, identity_key TEXT,
            identity_value TEXT, properties TEXT,
            first_seen TEXT, last_seen TEXT, ref_count INTEGER);
        -- one row per (car.db record, content node) reference
        CREATE TABLE IF NOT EXISTS entity_ref (
            id INTEGER PRIMARY KEY, source_host TEXT, object TEXT, guid TEXT,
            node_id TEXT, identity_key TEXT, timestamp TEXT,
            UNIQUE (source_host, object, guid, node_id, identity_key));
        CREATE INDEX IF NOT EXISTS ix_eref_node ON entity_ref (node_id);
        """)
        # an older superset.db predates the class columns: add them in place
        have = {r[1] for r in cur.execute("PRAGMA table_info(relationship)")}
        for col, typ in _RELATIONSHIP_ADDED:
            if col not in have:
                cur.execute(f'ALTER TABLE relationship ADD COLUMN "{col}" {typ}')
        cur.execute('CREATE INDEX IF NOT EXISTS ix_rel_class ON relationship ("class")')
        self.conn.commit()

    def seed_model(self):
        """Enter the superset data model + ATT&CK relationship edge-types."""
        model, rels = build_data_model.build_superset()
        cur = self.conn.cursor()
        for o in model["objects"]:
            name = o["name"][0] if isinstance(o["name"], list) else o["name"]
            cur.execute("INSERT OR REPLACE INTO model_object VALUES (?,?,?,?)",
                        (name, o.get("source"), json.dumps(o.get("actions", [])),
                         o.get("definition")))
        for r in rels:
            cur.execute("INSERT OR IGNORE INTO relationship_type VALUES (?,?,?)",
                        (r["source"], r["relationship"], r["target"]))
        self.conn.commit()

    def insert_edges(self, edges: list[dict]) -> int:
        """Store relationship instances. An edge without a `class` is a DECLARED
        cascade edge; derive.py's edges carry class=derived plus identity_key /
        inferred_end / corroborated_by."""
        cur = self.conn.cursor()
        for e in edges:
            cur.execute(
                "INSERT INTO relationship (timestamp, source_host, relationship, "
                "source_object, source_guid, target_object, target_guid, "
                "confidence, method, \"class\", identity_key, inferred_end, "
                "corroborated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e["timestamp"], e["source_host"], e["relationship"],
                 e["source_object"], e["source_guid"], e["target_object"],
                 e["target_guid"], e["confidence"], e["method"],
                 e.get("class") or DECLARED, e.get("identity_key"),
                 e.get("inferred_end"), _json_text(e.get("corroborated_by"))))
        self.conn.commit()
        return len(edges)

    def insert_inferred_nodes(self, nodes: list[dict]) -> int:
        cur = self.conn.cursor()
        for n in nodes:
            cur.execute(
                "INSERT OR REPLACE INTO inferred_node (node_id, source_host, object, "
                "identity_key, identity_value, reason, method, corroborated_by, "
                "properties, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (n["node_id"], n.get("source_host"), n["object"], n["identity_key"],
                 n["identity_value"], n.get("reason"), n.get("method"),
                 _json_text(n.get("corroborated_by")), _json_text(n.get("properties")),
                 n.get("first_seen"), n.get("last_seen")))
        self.conn.commit()
        return len(nodes)

    def insert_content_nodes(self, nodes: list[dict]) -> int:
        cur = self.conn.cursor()
        for n in nodes:
            cur.execute(
                "INSERT OR REPLACE INTO content_node (node_id, kind, identity_key, "
                "identity_value, properties, first_seen, last_seen, ref_count) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (n["node_id"], n.get("kind"), n["identity_key"], n["identity_value"],
                 _json_text(n.get("properties")), n.get("first_seen"),
                 n.get("last_seen"), n.get("ref_count")))
        self.conn.commit()
        return len(nodes)

    def insert_entity_refs(self, refs: list[dict]) -> int:
        cur = self.conn.cursor()
        for r in refs:
            cur.execute(
                "INSERT OR IGNORE INTO entity_ref (source_host, object, guid, node_id, "
                "identity_key, timestamp) VALUES (?,?,?,?,?,?)",
                (r.get("source_host"), r["object"], r["guid"], r["node_id"],
                 r.get("identity_key"), r.get("timestamp")))
        self.conn.commit()
        return len(refs)

    def clear_derived(self) -> None:
        """Drop everything the derive pass produced (re-derivable from the
        stores); the declared cascade edges stay."""
        cur = self.conn.cursor()
        cur.execute('DELETE FROM relationship WHERE "class" = ?', (DERIVED,))
        for t in ("inferred_node", "content_node", "entity_ref"):
            cur.execute(f"DELETE FROM {t}")
        self.conn.commit()

    def _export_table(self, out_dir: str, table: str, filename: str, order: str) -> int:
        """Stream one table to <out_dir>/<filename> as JSONL — the timeline can
        be very large, so rows go straight from the cursor."""
        cur = self.conn.execute(f"SELECT * FROM {table} ORDER BY {order}")
        cols = [c[0] for c in cur.description]
        n = 0
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as fh:
            for row in cur:
                fh.write(json.dumps(_row_dict(cols, row), default=str) + "\n")
                n += 1
        return n

    def export_jsonl(self, out_dir: str) -> int:
        """The granular relationship timeline as JSONL (the ADX/timeline contract)."""
        return self._export_table(out_dir, "relationship", "car_relationships.jsonl",
                                  "timestamp")

    def export_inferred_jsonl(self, out_dir: str) -> int:
        """The reconstructed-but-unobserved nodes as JSONL — car_inferred.jsonl,
        destined for its own stream (logs-car.inferred-*), never a car_<object>."""
        return self._export_table(out_dir, "inferred_node", "car_inferred.jsonl",
                                  "first_seen, id")

    def counts(self) -> dict:
        q = lambda sql, *a: self.conn.execute(sql, a).fetchone()[0]  # noqa: E731
        return {"relationships": q("SELECT count(*) FROM relationship"),
                "derived": q('SELECT count(*) FROM relationship WHERE "class" = ?', DERIVED),
                "inferred_nodes": q("SELECT count(*) FROM inferred_node"),
                "content_nodes": q("SELECT count(*) FROM content_node"),
                "entity_refs": q("SELECT count(*) FROM entity_ref")}

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
