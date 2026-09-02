"""CROSS-SOURCE correlation — the OPT-IN end-stage over the aggregate.

Every source is finished on its own: normalize -> enrich -> car.db + superset.db,
enrichment SELF-CONTAINED within the source (docs/CAR-Pipeline.md §2; no source
depends on another). This module is the separate, optional stage that runs
AFTER that, over a TREE of finished per-source stores, and correlates them on
the content-keyed strong identities derive.py already extracted per source:

- content nodes carrying the same strong identity (the same sha256:<hex>, the
  same sid:<S-1-5-21-…>) in different sources are UNIONED into one cross-source
  entity: properties unioned additively, ref counts summed, first/last seen
  widened — nothing a source contributed is dropped, and each source's own
  contribution stays legible under `per_source`;
- where two sources share such an identity, ONE cross-source DERIVED
  relationship per (entity, source pair) records the corroboration —
  class=derived, method cross_source_hash / cross_source_sid, confidence
  HEURISTIC (a shared hash or SID is the same bytes / the same account; it is
  not proof that two instances are one event, and two evidence sets may share
  a host label) — corroborated by the guids of the records on both sides;
- every node, ref and edge carries a STORED SOURCE BOUNDARY naming the
  contributing per-source stores by their path under the tree (`sources`, a
  ref's `source`, an edge's `source_boundary`): `source_host` alone is not a
  boundary — cases and hosts may share a host label over time.

The stage writes ONLY its own aggregate store — <tree>/crosssource/crosssource.db
+ car_crosssource.jsonl (its own stream, logs-car.crosssource-*). The per-source
car.db / superset.db are opened READ-ONLY and never changed. Default OFF:
nothing in the per-source path runs it.

    python -m piiat_mitrecar.crosssource <tree> [--out DIR]
    python -m piiat_mitrecar --batch <processed_dir> --derive --crosssource
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import sqlite3
import sys
from collections import defaultdict

from . import carmodel, derive, superset

# The cross-source verb. Deliberately NOT an ATT&CK relationship verb: that
# vocabulary says what one data element did to another (created, executed,
# loaded …); a cross-source edge asserts that two evidence sets observed the
# SAME content entity — a correlation, not an action. It lives only here.
VERB = "corroborated"
CONFIDENCE = "heuristic"          # never definitive: an identity match across evidence sets
OUT_DIRNAME = "crosssource"
DB_NAME = "crosssource.db"
JSONL_NAME = "car_crosssource.jsonl"
_CORROBORATION_CAP = 64           # guids listed per end on an edge; exact counts stay in `corroboration`
_JSON_COLS = {"properties", "per_source", "sources", "hosts", "corroborated_by",
              "corroboration", "source_boundary"}
_MISSING = (None, "")


# --------------------------------------------------------------------------- #
# Reading the per-source stores — read-only, always
# --------------------------------------------------------------------------- #
def _open_ro(path: str) -> sqlite3.Connection:
    """A per-source store opened READ-ONLY (sqlite URI mode=ro): this stage can
    not mutate a source even by accident."""
    return sqlite3.connect(pathlib.Path(path).resolve().as_uri() + "?mode=ro", uri=True)


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (name,)).fetchone() is not None


def _row_dict(cols, row) -> dict:
    d = dict(zip(cols, row))
    for c in _JSON_COLS:
        if isinstance(d.get(c), str):
            try:
                d[c] = json.loads(d[c])
            except ValueError:
                pass
    return d


def _json_text(v):
    if v is None:
        return None
    return v if isinstance(v, str) else json.dumps(v, default=str)


def discover(tree: str) -> list[tuple[str, str]]:
    """(name, dir) for every per-source store under `tree` — each directory
    holding a car.db, named by its path under the tree (the batch layout is
    <out_root>/<source_name>/, so the name IS the batch source name); the tree
    itself when it is a single source. The name is the stored source boundary."""
    tree = os.path.abspath(tree)
    if os.path.isfile(os.path.join(tree, "car.db")):
        return [(os.path.basename(tree) or "source", tree)]
    out = []
    for p in sorted(glob.glob(os.path.join(glob.escape(tree), "**", "car.db"), recursive=True)):
        d = os.path.dirname(p)
        out.append((os.path.relpath(d, tree).replace(os.sep, "/"), d))
    return out


def _content_from_superset(sup_db: str) -> tuple[list[dict], list[dict]]:
    """The finished content layer of one source (content_node + entity_ref),
    as derive.py wrote it; empty when the derive pass never ran there."""
    conn = _open_ro(sup_db)
    try:
        if not (_has_table(conn, "content_node") and _has_table(conn, "entity_ref")):
            return [], []
        out = []
        for table, order in (("content_node", "node_id"), ("entity_ref", "id")):
            cur = conn.execute(f"SELECT * FROM {table} ORDER BY {order}")
            cols = [c[0] for c in cur.description]
            out.append([_row_dict(cols, r) for r in cur])
        return out[0], out[1]
    finally:
        conn.close()


def _events_ro(car_db: str) -> list[dict]:
    """A finished car.db as derive's in-memory event shape (native -> _native),
    read-only — derive.load_events goes through CarStore, which opens read-write."""
    conn = _open_ro(car_db)
    conn.row_factory = sqlite3.Row
    try:
        out = []
        for obj in carmodel.load():
            if not _has_table(conn, obj):
                continue
            for r in conn.execute(f'SELECT * FROM "{obj}" ORDER BY event_id'):
                ev = dict(r)
                ev["car_object"] = obj
                ev.pop("event_id", None)
                nat = ev.pop("native", None)
                if isinstance(nat, str):
                    try:
                        nat = json.loads(nat)
                    except ValueError:
                        nat = None
                ev["_native"] = nat if isinstance(nat, dict) else {}
                out.append(ev)
        return out
    finally:
        conn.close()


def load_source(name: str, car_dir: str) -> dict:
    """One per-source store's content layer. From superset.db where the derive
    pass ran; otherwise derived in memory from car.db by the same per-source
    rules (derive.content_entities) — read-only, nothing is written back."""
    car_db, sup_db = os.path.join(car_dir, "car.db"), os.path.join(car_dir, "superset.db")
    nodes, refs, layer = [], [], None
    if os.path.isfile(sup_db):
        nodes, refs = _content_from_superset(sup_db)
        layer = "superset.db"
    if not nodes:
        nodes, refs = derive.content_entities(_events_ro(car_db))
        layer = "car.db (derived in memory, read-only)"
    hosts = sorted({r.get("source_host") for r in refs if r.get("source_host") not in _MISSING})
    return {"name": name, "path": car_dir, "content_layer": layer, "hosts": hosts,
            "nodes": nodes, "refs": refs}


# --------------------------------------------------------------------------- #
# The union: one entity per strong identity across sources
# --------------------------------------------------------------------------- #
def _earlier(a, b):
    return b if a is None else a if b is None else min(a, b)


def _later(a, b):
    return b if a is None else a if b is None else max(a, b)


def union_nodes(sources: list[dict]) -> tuple[list[dict], list[dict]]:
    """UNION the per-source content nodes by node_id (deterministic by content,
    so the same identity is the same node in every source). Additive: every
    property value any source supplied is kept, ref counts add up, first/last
    seen widen; `sources` names every contributor and `per_source` keeps each
    contribution legible. Every ref is tagged with its source (the boundary)."""
    nodes: dict[str, dict] = {}
    refs: list[dict] = []
    for src in sorted(sources, key=lambda s: s["name"]):
        hosts_by_node: dict[str, list] = defaultdict(list)
        for r in src["refs"]:
            h = r.get("source_host")
            if h not in _MISSING and h not in hosts_by_node[r["node_id"]]:
                hosts_by_node[r["node_id"]].append(h)
            refs.append({"source": src["name"], "source_host": h, "object": r["object"],
                         "guid": r["guid"], "node_id": r["node_id"],
                         "identity_key": r.get("identity_key"), "timestamp": r.get("timestamp")})
        for n in src["nodes"]:
            nid = n["node_id"]
            u = nodes.get(nid)
            if u is None:
                u = nodes[nid] = {"node_id": nid, "kind": n.get("kind"),
                                  "identity_key": n.get("identity_key"),
                                  "identity_value": n.get("identity_value"), "properties": {},
                                  "first_seen": None, "last_seen": None, "ref_count": 0,
                                  "sources": [], "per_source": {}}
            if src["name"] not in u["sources"]:
                u["sources"].append(src["name"])
            u["ref_count"] += n.get("ref_count") or 0
            u["first_seen"] = _earlier(u["first_seen"], n.get("first_seen"))
            u["last_seen"] = _later(u["last_seen"], n.get("last_seen"))
            for k, vs in (n.get("properties") or {}).items():
                lst = u["properties"].setdefault(k, [])
                for v in (vs if isinstance(vs, list) else [vs]):
                    if v not in lst:
                        lst.append(v)
            u["per_source"][src["name"]] = {
                "identity_key": n.get("identity_key"), "ref_count": n.get("ref_count") or 0,
                "first_seen": n.get("first_seen"), "last_seen": n.get("last_seen"),
                "hosts": hosts_by_node.get(nid, [])}
    out = []
    for u in nodes.values():
        u["source_count"] = len(u["sources"])
        out.append(u)
    return out, refs


# --------------------------------------------------------------------------- #
# The cross-source derived relationships
# --------------------------------------------------------------------------- #
def _family_by_prefix() -> dict[str, str]:
    """node_id prefix -> its identity family in relationships.yml (sha256 /
    sha1 / md5 -> hash, sid -> sid): the method label is cross_source_<family>."""
    out = {}
    for name, ident in derive.rules()["identities"].items():
        if ident.get("kind") != "content":
            continue
        for f in ident.get("fields", []):
            out[f[:-len("_hash")] if f.endswith("_hash") else name] = name
    return out


def cross_source_edges(nodes: list[dict], refs: list[dict]) -> list[dict]:
    """One DERIVED edge per (entity shared by >= 2 sources, unordered source
    pair): the entity as seen in one source `corroborated` the entity as seen
    in the other. Bounded by entities x pairs — the record-level many-to-many
    stays on the entity (its refs), as the per-source layer keeps it. The edge
    is stamped at the instant BOTH sources had seen the entity."""
    fam = _family_by_prefix()
    by_node: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in refs:
        by_node[r["node_id"]][r["source"]].append(r)
    out = []
    for n in sorted(nodes, key=lambda x: x["node_id"]):
        if n["source_count"] < 2:
            continue
        prefix = n["node_id"].split(":", 1)[0]
        family = fam.get(prefix, prefix)
        srcs = n["sources"]
        for i, a in enumerate(srcs):
            for b in srcs[i + 1:]:
                pa, pb = n["per_source"][a], n["per_source"][b]
                ra, rb = by_node[n["node_id"]][a], by_node[n["node_id"]][b]
                out.append({
                    "timestamp": _later(pa.get("first_seen"), pb.get("first_seen")),
                    "source_host": (pa["hosts"] or [None])[0],
                    "relationship": VERB,
                    "source_object": n["kind"], "source_guid": n["node_id"],
                    "target_object": n["kind"], "target_guid": n["node_id"],
                    "confidence": CONFIDENCE, "method": f"cross_source_{family}",
                    "class": superset.DERIVED, "identity_key": family, "inferred_end": None,
                    "corroborated_by": [r["guid"] for r in ra[:_CORROBORATION_CAP]]
                                       + [r["guid"] for r in rb[:_CORROBORATION_CAP]],
                    "corroboration": {a: {"records": pa["ref_count"], "hosts": pa["hosts"]},
                                      b: {"records": pb["ref_count"], "hosts": pb["hosts"]}},
                    "sources": [a, b],
                    "source_boundary": {"source": a, "target": b}})
    return out


# --------------------------------------------------------------------------- #
# The aggregate store — the ONLY thing this stage writes
# --------------------------------------------------------------------------- #
class CrossSourceStore:
    """crosssource.db: the union of the per-source content layers plus the
    cross-source derived relationships, every row carrying its source boundary.
    The node/ref/relationship columns are those of the per-source superset.db
    tables (same names, same meaning) plus the boundary columns."""

    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self._create()

    def _create(self):
        self.conn.executescript("""
        -- the contributing per-source stores: the source-boundary registry
        CREATE TABLE IF NOT EXISTS source (
            name TEXT PRIMARY KEY, path TEXT, content_layer TEXT, hosts TEXT,
            content_nodes INTEGER, entity_refs INTEGER);
        -- a content-keyed entity UNIONED across sources: the per-source
        -- content_node columns + sources / source_count / per_source
        CREATE TABLE IF NOT EXISTS content_node (
            node_id TEXT PRIMARY KEY, kind TEXT, identity_key TEXT,
            identity_value TEXT, properties TEXT, first_seen TEXT, last_seen TEXT,
            ref_count INTEGER, sources TEXT, source_count INTEGER, per_source TEXT);
        CREATE INDEX IF NOT EXISTS ix_xnode_sources ON content_node (source_count);
        -- one row per (source, car.db record, content node) reference
        CREATE TABLE IF NOT EXISTS entity_ref (
            id INTEGER PRIMARY KEY, source TEXT, source_host TEXT, object TEXT,
            guid TEXT, node_id TEXT, identity_key TEXT, timestamp TEXT,
            UNIQUE (source, source_host, object, guid, node_id, identity_key));
        CREATE INDEX IF NOT EXISTS ix_xref_node ON entity_ref (node_id);
        -- the cross-source DERIVED relationships: the per-source relationship
        -- columns + corroboration / sources / source_boundary
        CREATE TABLE IF NOT EXISTS relationship (
            id INTEGER PRIMARY KEY, timestamp TEXT, source_host TEXT,
            relationship TEXT,
            source_object TEXT, source_guid TEXT,
            target_object TEXT, target_guid TEXT,
            confidence TEXT, method TEXT,
            "class" TEXT, identity_key TEXT, inferred_end TEXT, corroborated_by TEXT,
            corroboration TEXT, sources TEXT, source_boundary TEXT);
        CREATE INDEX IF NOT EXISTS ix_xrel_ts ON relationship (timestamp);
        CREATE INDEX IF NOT EXISTS ix_xrel_node ON relationship (source_guid);
        """)
        self.conn.commit()

    def insert_sources(self, sources: list[dict]) -> int:
        cur = self.conn.cursor()
        for s in sources:
            cur.execute("INSERT OR REPLACE INTO source VALUES (?,?,?,?,?,?)",
                        (s["name"], s.get("path"), s.get("content_layer"),
                         _json_text(s.get("hosts")), len(s.get("nodes") or []),
                         len(s.get("refs") or [])))
        self.conn.commit()
        return len(sources)

    def insert_content_nodes(self, nodes: list[dict]) -> int:
        cur = self.conn.cursor()
        for n in nodes:
            cur.execute(
                "INSERT OR REPLACE INTO content_node (node_id, kind, identity_key, "
                "identity_value, properties, first_seen, last_seen, ref_count, sources, "
                "source_count, per_source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (n["node_id"], n.get("kind"), n.get("identity_key"), n.get("identity_value"),
                 _json_text(n.get("properties")), n.get("first_seen"), n.get("last_seen"),
                 n.get("ref_count"), _json_text(n.get("sources")), n.get("source_count"),
                 _json_text(n.get("per_source"))))
        self.conn.commit()
        return len(nodes)

    def insert_entity_refs(self, refs: list[dict]) -> int:
        cur = self.conn.cursor()
        for r in refs:
            cur.execute(
                "INSERT OR IGNORE INTO entity_ref (source, source_host, object, guid, "
                "node_id, identity_key, timestamp) VALUES (?,?,?,?,?,?,?)",
                (r["source"], r.get("source_host"), r["object"], r["guid"], r["node_id"],
                 r.get("identity_key"), r.get("timestamp")))
        self.conn.commit()
        return len(refs)

    def insert_edges(self, edges: list[dict]) -> int:
        cur = self.conn.cursor()
        for e in edges:
            cur.execute(
                "INSERT INTO relationship (timestamp, source_host, relationship, "
                "source_object, source_guid, target_object, target_guid, confidence, "
                "method, \"class\", identity_key, inferred_end, corroborated_by, "
                "corroboration, sources, source_boundary) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.get("timestamp"), e.get("source_host"), e["relationship"],
                 e["source_object"], e["source_guid"], e["target_object"], e["target_guid"],
                 e.get("confidence"), e.get("method"), e.get("class") or superset.DERIVED,
                 e.get("identity_key"), e.get("inferred_end"),
                 _json_text(e.get("corroborated_by")), _json_text(e.get("corroboration")),
                 _json_text(e.get("sources")), _json_text(e.get("source_boundary"))))
        self.conn.commit()
        return len(edges)

    def export_jsonl(self, out_dir: str) -> int:
        """car_crosssource.jsonl — the unified entities then the cross-source
        relationships, each line typed (`type`) and carrying its `sources`;
        destined for its own stream (logs-car.crosssource-*), never a
        car_<object> or a per-source car_relationships."""
        n = 0
        with open(os.path.join(out_dir, JSONL_NAME), "w", encoding="utf-8") as fh:
            for table, order in (("content_node", "node_id"), ("relationship", "timestamp, id")):
                cur = self.conn.execute(f"SELECT * FROM {table} ORDER BY {order}")
                cols = [c[0] for c in cur.description]
                for row in cur:
                    fh.write(json.dumps({"type": table, **_row_dict(cols, row)}, default=str) + "\n")
                    n += 1
        return n

    def counts(self) -> dict:
        q = lambda sql: self.conn.execute(sql).fetchone()[0]  # noqa: E731
        return {"source_count": q("SELECT count(*) FROM source"),
                "content_nodes": q("SELECT count(*) FROM content_node"),
                "cross_source_nodes": q("SELECT count(*) FROM content_node WHERE source_count >= 2"),
                "entity_refs": q("SELECT count(*) FROM entity_ref"),
                "relationships": q("SELECT count(*) FROM relationship")}

    def close(self):
        self.conn.close()


# --------------------------------------------------------------------------- #
# The pass
# --------------------------------------------------------------------------- #
def run(tree: str, out_dir: str | None = None) -> dict:
    """The end-stage over every per-source store under `tree`, into
    <out_dir>/crosssource.db + car_crosssource.jsonl (default out_dir:
    <tree>/crosssource). Rebuilt from the per-source stores each run; the
    per-source stores are read-only inputs and are never written."""
    found = discover(tree)
    if not found:
        raise FileNotFoundError(f"no car.db under {tree!r}")
    out_dir = out_dir or os.path.join(os.path.abspath(tree), OUT_DIRNAME)
    os.makedirs(out_dir, exist_ok=True)
    sources = [load_source(name, d) for name, d in found]
    nodes, refs = union_nodes(sources)
    edges = cross_source_edges(nodes, refs)
    db = os.path.join(out_dir, DB_NAME)
    if os.path.exists(db):
        os.remove(db)
    st = CrossSourceStore(db)
    try:
        st.insert_sources(sources)
        st.insert_content_nodes(nodes)
        st.insert_entity_refs(refs)
        st.insert_edges(edges)
        exported = st.export_jsonl(out_dir)
        summary = st.counts()
    finally:
        st.close()
    return {"tree": tree, "out_dir": out_dir, "crosssource_db": db,
            "sources": [s["name"] for s in sources],
            "content_layers": {s["name"]: s["content_layer"] for s in sources},
            **summary, "exported": exported, "jsonl": os.path.join(out_dir, JSONL_NAME)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="piiat_mitrecar.crosssource",
        description="the OPT-IN cross-source correlation end-stage over a tree of finished "
                    "per-source stores (car.db + superset.db each); writes only its own "
                    "aggregate store, never the per-source ones")
    ap.add_argument("tree", help="a tree of per-source car directories, e.g. the --batch output root")
    ap.add_argument("--out", default=None,
                    help=f"output dir for {DB_NAME} + {JSONL_NAME} (default: <tree>/{OUT_DIRNAME})")
    args = ap.parse_args(argv)
    try:
        summary = run(args.tree, args.out)
    except FileNotFoundError as exc:
        ap.error(str(exc))
    json.dump(summary, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
