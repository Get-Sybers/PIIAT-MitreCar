"""Build one property-rich, time-ordered CAR timeline from the stores.

Unions the OBJECT events (car.db — every populated CAR field plus the `native`
evidence) and the RELATIONSHIP instances (superset.db — source→verb→target with
confidence/method) into a single timestamp-ordered stream, written as
timeline.jsonl. Point it at one source's car directory, or at a parent tree to
aggregate every source under it.

  python -m piiat_mitrecar.timeline <car-dir-or-tree> [--out FILE]
         [--host H] [--after ISO] [--before ISO] [--objects-only | --edges-only]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys

# the one tolerant ISO-8601 parser (mixed renderings, any fraction width) —
# shared with the engine's ts_before marker and the STIX projection
from .normalize import parse_ts as _parse_ts


def _find_stores(path: str) -> list[str]:
    """The store directories under `path`: `path` itself if it holds a car.db,
    else every directory beneath it that does (aggregate mode)."""
    if os.path.isfile(os.path.join(path, "car.db")):
        return [path]
    return sorted({os.path.dirname(p)
                   for p in glob.glob(os.path.join(path, "**", "car.db"),
                                      recursive=True)})


def _object_entries(car_db: str):
    """One entry per object event, carrying every populated CAR field + native."""
    c = sqlite3.connect(car_db)
    c.row_factory = sqlite3.Row
    try:
        tables = [r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            for r in c.execute(f'SELECT * FROM "{t}" WHERE timestamp IS NOT NULL'):
                entry = {"timestamp": r["timestamp"], "kind": "object", "object": t}
                for k in r.keys():
                    if k in ("event_id", "native", "timestamp"):
                        continue
                    if r[k] not in (None, ""):
                        entry[k] = r[k]
                if r["native"]:
                    try:
                        nat = {k: v for k, v in json.loads(r["native"]).items()
                               if v not in (None, "")}
                        if nat:
                            entry["native"] = nat
                    except (ValueError, TypeError):
                        pass
                yield entry
    finally:
        c.close()


def _edge_entries(superset_db: str):
    """One entry per relationship instance (source→verb→target, confidence)."""
    if not os.path.exists(superset_db):
        return
    c = sqlite3.connect(superset_db)
    c.row_factory = sqlite3.Row
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                         "AND name='relationship'").fetchone():
            return
        for r in c.execute("SELECT * FROM relationship WHERE timestamp IS NOT NULL"):
            yield {
                "timestamp": r["timestamp"], "kind": "relationship",
                "source_host": r["source_host"],
                "relationship": r["relationship"],
                "source_object": r["source_object"], "source_guid": r["source_guid"],
                "target_object": r["target_object"], "target_guid": r["target_guid"],
                "confidence": r["confidence"], "method": r["method"],
            }
    finally:
        c.close()


def build_timeline(path: str, host: str | None = None, after: str | None = None,
                   before: str | None = None, objects_only: bool = False,
                   edges_only: bool = False) -> list[dict]:
    """The merged, time-ordered timeline (objects + relationship edges)."""
    stores = _find_stores(path)
    if not stores:
        raise SystemExit(f"no car.db found under {path!r}")
    rows: list[dict] = []
    for d in stores:
        if not edges_only:
            rows.extend(_object_entries(os.path.join(d, "car.db")))
        if not objects_only:
            rows.extend(_edge_entries(os.path.join(d, "superset.db")))
    if host is not None:
        rows = [e for e in rows if e.get("source_host") == host]
    lo = _parse_ts(after) if after is not None else None
    hi = _parse_ts(before) if before is not None else None
    if after is not None and lo is None:
        raise SystemExit(f"--after: not an ISO-8601 timestamp: {after!r}")
    if before is not None and hi is None:
        raise SystemExit(f"--before: not an ISO-8601 timestamp: {before!r}")
    if lo is not None or hi is not None:
        # a bounded window compares the true instant; an unparseable event
        # timestamp can't be placed, so it's excluded rather than mis-sorted.
        rows = [e for e in rows
                if (dt := _parse_ts(e.get("timestamp"))) is not None
                and (lo is None or dt >= lo) and (hi is None or dt <= hi)]
    rows.sort(key=_sort_key)
    return rows


def _sort_key(e: dict):
    """Order by the true instant; unparseable timestamps sort last (by their
    raw string), and within one instant an object precedes its relationships."""
    dt = _parse_ts(e.get("timestamp"))
    edge = e.get("kind") == "relationship"
    if dt is not None:
        return (0, dt, edge)
    return (1, e.get("timestamp") or "", edge)


def write_jsonl(rows: list[dict], out: str) -> int:
    with open(out, "w", encoding="utf-8") as fh:
        for e in rows:
            fh.write(json.dumps(e, default=str) + "\n")
    return len(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="piiat_mitrecar.timeline",
        description="one property-rich, time-ordered CAR timeline from car.db + superset.db")
    ap.add_argument("car_dir", help="a source's car directory, or a tree to aggregate")
    ap.add_argument("--out", help="output path (default: <car_dir>/timeline.jsonl)")
    ap.add_argument("--host", help="only events whose source_host matches")
    ap.add_argument("--after", help="only events at/after this ISO timestamp")
    ap.add_argument("--before", help="only events at/before this ISO timestamp")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--objects-only", action="store_true")
    g.add_argument("--edges-only", action="store_true")
    a = ap.parse_args(argv)
    rows = build_timeline(a.car_dir, a.host, a.after, a.before,
                          a.objects_only, a.edges_only)
    out = a.out or os.path.join(a.car_dir, "timeline.jsonl")
    write_jsonl(rows, out)
    json.dump({"car_dir": a.car_dir, "timeline": out, "entries": len(rows),
               "objects": sum(1 for e in rows if e["kind"] == "object"),
               "relationships": sum(1 for e in rows if e["kind"] == "relationship")},
              sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
