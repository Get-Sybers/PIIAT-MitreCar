"""log2timeline json_line splitting — vendored from the DX_DFIR ingest lane.

A raw Plaso json_line file is a CONTAINER of many parsers; these helpers wrap
each record as {SourceImage, RecordId, Timestamp, Parser, Record} and split it
into per-parser table files (streaming — safe on multi-GB files).
Self-contained (stdlib only) so the tool stays standalone.

RecordId is the record's physical line in the container — the per-record index
a row's positional identity falls back on when its artefact carries no
intrinsic one (normalize._spindle). Like the EVTX record id, it is minted from
the input itself: stable across re-splits of the same json_line file, never
across a re-run of the parser.
"""
from __future__ import annotations

import datetime
import json
import os
import re

def table_name(parser: str) -> str:
    """Top-level parser -> table name: filestat -> L2tFilestat,
    winreg/appcompatcache -> L2tWinreg, firefox_cache -> L2tFirefoxCache."""
    top = re.split(r"/", parser or "unknown")[0] or "unknown"
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", top) if p]
    return "L2t" + "".join(p[:1].upper() + p[1:] for p in parts) if parts else "L2tUnknown"



def _iter_numbered_jsonl(path: str):
    """Yield (line number, record) from a JSON Lines file, ONE LINE AT A TIME
    (no whole-file read).

    This never slurps the file into memory, so it is safe on a multi-GB Plaso
    json_line output. Vanish-tolerant (missing file -> nothing) and per-line
    error-tolerant (a bad line is skipped). The 1-based PHYSICAL line number is
    the record's positional identity (RecordId): blank and unparseable lines are
    skipped but still counted, so a later fix that makes a bad line parse never
    renumbers its neighbours."""
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield lineno, json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue


def _iter_jsonl(path: str):
    """Yield records from a JSON Lines file, one line at a time (see
    :func:`_iter_numbered_jsonl`)."""
    for _lineno, rec in _iter_numbered_jsonl(path):
        yield rec



def _l2t_row(rec: dict, source_rel: str, record_id: int | None = None) -> tuple[str, str]:
    """(table, wrapped-JSONL-string) for one Plaso record — {SourceImage, RecordId,
    Timestamp, Parser, Record}. `record_id` is the record's line in the container
    (its positional identity; left out when the caller has none). A zero/absent/
    out-of-range timestamp is left unset (not 1970)."""
    parser = str(rec.get("parser") or "unknown")
    row = {"SourceImage": source_rel}
    if record_id is not None:
        row["RecordId"] = record_id
    row.update({"Parser": parser, "Record": rec})
    ts = rec.get("timestamp")
    if isinstance(ts, (int, float)) and ts > 0:
        try:
            row["Timestamp"] = datetime.datetime.fromtimestamp(
                ts / 1_000_000, datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (OverflowError, OSError, ValueError):
            pass
    return table_name(parser), json.dumps(row)



def l2t_tables(path: str) -> dict[str, int]:
    """Streaming scan of a Plaso json_line file -> {table: record_count}. Memory is
    bounded (a small dict of table names). Used for a cheap dry-run report."""
    counts: dict[str, int] = {}
    for rec in _iter_jsonl(path):
        table, _ = _l2t_row(rec, "")
        counts[table] = counts.get(table, 0) + 1
    return counts



def split_l2t(path: str, source_rel: str, out_dir: str, prefix: str) -> dict[str, str]:
    """Stream a Plaso json_line file into per-parser table files, WITHOUT holding the
    file (or the split) in memory — the input can be many GB. Each record is wrapped
    as {SourceImage, Timestamp, Parser, Record} and appended to ``out_dir/{prefix}.
    {table}`` as it is read. Returns {table: filepath}. Only a handful of open file
    handles (one per parser table) and one record are live at a time."""
    handles: dict[str, "object"] = {}
    paths: dict[str, str] = {}
    try:
        for lineno, rec in _iter_numbered_jsonl(path):
            table, line = _l2t_row(rec, source_rel, lineno)
            fh = handles.get(table)
            if fh is None:
                fp = os.path.join(out_dir, f"{prefix}.{table}")
                fh = open(fp, "w", encoding="utf-8")
                handles[table] = fh
                paths[table] = fp
            fh.write(line)
            fh.write("\n")
    finally:
        for fh in handles.values():
            fh.close()
    return paths

