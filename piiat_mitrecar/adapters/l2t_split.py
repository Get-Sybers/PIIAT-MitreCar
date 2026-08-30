"""log2timeline json_line splitting — vendored from the DX_DFIR ingest lane.

A raw Plaso json_line file is a CONTAINER of many parsers; these helpers wrap
each record as {SourceImage, Timestamp, Parser, Record} and split it into
per-parser table files (streaming — safe on multi-GB files). Self-contained
(stdlib only) so the tool stays standalone.
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



def _iter_jsonl(path: str):
    """Yield records from a JSON Lines file, ONE LINE AT A TIME (no whole-file read).

    Unlike :func:`_records`, this never slurps the file into memory, so it is safe on
    a multi-GB Plaso json_line output. Vanish-tolerant (missing file -> nothing) and
    per-line error-tolerant (a bad line is skipped)."""
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue



def _l2t_row(rec: dict, source_rel: str) -> tuple[str, str]:
    """(table, wrapped-JSONL-string) for one Plaso record — {SourceImage, Timestamp,
    Parser, Record}. A zero/absent/out-of-range timestamp is left unset (not 1970)."""
    parser = str(rec.get("parser") or "unknown")
    row = {"SourceImage": source_rel, "Parser": parser, "Record": rec}
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
        for rec in _iter_jsonl(path):
            table, line = _l2t_row(rec, source_rel)
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

