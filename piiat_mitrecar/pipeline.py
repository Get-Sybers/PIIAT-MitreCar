"""The per-file CAR pipeline — one ingested file, one CAR database (epic #86).

Owner's isolation rule: **each ingested file gets its OWN car database for
enrichment** — enrichment runs only within that file's events, so no source
ever depends on another source being present, and nothing is mixed. Cross-source
("final") enrichment is a separate, optional end-stage over the aggregate,
gated behind the capability determination — never part of the per-file product.

    python -m piiat_mitrecar --in <file> --out <dir> [--artefacts k1,k2]

One input file -> route to its artefact map(s) -> normalize -> enrich
(self-contained) -> <out>/car.db + <out>/car_<object>.jsonl (the ADX contract).
A PIIAT-Mem car.db input passes through 1:1 (already finished CAR).

Routing is by filename when --artefacts is not given; a Security log feeds BOTH
its authentication and its user_session maps (same file — the in-file LUID join
between them is legitimately self-contained).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile

from . import enrich, readers, store

# EvtxECmd output is ONE uniform shape across all ~110 Windows channels, so it
# is CONTENT-routed, not filename-routed: every *_EvtxECmd_Output.json feeds the
# whole evtx map family and each map's (Channel, EventId) predicate decides which
# rows it claims (a row matching none is dropped). Adding a channel/EventId is a
# map change, never a routing change.
EVTX_MAPS = ["evtx_security",           # Security 4624/4625/4672 -> authentication
             "evtx_security_sessions",  # Security 4624/4634/4647/4778/4779 -> user_session
             "evtx_process",            # Security 4688 -> process
             "evtx_services",           # System 7045 / Security 4697 -> service
             "evtx_sysmon",             # Sysmon EIDs -> process/flow/file/registry/module/driver/thread
             "evtx_bits",               # BITS-Client 59/60 -> http
             "evtx_rdp",                # TerminalServices 21/24/25 -> user_session
             "evtx_more"]               # 4907/5857/20003/30803/7001/7002/7034 -> file/module/service/flow/user_session
# NB: the Security-audit families (4663/4657/4660/4670/4689/5140/5145/5156/5157/
# 5158/5058 -> file/registry/process/flow/socket) are NOT active — their mappings
# are unvalidated inferences quarantined in ../to-be-validated/evtx_audit.yml
# until confirmed against an audit-enabled capture. Promote from there.

# filename-pattern -> artefact map keys (explicit, first match wins)
ROUTES = [
    ("_EvtxECmd_Output", EVTX_MAPS),
    ("conn.json", ["zeek_conn"]),
    ("http.json", ["zeek_http"]),
    ("smtp.json", ["zeek_smtp"]),
    ("files.json", ["zeek_files"]),
    # Zeek logs with no dedicated CAR object — routed to nothing EXPLICITLY (known,
    # not unknown): their per-flow detail can enrich the flow by uid at the
    # cascade stage, but they are not CAR objects.
    ("dns.json", []), ("ssl.json", []), ("x509.json", []), ("dhcp.json", []),
    ("ntp.json", []), ("snmp.json", []), ("ocsp.json", []), ("weird.json", []),
    ("pe.json", []), ("packet_filter.json", []),
    (".L2tPrefetch", ["plaso_exec_prefetch"]),
    (".L2tWinreg", ["plaso_exec_winreg", "plaso_registry", "plaso_shellitem"]),
    (".L2tSyslog", ["plaso_exec_cron", "l2t_text"]),
    (".L2tCron", ["plaso_exec_cron"]),
    (".L2tFilestat", ["l2t_filestat"]),
    (".L2tMft", ["l2t_mft"]),
    (".L2tUsnjrnl", ["l2t_usnjrnl"]),
    (".L2tWinevt", ["l2t_winevt"]),     # Plaso legacy EVT  -> the winevtx CAR maps
    (".L2tWinevtx", ["l2t_winevt"]),    # Plaso modern EVTX -> the winevtx CAR maps
    (".L2tMsiecf", ["l2t_msiecf"]),     # IE index.dat visits -> http
    (".L2tFirefoxCache", ["l2t_firefox_cache"]),  # -> http (recorded method/status)
    (".L2tSqlite", ["l2t_firefox_places"]),       # firefox page visits -> http (gated by data_type)
    (".L2tJavaIdx", ["l2t_javaidx"]),   # Java download cache -> http
    (".L2tLnk", ["l2t_lnk", "plaso_shellitem"]),  # shortcut target MAC times -> file (+ embedded shell items)
    (".L2tRecycleBinInfo2", ["l2t_recyclebin"]),  # deletion events -> file/delete
    (".L2tRecycleBin", ["l2t_recyclebin"]),
    # l2t tables with NO CAR object — routed to [] EXPLICITLY (known, not
    # unknown): pe = compilation times (no CAR file action); olecf = document
    # internal streams; rplog = restore-point info; fseventsd = macOS flags
    # (2 rows, undecoded). Their rows stay raw.
    (".L2tPe", ["plaso_pecoff"]),        # pe_coff:file -> timestamp-less file record (path + sha256 + PE meta, compile_time native); dll_import/resource -> raw
    (".L2tOlecf", ["plaso_olecf"]),      # olecf:summary_info -> file (doc + authoring meta); olecf:item -> raw
    (".L2tRplog", []),
    (".L2tFseventsd", ["plaso_fseventsd"]),  # macOS FSEvents -> file/modify (never dropped)
    (".L2tEsedb", ["l2t_srum"]),        # Plaso esedb/srum -> flow + process (SRUM)
    ("_RECmd_Batch_", ["recmd_batch"]), # RECmd --json batch output -> registry
    ("jlecmd_AutomaticDestinations", ["jlecmd_dest"]),  # jump lists -> file (via adapter)
    ("jlecmd_CustomDestinations", []),  # pin-centric, no interaction times -> raw
    ("_LECmd_Output", []),              # lnk: the l2t lnk map is canonical (artefact != processor)
    ("recmd_batch.json", ["recmd_batch"]),
    (".L2tUtmp", ["l2t_utmp"]),
    (".L2tUtmpx", ["l2t_utmpx"]),
    (".L2tText", ["l2t_text"]),
]


def route(path: str) -> list[str]:
    name = os.path.basename(path)
    for pattern, keys in ROUTES:
        if pattern in name:
            return keys
    return []


def _is_raw_l2t(path: str) -> bool:
    """A raw log2timeline json_line file: unwrapped Plaso records (top-level
    data_type + parser, no `Record`), as opposed to the split per-table files
    the l2t maps consume."""
    if not path.endswith(".jsonl"):
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                r = json.loads(line)
                return isinstance(r, dict) and "data_type" in r and "Record" not in r
    except (OSError, ValueError):
        return False
    return False


def _iter_source_files(in_path: str):
    """The files that make up ONE source. A directory (a Zeek capture, a host's
    event-log export) is a single source: every file under it is routed and
    merged into ONE car.db, so within-source cross-log enrichment can run and no
    other source is depended on. A single file is a one-file source."""
    if os.path.isdir(in_path):
        for root, _dirs, files in os.walk(in_path):
            for fn in sorted(files):
                yield os.path.join(root, fn)
    else:
        yield in_path


def process_file(in_path: str, out_dir: str, artefacts: list[str] | None = None,
                 default_host: str | None = None, derive_pass: bool = False) -> dict:
    """One SOURCE -> its own enriched CAR database + JSON export. The source is a
    single file, or a directory whose files together are one source (Zeek's per-
    protocol logs; a host's event-log channels) — same isolation either way.

    `derive_pass` (optional, off by default) adds the DERIVED relationship stage
    (derive.py): additive coalescing before enrich, then data-driven 1:1 links,
    inferred nodes and content entities written into superset.db."""
    os.makedirs(out_dir, exist_ok=True)
    name = os.path.basename(in_path.rstrip("/"))

    if name == "car.db":                       # PIIAT-Mem finished CAR: passthrough
        events = readers.load_piiat_car(in_path)
        used = ["memory (passthrough)"]
    else:
        events, used = [], []

        def _consume_rec(arts, rec):
            for art in arts:
                ev = readers.normalize.normalize(art, rec)
                if ev is None:
                    continue
                if not ev.get("source_host"):
                    ev["source_host"] = default_host
                events.append(ev)

        def _consume(arts, path):
            """Read `path` ONCE and run every routed map per record (content-
            routing sends an evtx file to all evtx maps — re-reading the file per
            map is what made this O(maps × file))."""
            arts = [a for a in arts if a]
            if not arts:
                return
            for a in arts:
                if a not in used:
                    used.append(a)
            # a Plaso winevt table is PORTED to the evtx maps: adapt each record
            # to the EvtxECmd shape, then run the existing EVTX_MAPS over it
            if arts == ["jlecmd_dest"]:
                from .adapters import jlecmd as _jl
                for a in arts:
                    if a not in used:
                        used.append(a)
                for rec in readers.iter_jsonl(path):
                    for flat in _jl.flatten(rec):
                        _consume_rec(["jlecmd_dest"], flat)
                return
            if arts == ["l2t_winevt"]:
                from .adapters import winevt as winevt_adapter
                for a in EVTX_MAPS:
                    if a not in used:
                        used.append(a)
                for wrapped in readers.iter_jsonl(path):
                    shaped = winevt_adapter.adapt(wrapped)
                    if shaped is not None:
                        _consume_rec(EVTX_MAPS, shaped)
                return
            for rec in readers.iter_jsonl(path):
                _consume_rec(arts, rec)

        for f in _iter_source_files(in_path):
            if artefacts:
                _consume(artefacts, f)
            elif _is_raw_l2t(f):
                # a raw log2timeline json_line file is a CONTAINER of many
                # parsers; wrap+split it into per-parser tables (the shape the
                # l2t maps expect) and route each table by its name
                from .adapters import l2t_split as prepare
                # split under the (disk-backed) output dir — a big container's
                # per-parser tables overflow a tmpfs /tmp (hit for real: 15G
                # tmpfs at 98% killed the two largest sources)
                tmp = tempfile.mkdtemp(prefix=".car_l2t_", dir=out_dir)
                try:
                    tables = prepare.split_l2t(f, os.path.basename(f), tmp,
                                               os.path.basename(f))
                    for tpath in tables.values():
                        _consume(route(tpath), tpath)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
            else:
                _consume(route(f), f)

    if derive_pass:
        # ADDITIVE coalescing (D4): rows that are the same event become ONE entry
        # holding every source's properties, so enrich's dedupe drops nothing
        from . import derive
        events = derive.coalesce(events)
    # enrichment is SELF-CONTAINED: only THIS source's events are in scope
    events = enrich.enrich(events)

    db_path = os.path.join(out_dir, "car.db")
    if os.path.exists(db_path):
        os.remove(db_path)                     # rebuilt from this file each run
    st = store.CarStore(db_path)
    st.insert_events(events)
    counts = st.counts()
    written = st.export_jsonl(out_dir)
    st.close()

    # USE the source-manifest structure: emit the manifest for every source that
    # actually contributed (traceability — the car.db is now paired with a hard
    # file saying "this source gives these objects/actions/properties, derived by
    # this wrapper"), and CAR-validity-check what those sources emit.
    source_ids, source_issues = _write_source_manifests(out_dir, used)

    # the SUPERSET-MODEL database beside car.db: the data model + ATT&CK
    # relationship edge-types, plus the relationship INSTANCES the cascade
    # produced between these events — a second, granular relationship timeline
    # linking the car.db rows by guid.
    from . import superset
    sup = superset.build_superset_db(out_dir, events)
    if derive_pass:
        # the DERIVED class: strong-identity 1:1 links, reconstructed (flagged)
        # nodes, content entities — into the same superset.db, beside car.db
        from . import derive
        sup.update(derive.derive(events, sup["superset_db"], out_dir))
    return {"input": in_path, "artefacts": used, "events": sum(counts.values()),
            "objects": counts, "exported": written, "car_db": db_path,
            "sources": source_ids, "source_manifests": os.path.join(out_dir, "sources.yaml"),
            "source_issues": source_issues, **sup}


def _write_source_manifests(out_dir: str, used: list[str]) -> tuple[list[str], list[str]]:
    """Write the source (sensor) manifests for the artefacts that contributed to
    this car.db, and return (source_ids, CAR-validity problems). Makes each store
    traceable to how it was derived; the manifests are generated from the maps."""
    import yaml
    from . import mappings, sources_model
    docs, ids = [], []
    for u in used:
        key = "memory" if u.startswith("memory") else u
        if key in mappings.MAPPINGS:
            docs.append(sources_model.build_source_doc(key)); ids.append(key)
        elif key in sources_model._PASSTHROUGH:      # noqa: SLF001
            docs.append(sources_model.build_passthrough_doc(key)); ids.append(key)
    with open(os.path.join(out_dir, "sources.yaml"), "w", encoding="utf-8") as fh:
        yaml.safe_dump_all(docs, fh, sort_keys=False, allow_unicode=True)
    # a source must never claim coverage outside the CAR data model
    problems = [p for p in sources_model.validate_against_car_model()
                if any(p.startswith(i + ":") for i in ids)]
    return ids, problems


def discover_sources(processed_dir: str) -> list[tuple[str, str, str | None]]:
    """The CAR sources under a processed tree, honouring the isolation rule
    (one source -> one car.db). Returns (source_name, in_path, default_host):

    - windows_logs/<case>/...: each DIRECTORY holding *_EvtxECmd_Output.json is
      one host's event-log export (one source);
    - zeek/<capture>/: each capture directory (one source, all protocol logs);
    - log2timeline/jsonl/<image>.jsonl: each raw l2t container (one source);
    - volatility/<image>/car.db: PIIAT-Mem finished CAR (passthrough).
    """
    out: list[tuple[str, str, str | None]] = []
    wl = os.path.join(processed_dir, "windows_logs")
    if os.path.isdir(wl):
        dirs = set()
        for root, _d, files in os.walk(wl):
            if any(f.endswith("_EvtxECmd_Output.json") for f in files):
                dirs.add(root)
        for d in sorted(dirs):
            rel = os.path.relpath(d, wl).replace(os.sep, "_")
            out.append((f"windows_logs_{rel}", d, None))
    zk = os.path.join(processed_dir, "zeek")
    if os.path.isdir(zk):
        for name in sorted(os.listdir(zk)):
            d = os.path.join(zk, name)
            if os.path.isdir(d):
                out.append((f"zeek_{name}", d, name))
    l2t = os.path.join(processed_dir, "log2timeline", "jsonl")
    if os.path.isdir(l2t):
        for name in sorted(os.listdir(l2t)):
            if name.endswith(".jsonl"):
                out.append((f"l2t_{name[:-6]}", os.path.join(l2t, name), None))
    zm = os.path.join(processed_dir, "zimmerman")
    if os.path.isdir(zm):
        for name in sorted(os.listdir(zm)):
            d = os.path.join(zm, name)
            if os.path.isdir(d):
                out.append((f"zimmerman_{name}", d, name.upper()))
    vol = os.path.join(processed_dir, "volatility")
    if os.path.isdir(vol):
        for name in sorted(os.listdir(vol)):
            db = os.path.join(vol, name, "car.db")
            if os.path.isfile(db):
                out.append((f"memory_{name}", db, None))
    return out


def run_batch(processed_dir: str, out_root: str, force: bool = False,
              derive_pass: bool = False, stix_export: bool = False) -> list[dict]:
    """Every discovered source -> <out_root>/<source_name>/car.db + car_*.jsonl.
    Idempotent: a source whose output car.db already exists is skipped unless
    `force`. Sources run SEQUENTIALLY (bounded load); one failing source never
    stops the rest. `stix_export` adds the STIX projection step (stix.py) over
    each finished store, case-scoped by the source name."""
    results = []
    for name, in_path, host in discover_sources(processed_dir):
        dst = os.path.join(out_root, name)
        if not force and os.path.isfile(os.path.join(dst, "car.db")):
            results.append({"source": name, "skipped": "exists"})
            continue
        try:
            s = process_file(in_path, dst, default_host=host, derive_pass=derive_pass)
            s["source"] = name
            if stix_export:
                from . import stix
                s["stix"] = stix.export(dst, case=name)
            results.append(s)
        except Exception as exc:                       # noqa: BLE001 — batch isolation
            results.append({"source": name, "error": f"{type(exc).__name__}: {exc}"})
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="piiat_mitrecar",
        description="one ingested source -> its own enriched CAR database + JSON for ADX")
    ap.add_argument("--in", dest="in_path", help="one processed artefact file/dir (single-source mode)")
    ap.add_argument("--out", dest="out_dir", help="output dir (single-source: this source's car.db; batch: the car/ root)")
    ap.add_argument("--artefacts", default=None, help="comma-separated artefact map keys (default: route by filename)")
    ap.add_argument("--host", default=None, help="fallback source_host where the map derives none")
    ap.add_argument("--batch", dest="batch_dir", default=None,
                    help="discover every source under this processed dir and run each (idempotent)")
    ap.add_argument("--force", action="store_true", help="batch: rebuild sources whose car.db already exists")
    ap.add_argument("--derive", action="store_true",
                    help="also run the DERIVED relationship pass (additive coalescing, "
                         "strong-identity 1:1 links, inferred nodes) into superset.db")
    ap.add_argument("--stix", action="store_true",
                    help="also derive the STIX 2.1 bundle (stix_bundle.json) from the finished "
                         "stores (python -m piiat_mitrecar.stix export)")
    args = ap.parse_args(argv)

    if args.batch_dir:
        out_root = args.out_dir or os.path.join(args.batch_dir, "car")
        results = run_batch(args.batch_dir, out_root, force=args.force,
                            derive_pass=args.derive, stix_export=args.stix)
        json.dump(results, sys.stdout, default=str)
        sys.stdout.write("\n")
        return 0 if any("error" not in r for r in results) else 1

    if not (args.in_path and args.out_dir):
        ap.error("--in/--out (single source) or --batch required")
    arts = [a.strip() for a in args.artefacts.split(",") if a.strip()] if args.artefacts else None
    summary = process_file(args.in_path, args.out_dir, artefacts=arts, default_host=args.host,
                           derive_pass=args.derive)
    if args.stix:
        from . import stix
        summary["stix"] = stix.export(args.out_dir)
    json.dump(summary, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0 if summary["events"] or summary["artefacts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
