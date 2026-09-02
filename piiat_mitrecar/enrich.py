"""Enrichment — the CAR relationship + inheritance engine (epic #86).

The logic proven in PIIAT-Mem's store, generalized for the multi-artefact
pipeline. Joins are scoped per **evidence host** (`source_host`) — never across
hosts:

- **process is the hub.** Every spoke (module/flow/file/registry/service/
  thread/socket/http/authentication rows that carry a process reference)
  resolves its owner in two tiers:
    tier 1 — DEFINITIVE: the spoke natively carries the owning process's guid
      (e.g. Sysmon ProcessGuid on every Sysmon spoke event) and a process event
      with that guid exists;
    tier 2 — heuristic: the (pid, create-time window) join — the latest process
      created at-or-before the spoke's timestamp; a process created later can
      never own an earlier event. Marked `link_confidence`.
- **process → parent** by (ppid, create-time window) — heuristic (PID reuse) —
  unless the artefact natively carries ParentProcessGuid (Sysmon 1) —
  definitive.
- **inheritance fills only nulls** — a spoke inherits its owner's context
  (exe, image_path, command_line, user, sid, hostname, fqdn, ppid) only for
  fields its CAR object has and only where its own value is null. A natively
  extracted value is never overwritten.
- **fold (dedupe)** on (host, object, guid, action [, target_guid, access_level]) —
  rows that are the same event FOLD into one (relationships.yml `dedupe`):
  additively by default — every property any row supplied, a disagreeing
  value kept in native, the contributors counted (native.contributions /
  contributed_by) — or the single most-populated row when the rules say so;
  identity-less rows never fold.
- **canonical well-known accounts** (S-1-5-18/19/20) so `user` means the same
  string in every table.
"""
from __future__ import annotations

import os
from collections import defaultdict

from . import carmodel, spindle

# the fold vocabulary (relationships.yml dedupe.fold)
FOLD_ADDITIVE, FOLD_MOST_POPULATED = "additive", "most_populated"
FOLDS = (FOLD_ADDITIVE, FOLD_MOST_POPULATED)
_CONTRIBUTORS_CAP = 64          # contributed_by entries kept per folded row
_MISSING = (None, "")
# native keys the fold itself writes, plus the per-record provenance: never
# merged as evidence, never a conflict (contributed_by carries each row's ref)
_FOLD_NATIVE = ("coalesced_sources", "coalesced_conflicts", "contributions", "contributed_by",
                spindle.NATIVE_REF)

# The relationship & inheritance RULES are data (relationships.yml, beside the
# model) — the engine implements the mechanics; the YAML declares the rules.
_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "relationships.yml")
_rules_cache: dict | None = None


def rules() -> dict:
    global _rules_cache
    if _rules_cache is None:
        import yaml
        with open(_RULES_PATH, encoding="utf-8") as fh:
            _rules_cache = yaml.safe_load(fh)
    return _rules_cache


def _inherit_fields() -> list:
    return rules()["inheritance"]["from_owning_process"]


def _parent_inherit() -> dict:
    return rules()["inheritance"]["from_parent_process"]

def _to_int(v):
    """int() that also accepts Windows hex strings ('0x1FC') — EvtxECmd payload
    PIDs arrive hex; a silent parse failure would silently kill the join."""
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(str(v), 16)
        except (TypeError, ValueError):
            return None




def dedupe_rules() -> dict:
    """relationships.yml `dedupe`: the same-event key and the fold."""
    return rules()["dedupe"]


def dedupe_key() -> list[str]:
    return list(dedupe_rules()["key"])


def _populated(ev: dict) -> int:
    return sum(1 for k, v in ev.items() if not k.startswith("_") and v not in (None, ""))


def _same_event_key(ev: dict):
    k = tuple(ev.get(f) if f != "car_object" else ev["car_object"] for f in dedupe_key())
    return k + (id(ev),) if ev.get("guid") is None else k     # no identity -> never folds


def _merge_into(base: dict, other: dict) -> None:
    """Fold `other` (a second row of the SAME event) into `base`: every
    property `base` lacks is filled; a value that disagrees is kept in native
    under coalesced_conflicts (never overwritten, never nulled); the
    contributing artefacts are listed in coalesced_sources. Native fills the
    same way, except the fold's own keys and the per-record provenance."""
    nat = base.setdefault("_native", {})
    srcs = nat.get("coalesced_sources") or [base.get("source_artefact")]
    if other.get("source_artefact") not in srcs:
        srcs.append(other.get("source_artefact"))
    nat["coalesced_sources"] = srcs
    conflicts = nat.get("coalesced_conflicts") or {}
    tag = {"source_artefact": other.get("source_artefact")}
    for f, v in other.items():
        if f.startswith("_") or f == "source_artefact" or v in _MISSING:
            continue
        cur = base.get(f)
        if cur in _MISSING:
            base[f] = v
        elif str(cur) != str(v):
            conflicts.setdefault(f, []).append(dict(tag, value=v))
    for k, v in (other.get("_native") or {}).items():
        if k in _FOLD_NATIVE or v in _MISSING:
            continue
        cur = nat.get(k)
        if cur in _MISSING:
            nat[k] = v
        elif cur != v and str(cur) != str(v):
            conflicts.setdefault("native." + k, []).append(dict(tag, value=v))
    if conflicts:
        nat["coalesced_conflicts"] = conflicts


def _contributor(ev: dict) -> dict:
    """One contributed_by entry: the artefact and, for a minted row, the
    container + record index it came from (native.spindle_ref)."""
    c = {"source_artefact": ev.get("source_artefact")}
    ref = (ev.get("_native") or {}).get(spindle.NATIVE_REF)
    if ref:
        c[spindle.NATIVE_REF] = ref
    return c


def fold(events: list[dict], mode: str | None = None) -> list[dict]:
    """Rows that are the SAME event (relationships.yml dedupe.key) become ONE
    row, in first-seen order. `additive` (the default rule): the first row is
    the base and every later row folds into it (_merge_into) — nothing a
    contributor carried is lost — and the row counts its contributors:
    native.contributions (the number of rows, summing any prior fold) and
    native.contributed_by ([{source_artefact, spindle_ref}], capped). A lone
    row is left untouched. `most_populated`: the single most-populated row
    survives (the first of equals), the others are discarded. A row with no
    guid has no identity and never folds."""
    mode = mode or dedupe_rules().get("fold") or FOLD_ADDITIVE
    if mode not in FOLDS:
        raise ValueError(f"unknown dedupe fold {mode!r}: one of {FOLDS}")
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for ev in events:
        k = _same_event_key(ev)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(ev)
    out = []
    for k in order:
        rows = groups[k]
        if len(rows) == 1:
            out.append(rows[0])
            continue
        if mode == FOLD_MOST_POPULATED:
            out.append(max(rows, key=_populated))
            continue
        base = rows[0]
        for other in rows[1:]:
            _merge_into(base, other)
        nat = base.setdefault("_native", {})
        nat["contributions"] = sum((r.get("_native") or {}).get("contributions") or 1 for r in rows)
        by: list[dict] = []
        for r in rows:
            by.extend((r.get("_native") or {}).get("contributed_by") or [_contributor(r)])
        nat["contributed_by"] = by[:_CONTRIBUTORS_CAP]
        out.append(base)
    return out


def _is_process_create(ev: dict) -> bool:
    return ev["car_object"] == "process" and ev.get("car_action") == "create"


def _by_guid(events):
    """(host, guid) -> process create event."""
    idx = {}
    for ev in events:
        if _is_process_create(ev) and ev.get("guid"):
            idx[(ev.get("source_host"), str(ev["guid"]))] = ev
    return idx


def _by_pid(events):
    """(host, pid) -> [process create events sorted by create time]."""
    idx = defaultdict(list)
    for ev in events:
        if _is_process_create(ev) and ev.get("pid") is not None:
            pid = _to_int(ev["pid"])
            if pid is None:
                continue
            idx[(ev.get("source_host"), pid)].append(ev)
    for lst in idx.values():
        lst.sort(key=lambda e: e.get("timestamp") or "")
    return idx


def _exit_by_guid(events):
    """(host, guid) -> earliest terminate/exit timestamp for that process
    identity. Lets a pid-window match reject an owner that had ALREADY exited
    before the spoke happened (R2 — process lifetime bounding)."""
    idx = {}
    for ev in events:
        if ev["car_object"] == "process" and ev.get("car_action") in ("terminate", "exit") \
                and ev.get("guid"):
            k = (ev.get("source_host"), str(ev["guid"]))
            ts = ev.get("timestamp") or ""
            if k not in idx or (ts and ts < idx[k]):
                idx[k] = ts
    return idx


def _alive_at(owner, ts, exits):
    """False iff `owner` had terminated strictly before `ts` (so it cannot own
    an event at `ts`). No exit record / no timestamps -> assumed alive."""
    if not ts:
        return True
    ex = exits.get((owner.get("source_host"), str(owner.get("guid"))))
    return not (ex and ex < ts)


def _match(candidates, ts, exits=None):
    """The process a PID means at time `ts`: latest create <= ts that had not
    already terminated by `ts`. A timestamped event whose window disqualifies
    every candidate matches NOTHING; only a timestamp-less event falls back to
    an unambiguous single candidate."""
    if not candidates:
        return None
    if ts:
        eligible = [c for c in candidates if (c.get("timestamp") or "") <= ts
                    and (exits is None or _alive_at(c, ts, exits))]
        return eligible[-1] if eligible else None
    return candidates[0] if len(candidates) == 1 else None


def _inherit(ev, owner, obj_fields):
    for f in _inherit_fields():
        if f in obj_fields and ev.get(f) in (None, "") and owner.get(f) not in (None, ""):
            ev[f] = owner[f]


def _resolve_owner(ev, by_guid, by_pid, exits=None):
    """(owner_event, confidence) for a spoke, tier 1 then tier 2."""
    host = ev.get("source_host")
    native = ev.get("owning_guid_native")
    if native:
        owner = by_guid.get((host, str(native)))
        if owner is not None:
            return owner, "definitive"
    if ev.get("owning_pid") is not None:
        pid = _to_int(ev["owning_pid"])
        if pid is None:
            return None, None
        owner = _match(by_pid.get((host, pid), []), ev.get("timestamp"), exits)
        if owner is not None:
            return owner, "heuristic"
    return None, None




def _session_index(events):
    """(host, lowercased LUID) -> user_session event."""
    idx = {}
    for ev in events:
        if ev["car_object"] == "user_session" and ev.get("login_id"):
            idx[(ev.get("source_host"), str(ev["login_id"]).lower())] = ev
    return idx


def _link_auth_sessions(ev, sessions):
    """A successful authentication names the session it opened (TargetLogonId)
    and the session it was requested FROM (SubjectLogonId) — both LUIDs, both
    joinable per (host, LUID). LUIDs are per-boot unique, so a match on a
    well-known LUID (0x3e7/…) across a multi-boot log is only heuristic; any
    other LUID match is definitive within the evidence window. A FAILED
    authentication opens no session — the target join never runs for it."""
    host = ev.get("source_host")
    nat = ev.get("_native") or {}
    cfg = rules()["joins"]["auth_session_luid"]
    def tier(luid):
        return "heuristic" if luid in set(cfg["well_known_luids"]) else "definitive"
    if ev.get("car_action") == "success":
        luid = str(nat.get("TargetLogonId") or "").lower()
        if luid and luid not in set(cfg["null_luids"]):
            sess = sessions.get((host, luid))
            if sess is not None:
                nat["target_session_guid"] = sess.get("guid")
                nat["target_session_link"] = tier(luid)
    luid = str(nat.get("SubjectLogonId") or "").lower()
    if luid and luid not in set(cfg["null_luids"]):
        sess = sessions.get((host, luid))
        if sess is not None:
            nat["subject_session_guid"] = sess.get("guid")
            nat["subject_session_link"] = tier(luid)


def _flow_by_uid(events):
    """(host, zeek uid) -> flow event. Zeek mints one connection uid that conn/
    http/files all carry; the flow's guid IS that uid (zeek_conn). R3 — a
    spoke (http/file) links to its connection DEFINITIVELY within the capture."""
    idx = {}
    for ev in events:
        if ev["car_object"] == "flow":
            uid = ev.get("guid") or (ev.get("_native") or {}).get("uid")
            if uid:
                idx.setdefault((ev.get("source_host"), str(uid)), ev)
    return idx


def _proc_by_image_path(events):
    """(host, lowercased image_path) -> [process create events]. Keys the
    file->process-by-path edge (CAR-2014-02-001): a file on disk whose path IS a
    process's image_path is the binary that process executed."""
    idx = defaultdict(list)
    for ev in events:
        if _is_process_create(ev):
            ip = ev.get("image_path") or ev.get("exe")
            if ip:
                idx[(ev.get("source_host"), str(ip).lower())].append(ev)
    return idx


def _link_file_to_process(ev, by_image_path):
    """R (CAR-2014-02-001): link a file event to the process(es) that executed
    that exact path on the same host — a PROVEN CAR correlation. Heuristic
    (path equality, not instance identity); surfaced in _native, never a
    canonical column."""
    fp = ev.get("file_path")
    if not fp:
        return
    procs = by_image_path.get((ev.get("source_host"), str(fp).lower()))
    if not procs:
        return
    nat = ev.setdefault("_native", {})
    nat["executed_as_process_guid"] = procs[0].get("guid")
    nat["executed_as_process_link"] = "heuristic"   # file_path == image_path
    if len(procs) > 1:
        nat["executed_as_process_count"] = len(procs)


def _flow_ctx() -> dict:
    """Connection context an http/file spoke may inherit from its zeek flow —
    a rule, declared in relationships.yml (from_owning_flow). Only fields the
    receiving object has; a native value is never overwritten."""
    return rules()["inheritance"].get("from_owning_flow", {})


def _link_zeek_spoke_to_flow(ev, flows, obj_fields):
    uid = (ev.get("_native") or {}).get("uid")
    if not uid:
        return
    flow = flows.get((ev.get("source_host"), str(uid)))
    if flow is None:
        return
    nat = ev.setdefault("_native", {})
    nat["flow_guid"] = flow.get("guid")
    nat["flow_link"] = "definitive"          # shared capture uid
    for dst, src in _flow_ctx().items():
        if dst in obj_fields and ev.get(dst) in (None, "") and flow.get(src) not in (None, ""):
            ev[dst] = flow[src]


def _login_indexes(events):
    """Session logins keyed both ways a logout can name them: by LUID
    (Security 4634/4647 -> TargetLogonId) and by SessionID (TS id24)."""
    by_luid, by_sid = {}, {}
    for ev in events:
        if ev["car_object"] == "user_session" and ev.get("car_action") in ("login", "reconnect", "unlock"):
            if ev.get("login_id"):
                by_luid.setdefault((ev.get("source_host"), str(ev["login_id"]).lower()), ev)
            sid = (ev.get("_native") or {}).get("SessionID")
            if sid not in (None, ""):
                by_sid.setdefault((ev.get("source_host"), str(sid)), ev)
    return by_luid, by_sid


def _pair_session_lifecycle(ev, by_luid, by_sid):
    """R1 — pair a logout to the login it closes (LUID, else SessionID) and
    cross-link them. The CAR model has no session end_time field, so the
    lifetime is surfaced natively (never a fabricated column)."""
    host = ev.get("source_host")
    nat = ev.setdefault("_native", {})
    login = None
    if ev.get("login_id"):
        login = by_luid.get((host, str(ev["login_id"]).lower()))
    if login is None:
        sid = nat.get("SessionID")
        if sid not in (None, ""):
            login = by_sid.get((host, str(sid)))
    if login is not None and login is not ev:
        nat["session_login_guid"] = login.get("guid")
        lnat = login.setdefault("_native", {})
        lnat["session_logout_guid"] = ev.get("guid")
        lnat["session_end"] = ev.get("timestamp")


def enrich(events: list[dict]) -> list[dict]:
    """Fold, link, inherit, canonicalize. Returns the final event list."""
    model = carmodel.load()
    events = fold(events)
    by_guid = _by_guid(events)
    by_pid = _by_pid(events)
    exits = _exit_by_guid(events)
    sessions = _session_index(events)
    flows = _flow_by_uid(events)
    login_luid, login_sid = _login_indexes(events)
    proc_by_image = _proc_by_image_path(events)

    for ev in events:
        obj_fields = set(model[ev["car_object"]]["fields"])

        if ev["car_object"] == "authentication":
            _link_auth_sessions(ev, sessions)

        # R3: zeek http/file spoke -> its connection (definitive by uid)
        if ev["car_object"] in ("http", "file"):
            _link_zeek_spoke_to_flow(ev, flows, obj_fields)

        # CAR-2014-02-001: a file whose path == a process image_path is the
        # binary that process executed (heuristic, path equality)
        if ev["car_object"] == "file":
            _link_file_to_process(ev, proc_by_image)

        # R1: pair a session logout to the login it closes
        if ev["car_object"] == "user_session" and ev.get("car_action") in ("logout", "disconnect"):
            _pair_session_lifecycle(ev, login_luid, login_sid)

        # canonical well-known account names, store-wide — filling blanks and
        # unifying alternate renderings of the SAME account, never overwriting
        # an arbitrary natively-extracted value (that value is evidence).
        ident = rules()["identity"]
        canonical = ident["well_known_sids"].get(str(ev.get("sid") or ev.get("uid") or ""))
        if canonical and "user" in obj_fields:
            cur = ev.get("user")
            if cur in (None, "") or str(cur).strip().lower() in set(ident["canonical_aliases"]):
                ev["user"] = canonical

        if _is_process_create(ev):
            # parent link: native ParentProcessGuid (definitive) else ppid window
            host = ev.get("source_host")
            parent, conf = None, None
            native_parent = (ev.get("_native") or {}).get("ParentProcessGuid")
            if native_parent:
                parent = by_guid.get((host, str(native_parent)))
                conf = "definitive" if parent is not None else None
            if parent is None and ev.get("parent_pid") is not None:
                ppid = _to_int(ev["parent_pid"])
                parent = _match(by_pid.get((host, ppid), []),
                                ev.get("timestamp"), exits) if ppid is not None else None
                conf = "heuristic" if parent is not None else None
            if parent is not None and parent is not ev:
                ev["parent_guid"] = parent.get("guid")
                ev["link_confidence"] = conf
                for src, dst in _parent_inherit().items():
                    if dst in obj_fields and ev.get(dst) in (None, "") \
                            and parent.get(src) not in (None, ""):
                        ev[dst] = parent[src]
            continue

        owner, conf = _resolve_owner(ev, by_guid, by_pid, exits)
        if owner is not None:
            ev["owning_guid"] = owner.get("guid")
            ev["link_confidence"] = conf
            _inherit(ev, owner, obj_fields)

        # R5: CreateRemoteThread names TWO processes — the acting SOURCE (the
        # owner, resolved above) AND the injected TARGET. Surface the target
        # link so the injection relationship is explicit, not just the owner.
        if ev["car_object"] == "thread":
            tgt_native = (ev.get("_native") or {}).get("TargetProcessGuid")
            if tgt_native:
                tgt = by_guid.get((ev.get("source_host"), str(tgt_native)))
                if tgt is not None and tgt is not owner:
                    nat = ev.setdefault("_native", {})
                    nat["target_process_guid"] = tgt.get("guid")
                    nat["target_process_link"] = "definitive"
    return events
