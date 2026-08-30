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
- **dedupe** on (host, object, guid, action [, target_guid, access_level]) —
  the most-populated row wins; identity-less rows never collapse.
- **canonical well-known accounts** (S-1-5-18/19/20) so `user` means the same
  string in every table.
"""
from __future__ import annotations

import os
from collections import defaultdict

from . import carmodel

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




def _populated(ev: dict) -> int:
    return sum(1 for k, v in ev.items() if not k.startswith("_") and v not in (None, ""))


def _dedupe(events: list[dict]) -> list[dict]:
    best, order = {}, []
    for ev in events:
        k = tuple(ev.get(f) if f != "car_object" else ev["car_object"]
                  for f in rules()["dedupe_key"])
        if ev.get("guid") is None:
            k = k + (id(ev),)          # no identity -> never collapse
        if k not in best:
            best[k] = ev
            order.append(k)
        elif _populated(ev) > _populated(best[k]):
            best[k] = ev
    return [best[k] for k in order]


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


def _match(candidates, ts):
    """The process a PID means at time `ts`: latest create <= ts. A timestamped
    event whose window disqualifies every candidate matches NOTHING; only a
    timestamp-less event falls back to an unambiguous single candidate."""
    if not candidates:
        return None
    if ts:
        eligible = [c for c in candidates if (c.get("timestamp") or "") <= ts]
        return eligible[-1] if eligible else None
    return candidates[0] if len(candidates) == 1 else None


def _inherit(ev, owner, obj_fields):
    for f in _inherit_fields():
        if f in obj_fields and ev.get(f) in (None, "") and owner.get(f) not in (None, ""):
            ev[f] = owner[f]


def _resolve_owner(ev, by_guid, by_pid):
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
        owner = _match(by_pid.get((host, pid), []), ev.get("timestamp"))
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


def enrich(events: list[dict]) -> list[dict]:
    """Dedupe, link, inherit, canonicalize. Returns the final event list."""
    model = carmodel.load()
    events = _dedupe(events)
    by_guid = _by_guid(events)
    by_pid = _by_pid(events)
    sessions = _session_index(events)

    for ev in events:
        obj_fields = set(model[ev["car_object"]]["fields"])

        if ev["car_object"] == "authentication":
            _link_auth_sessions(ev, sessions)

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
                                ev.get("timestamp")) if ppid is not None else None
                conf = "heuristic" if parent is not None else None
            if parent is not None and parent is not ev:
                ev["parent_guid"] = parent.get("guid")
                ev["link_confidence"] = conf
                for src, dst in _parent_inherit().items():
                    if dst in obj_fields and ev.get(dst) in (None, "") \
                            and parent.get(src) not in (None, ""):
                        ev[dst] = parent[src]
            continue

        owner, conf = _resolve_owner(ev, by_guid, by_pid)
        if owner is not None:
            ev["owning_guid"] = owner.get("guid")
            ev["link_confidence"] = conf
            _inherit(ev, owner, obj_fields)
    return events
