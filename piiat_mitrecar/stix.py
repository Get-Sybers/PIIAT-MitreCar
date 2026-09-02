"""STIX 2.1 projection — DERIVED from the stores at export (the D4 exchange layer).

car.db holds the OBJECT events (one CAR entry per event, every source's
properties superset-filled, the homeless values in `native`); superset.db holds
the RELATIONSHIP instances in both classes (declared cascade edges, derived
strong-identity links), the reconstructed `inferred_node` rows and the
content-keyed attribution layer. This module reads those — and nothing else —
and projects them as STIX 2.1 at export time: there is no second extraction
path, no parser-side STIX, nothing a re-export could disagree with.

    SCO             one per ENTITY a CAR row observes (its process, the file at
                    a path, the registry key, the connection, the account …)
                    plus the CONTENT entities (the same bytes, the same account)
    observed-data   one per CAR row: the observation, timestamped, referencing
                    the row's SCOs, carrying the CAR header (guid = event.id,
                    owning_guid = process.entity_id) and `native` verbatim
    relationship    one SRO per superset.db relationship row, labelled with its
                    class (declared | derived) and its method
    x-car-inferred-node
                    a reconstructed-but-unobserved end (antiforensics / partial
                    recovery): flagged, corroborated, referenced by derived SROs
                    only — never an SCO, never inside an observed-data

Ids come in two scopes, the D4 rule:

- CONTENT-KEYED entities (a file by hash, an account by real SID, an IP, a
  domain, a URL, an e-mail address) get the STIX 2.1 §2.9 spec-deterministic
  GLOBAL id — UUIDv5 over the STIX namespace and the canonical JSON of the
  ID-contributing properties — so the same content is the same object in every
  case and for every consumer.
- INSTANCE / OBSERVATION entities (a process, a file at a path, a key, a
  connection, every observed-data, every SRO) get a CASE-SCOPED id — UUIDv5
  under a per-case namespace — so a re-export of the same case is byte-identical
  and two cases never collide.

The identity conventions mirror the CAR->ECS projection: guid <-> event.id,
owning_guid -> process.entity_id (the acting process; on a process row the guid
itself unless owning_guid is set), parent_guid -> the parent, native ->
car.native (here x_car_native). The contract is model/stix/.

    python -m piiat_mitrecar.stix export <car-dir> [--out FILE] [--case ID]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import uuid
from collections import Counter, defaultdict

from . import derive, enrich, store, superset
from .timeline import _parse_ts  # noqa: SLF001 — the one tolerant ISO-8601 parser

SPEC = "2.1"
# STIX 2.1 §2.9: the namespace every spec-deterministic SCO id is minted under
STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# the project namespace case-scoped ids hang off: case_ns = uuid5(CAR_NS, "case|<case>")
CAR_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Get-Sybers/PIIAT-MitreCar/stix")
EPOCH = "1970-01-01T00:00:00.000Z"
PRODUCER = {"type": "identity", "spec_version": SPEC,
            "id": f"identity--{uuid.uuid5(CAR_NS, 'identity|piiat-mitrecar')}",
            "created": EPOCH, "modified": EPOCH, "name": "PIIAT-MitreCar",
            "identity_class": "system",
            "description": "MITRE CAR evidence stores (car.db + superset.db), projected to STIX 2.1 at export"}

# STIX 2.1 §2.9: when `hashes` contributes to an id ONE hash is used, chosen in this order
HASH_PREFERENCE = ("MD5", "SHA-1", "SHA-256", "SHA-512")
HASH_FIELDS = {"md5_hash": "MD5", "sha1_hash": "SHA-1", "sha256_hash": "SHA-256"}
_ALGO_BY_NODE_PREFIX = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}   # derive's node_id prefixes
_NODE_PREFIX_BY_ALGO = {a: p for p, a in _ALGO_BY_NODE_PREFIX.items()}
# the pipeline confidence vocabulary -> STIX `confidence` (0-100) on an SRO
CONFIDENCE = {"definitive": 100, "heuristic": 50, "inferred": 20}

# The projection contract per CAR object — model/stix/objects.yml mirrors this
# table and tests/test_stix.py holds the two in step.
#   sco           the SCO type the row's ENTITY projects to
#   sro_end       what a relationship end on this object resolves to: the entity
#                 `sco`, or the row's `observed-data` when the object is an event
#                 (an authentication, a session) rather than a thing
#   hash_subject  which path the row's md5/sha1/sha256 fields hash (per leaf);
#                 None where the object carries no hash fields
#   acting        the row's columns that describe the ACTING process (ECS
#                 process.*): filled onto the owning process SCO when the cascade
#                 resolved owning_guid, left under x_car_fields when it did not
#                 (an unresolved owner is derive's inferred node, never a minted SCO)
OBJECTS = {
    "authentication": {"sco": "user-account", "sro_end": "observed-data",
                       "hash_subject": None, "acting": []},
    "driver": {"sco": "file", "sro_end": "sco", "hash_subject": "image_path", "acting": ["pid"]},
    "email": {"sco": "email-message", "sro_end": "sco", "hash_subject": None, "acting": []},
    "file": {"sco": "file", "sro_end": "sco", "hash_subject": "file_path",
             "acting": ["pid", "ppid", "image_path"]},
    "flow": {"sco": "network-traffic", "sro_end": "sco", "hash_subject": None,
             "acting": ["pid", "ppid", "exe", "image_path"]},
    "http": {"sco": "network-traffic", "sro_end": "sco", "hash_subject": None, "acting": []},
    "module": {"sco": "file", "sro_end": "sco", "hash_subject": "module_path",
               "acting": ["pid", "image_path"]},
    "process": {"sco": "process", "sro_end": "sco", "hash_subject": "image_path", "acting": []},
    "registry": {"sco": "windows-registry-key", "sro_end": "sco", "hash_subject": None,
                 "acting": ["pid", "image_path"]},
    "service": {"sco": "process", "sro_end": "sco", "hash_subject": None, "acting": []},
    "socket": {"sco": "network-traffic", "sro_end": "sco", "hash_subject": None,
               "acting": ["pid", "image_path"]},
    "thread": {"sco": "x-car-thread", "sro_end": "sco", "hash_subject": None, "acting": ["src_pid"]},
    "user_session": {"sco": "user-account", "sro_end": "observed-data",
                     "hash_subject": None, "acting": []},
}

_MISSING = (None, "")
_HEADER = set(store.HEADER) | {"car_object", "native", "event_id"}
_ORDER = {"identity": 0, "observed-data": 2, "x-car-inferred-node": 3, "relationship": 4}  # SCOs: 1
_INTEGRITY = {"low", "medium", "high", "system"}


# --------------------------------------------------------------------------- #
# Ids
# --------------------------------------------------------------------------- #
def canonical_json(props: dict) -> str:
    """The ID-contributing properties as §2.9 canonical JSON (sorted keys, no
    whitespace, UTF-8) — RFC 8785 for the string values this projection contributes."""
    return json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def global_id(sco_type: str, contributing: dict) -> str:
    """A spec-deterministic GLOBAL SCO id (STIX 2.1 §2.9)."""
    return f"{sco_type}--{uuid.uuid5(STIX_NS, canonical_json(contributing))}"


def case_namespace(case: str) -> uuid.UUID:
    return uuid.uuid5(CAR_NS, f"case|{case}")


def case_id(ns: uuid.UUID, obj_type: str, *parts) -> str:
    """A CASE-SCOPED id: UUIDv5 under the case namespace over the typed key."""
    key = "|".join("" if p is None else str(p) for p in parts)
    return f"{obj_type}--{uuid.uuid5(ns, f'{obj_type}|{key}')}"


def content_hash(hashes: dict) -> tuple[str, str] | None:
    """The ONE hash §2.9 contributes to a file id: the first present in
    HASH_PREFERENCE, else the lexicographically first algorithm."""
    for algo in HASH_PREFERENCE:
        if algo in hashes:
            return algo, hashes[algo]
    if hashes:
        algo = sorted(hashes)[0]
        return algo, hashes[algo]
    return None


def content_file_id(hashes: dict) -> str | None:
    k = content_hash(hashes)
    return global_id("file", {"hashes": {k[0]: k[1]}}) if k else None


def stix_ts(value) -> str | None:
    """A CAR timestamp as a STIX timestamp (UTC, millisecond precision), or None."""
    dt = _parse_ts(value)
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _basename(path) -> str | None:
    s = str(path).rstrip("/\\")
    return re.split(r"[\\/]", s)[-1] or None if s else None


def _dirname(path) -> str | None:
    s = str(path).rstrip("/\\")
    m = re.match(r"^(.*)[\\/][^\\/]+$", s)
    if not m:
        return None
    return m.group(1) or ("/" if s.startswith("/") else None)


def _clean(o: dict) -> dict:
    return {k: v for k, v in o.items() if v not in (None, "", [], {})}


def _fill(cur: dict, new: dict, root: dict, prefix: str = "") -> None:
    """The additive superset fill at the STIX layer: every property `cur` lacks
    is filled, a list is unioned, a disagreeing scalar is kept under
    x_car_conflicts on the object — never overwritten, never nulled."""
    for k, v in new.items():
        if k in ("id", "type", "spec_version") or v in (None, "", [], {}):
            continue
        have = cur.get(k)
        if have in (None, "", [], {}):
            cur[k] = v
        elif isinstance(have, list) and isinstance(v, list):
            for x in v:
                if x not in have:
                    have.append(x)
        elif isinstance(have, dict) and isinstance(v, dict) and k != "x_car_conflicts":
            _fill(have, v, root, prefix + k + ".")
        elif have != v:
            alts = root.setdefault("x_car_conflicts", {}).setdefault(prefix + k, [])
            if v not in alts:
                alts.append(v)


class _Row:
    """A CAR row with CONSUMPTION tracking: every column a builder homes is
    marked; what no SCO property could home lands verbatim under x_car_fields
    on the observation (the D4 rule: nothing homeless is dropped)."""

    def __init__(self, ev: dict):
        self.ev, self.used = ev, set()

    def peek(self, f: str):
        v = self.ev.get(f)
        return None if v in _MISSING else v

    def get(self, f: str):
        v = self.peek(f)
        if v is not None:
            self.used.add(f)
        return v

    def int(self, f: str):
        i = enrich._to_int(self.ev.get(f))  # noqa: SLF001 — hex-tolerant, as the cascade reads pids
        if i is not None:
            self.used.add(f)
        return i                                 # unparseable: stays verbatim under x_car_fields

    def ts(self, f: str):
        t = stix_ts(self.ev.get(f))
        if t is not None:
            self.used.add(f)
        return t

    def leftovers(self) -> dict:
        return {k: v for k, v in self.ev.items()
                if k not in self.used and k not in _HEADER and not k.startswith("_")
                and v not in _MISSING}


class _Ctx:
    def __init__(self, ev: dict, n: int):
        self.host = ev.get("source_host")
        self.obj = ev["car_object"]
        self.action = ev.get("car_action")
        self.guid = ev.get("guid")
        self.key = self.guid if self.guid is not None else f"row{n}"
        self.owning_guid = ev.get("owning_guid")
        self.ts = stix_ts(ev.get("timestamp"))


def _hashes(r: _Row) -> dict:
    """The row's accepted hash fields as STIX `hashes` (lower-case hex), by the
    same identity rule derive.py keys content nodes with."""
    rule = derive.rules()["identities"]["hash"]
    out = {}
    for f, algo in HASH_FIELDS.items():
        v = r.peek(f)
        if v is not None and derive._accepts(rule, v):  # noqa: SLF001
            out[algo] = derive._normalize(rule, v)      # noqa: SLF001
            r.used.add(f)
    return out


# --------------------------------------------------------------------------- #
# The projection
# --------------------------------------------------------------------------- #
class Projection:
    def __init__(self, case: str, as_of: str):
        self.case, self.ns, self.as_of = case, case_namespace(case), as_of
        self.objs: dict[str, dict] = {}
        self.primary: dict[tuple, str] = {}         # (host, object, guid) -> the row's entity SCO
        self.obs: dict[tuple, str] = {}             # (host, object, guid) -> the row's observed-data
        self.obs_by_guid: dict[tuple, list] = defaultdict(list)
        self.node_content: dict[str, str] = {}      # superset content node_id -> the global SCO id
        self.record_refs: dict[tuple, list] = defaultdict(list)
        self.stats: Counter = Counter()
        self._n = 0
        self._refs: list[str] = []
        self._roles: dict[str, list] = {}

    # -- registry ------------------------------------------------------------
    def _put(self, o: dict) -> str:
        o = _clean(o)
        cur = self.objs.get(o["id"])
        if cur is None:
            self.objs[o["id"]] = o
        else:
            _fill(cur, o, cur)
        return o["id"]

    def ref(self, sco_id: str | None, role: str | None) -> None:
        if not sco_id:
            return
        if sco_id not in self._refs:
            self._refs.append(sco_id)
        if role:
            roles = self._roles.setdefault(sco_id, [])
            if role not in roles:
                roles.append(role)

    # -- content-keyed SCOs (global ids) --------------------------------------
    def _value_sco(self, sco_type: str, value, role: str | None) -> str | None:
        if value in _MISSING:
            return None
        v = str(value).strip()
        if not v:
            return None
        sid = global_id(sco_type, {"value": v})
        self._put({"type": sco_type, "spec_version": SPEC, "id": sid, "value": v})
        self.ref(sid, role)
        return sid

    def ip(self, r: _Row, field: str, role: str) -> str | None:
        v = r.peek(field)
        if v is None:
            return None
        try:
            a = ipaddress.ip_address(str(v).strip())
        except ValueError:
            return None                          # not an address: stays verbatim under x_car_fields
        r.used.add(field)
        return self._value_sco("ipv4-addr" if a.version == 4 else "ipv6-addr", str(a), role)

    def domain(self, r: _Row, field: str, role: str) -> str | None:
        return self._value_sco("domain-name", r.get(field), role)

    def url(self, r: _Row, field: str, role: str) -> str | None:
        return self._value_sco("url", r.get(field), role)

    def email_addr(self, value, role: str) -> str | None:
        return self._value_sco("email-addr", value, role)

    def user(self, host, ident, name, role: str) -> str | None:
        """A user-account: GLOBAL (keyed by the SID alone — account_login would
        contribute, so the login name goes to display_name) when `ident` is a
        REAL account SID by derive's identity rule; else a per-host instance."""
        if ident is None and name is None:
            return None
        rule = derive.rules()["identities"]["sid"]
        if ident is not None and derive._accepts(rule, ident):  # noqa: SLF001
            sid = derive._normalize(rule, ident)                 # noqa: SLF001
            uid = global_id("user-account", {"user_id": sid})
            o = {"type": "user-account", "spec_version": SPEC, "id": uid, "user_id": sid,
                 "x_car_content": True}
            if name is not None:
                o["display_name"] = str(name)
                o["x_car_logins"] = [str(name)]
        else:
            key = ("id", ident) if ident is not None else ("name", name)
            uid = case_id(self.ns, "user-account", host, *key)
            o = {"type": "user-account", "spec_version": SPEC, "id": uid, "x_car_source_host": host}
            if ident is not None:
                o["user_id"] = str(ident)
            if name is not None:
                o["account_login"] = str(name)
        self._put(o)
        self.ref(uid, role)
        return uid

    def content_ref(self, hashes: dict) -> str | None:
        """The global content file the row's hashes belong to — the superset
        node group when the content pass saw them, else the spec id of the row's own."""
        for algo, v in hashes.items():
            nid = f"{_NODE_PREFIX_BY_ALGO.get(algo, algo.lower())}:{v}"
            if nid in self.node_content:
                return self.node_content[nid]
        return content_file_id(hashes)

    # -- instance SCOs (case-scoped ids) -------------------------------------
    def directory(self, host, path) -> str:
        did = case_id(self.ns, "directory", host, path)
        self._put({"type": "directory", "spec_version": SPEC, "id": did, "path": str(path),
                   "x_car_source_host": host})
        self.ref(did, None)
        return did

    def file_instance(self, host, path, name, hashes: dict, role, fallback: tuple,
                      **props) -> str | None:
        """The file AT A PATH on a host (an instance): keyed by path, else by
        name, else by the row; its hashes also bind it to the global content file."""
        props = {k: v for k, v in props.items() if v not in _MISSING}
        if path is None and name is None and not hashes and not props:
            return None
        key = ("path", path) if path is not None else ("name", name) if name is not None \
            else ("row",) + tuple(fallback)
        fid = case_id(self.ns, "file", host, *key)
        o = {"type": "file", "spec_version": SPEC, "id": fid, "x_car_source_host": host}
        nm = name if name is not None else (_basename(path) if path is not None else None)
        if nm is not None:
            o["name"] = str(nm)
        if path is not None:
            o["x_car_path"] = str(path)
            d = _dirname(path)
            if d:
                o["parent_directory_ref"] = self.directory(host, d)
        if hashes:
            o["hashes"] = dict(hashes)
            o["x_car_content_ref"] = self.content_ref(hashes)
        o.update(props)
        self._put(o)
        self.ref(fid, role)
        return fid

    def process(self, host, guid, props: dict | None = None, image_path=None, image_name=None,
                hashes: dict | None = None, role: str | None = None, **image_props) -> str:
        """The process ENTITY (host, guid) — every row naming it fills the same SCO."""
        pid_ = case_id(self.ns, "process", host, guid)
        o = {"type": "process", "spec_version": SPEC, "id": pid_, "x_car_entity_id": str(guid),
             "x_car_source_host": host}
        o.update({k: v for k, v in (props or {}).items() if v not in _MISSING})
        if image_path is not None or image_name is not None or hashes:
            o["image_ref"] = self.file_instance(host, image_path, image_name, hashes or {}, None,
                                                ("process", guid), **image_props)
        self._put(o)
        self.primary.setdefault((host, "process", str(guid)), pid_)
        self.ref(pid_, role)
        return pid_

    def record(self, c: _Ctx) -> str:
        """The fallback when a row projects no entity at all: the record itself,
        so its observation still has an object to reference."""
        rid = case_id(self.ns, "x-car-record", c.host, c.obj, c.key)
        self._put({"type": "x-car-record", "spec_version": SPEC, "id": rid, "x_car_object": c.obj,
                   "x_car_event_id": c.guid, "x_car_source_host": c.host})
        self.ref(rid, c.obj)
        return rid

    # -- the content layer (superset content_node / entity_ref, from the events)
    def content(self, events: list[dict]) -> None:
        """The content-keyed entities: derive's content pass over the same
        events (one node per algorithm/value), the hash nodes one record
        co-references UNIONED into one file carrying all its hashes, whose id is
        the §2.9 one; real-SID nodes become the global user-accounts."""
        nodes, refs = derive.content_entities(events)
        by_id = {n["node_id"]: n for n in nodes}
        parent: dict[str, str] = {}

        def find(x):
            while parent.get(x, x) != x:
                x = parent[x]
            return x

        per_record: dict[tuple, list] = defaultdict(list)
        for ref in refs:
            per_record[(ref.get("source_host"), ref["object"], str(ref["guid"]))].append(ref)
        for lst in per_record.values():
            hs = [x["node_id"] for x in lst if by_id[x["node_id"]]["kind"] == "file_content"]
            for a in hs[1:]:
                ra, rb = find(hs[0]), find(a)
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
        groups: dict[str, list] = defaultdict(list)
        for n in nodes:
            if n["kind"] == "file_content":
                groups[find(n["node_id"])].append(n)
            elif n["kind"] == "user_account":
                self._content_user(n)
        for members in groups.values():
            self._content_file(members)
        for ref in refs:
            sco = self.node_content.get(ref["node_id"])
            if sco:
                self.record_refs[(ref.get("source_host"), ref["object"], str(ref["guid"]))] \
                    .append((sco, ref.get("identity_key")))

    def _content_file(self, members: list[dict]) -> None:
        hashes, conflicts, props = {}, {}, defaultdict(list)
        first = last = None
        refs = 0
        for m in sorted(members, key=lambda n: n["node_id"]):
            algo = _ALGO_BY_NODE_PREFIX.get(m["node_id"].split(":", 1)[0])
            if algo is None:
                continue
            if algo in hashes and hashes[algo] != m["identity_value"]:
                conflicts.setdefault("hashes." + algo, []).append(m["identity_value"])
            else:
                hashes[algo] = m["identity_value"]
            for k, vs in (m.get("properties") or {}).items():
                for v in vs:
                    if v not in props[k]:
                        props[k].append(v)
            refs += m.get("ref_count") or 0
            fs, ls = m.get("first_seen"), m.get("last_seen")
            first = fs if first is None or (fs and fs < first) else first
            last = ls if last is None or (ls and ls > last) else last
        fid = content_file_id(hashes)
        if fid is None:
            return
        paths = [p for k in ("file_path", "image_path", "module_path") for p in props.get(k, [])]
        names = list(dict.fromkeys([_basename(p) for p in paths if _basename(p)]
                                   + [str(n) for n in props.get("file_name", [])]))
        # `name` would contribute to the id (§2.9): the content file is the hash
        # alone — every name/path it was seen under rides under x_car_*
        self._put({"type": "file", "spec_version": SPEC, "id": fid, "hashes": hashes,
                   "x_car_content": True, "x_car_names": names, "x_car_paths": paths,
                   "x_car_signers": [str(s) for s in props.get("signer", [])],
                   "x_car_ref_count": refs, "x_car_first_seen": first, "x_car_last_seen": last,
                   "x_car_conflicts": conflicts})
        for m in members:
            self.node_content[m["node_id"]] = fid

    def _content_user(self, n: dict) -> None:
        sid = n["identity_value"]
        uid = global_id("user-account", {"user_id": sid})
        props = n.get("properties") or {}
        users = [str(u) for u in props.get("user", [])]
        self._put({"type": "user-account", "spec_version": SPEC, "id": uid, "user_id": sid,
                   "x_car_content": True, "display_name": users[0] if users else None,
                   "x_car_logins": users, "x_car_hosts": [str(h) for h in props.get("hostname", [])],
                   "x_car_ref_count": n.get("ref_count"),
                   "x_car_first_seen": n.get("first_seen"), "x_car_last_seen": n.get("last_seen")})
        self.node_content[n["node_id"]] = uid

    # -- one CAR row -> its SCOs + its observed-data ------------------------
    def row(self, ev: dict) -> None:
        self._n += 1
        obj = ev["car_object"]
        if obj not in OBJECTS:
            self.stats["rows_unknown_object"] += 1
            return
        r, c = _Row(ev), _Ctx(ev, self._n)
        self._refs, self._roles = [], {}
        prim = _BUILDERS[obj](self, r, c) or self.record(c)
        if c.owning_guid and obj != "process":
            self._acting(r, c)
        if c.guid is not None:
            self.primary.setdefault((c.host, obj, str(c.guid)), prim)
        for sco, role in self.record_refs.get((c.host, obj, str(c.guid)), []):
            self.ref(sco, role)
        self.stats["rows"] += 1
        if c.ts is None:
            # an observation time is never invented: the SCOs stand, no observed-data
            self.stats["observations_skipped_no_timestamp"] += 1
            return
        oid = case_id(self.ns, "observed-data", c.host, obj, c.key, c.action, ev.get("timestamp"),
                      ev.get("target_guid"), ev.get("access_level"))
        entity = c.owning_guid or (c.guid if obj == "process" else None)
        self._put({"type": "observed-data", "spec_version": SPEC, "id": oid,
                   "created": c.ts, "modified": c.ts, "created_by_ref": PRODUCER["id"],
                   "first_observed": c.ts, "last_observed": c.ts, "number_observed": 1,
                   "object_refs": list(self._refs), "labels": [f"car:{obj}"],
                   "x_car_object": obj, "x_car_action": c.action, "x_car_event_id": c.guid,
                   "x_car_process_entity_id": entity, "x_car_source_host": c.host,
                   "x_car_source_artefact": ev.get("source_artefact"),
                   "x_car_link_confidence": ev.get("link_confidence"),
                   "x_car_timestamp": ev.get("timestamp"), "x_car_roles": dict(self._roles),
                   "x_car_fields": r.leftovers(), "x_car_native": ev.get("_native") or {}})
        if c.guid is not None:
            self.obs[(c.host, obj, str(c.guid))] = oid
            self.obs_by_guid[(c.host, str(c.guid))].append(oid)

    def _acting(self, r: _Row, c: _Ctx) -> None:
        """The spoke's acting-process columns fill the OWNING process SCO
        (additively) — the cascade resolved it, so it exists; never a second
        process SCO minted from the spoke."""
        cols = OBJECTS[c.obj]["acting"]
        props, image_path, image_name = {}, None, None
        for col in cols:
            if col in ("pid", "src_pid"):
                props["pid"] = r.int(col)
            elif col == "ppid":
                props["x_car_ppid"] = r.int(col)
            elif col == "image_path":
                image_path = r.get(col)
            elif col == "exe":
                image_name = r.get(col)
        self.process(c.host, c.owning_guid, props, image_path=image_path, image_name=image_name,
                     role="owning_guid")

    # -- inferred nodes and relationships (superset.db) -----------------------
    def inferred(self, n: dict) -> str:
        """A reconstructed node as a FLAGGED, opinion-style object: never the
        would-be SCO type, never referenced by an observed-data."""
        host, node_id = n.get("source_host"), n["node_id"]
        nid = case_id(self.ns, "x-car-inferred-node", host, node_id)
        fs, ls = stix_ts(n.get("first_seen")), stix_ts(n.get("last_seen"))
        corr = n.get("corroborated_by") or []
        if isinstance(corr, str):
            try:
                corr = json.loads(corr)
            except ValueError:
                corr = [corr]
        self._put({"type": "x-car-inferred-node", "spec_version": SPEC, "id": nid,
                   "created": fs or self.as_of, "modified": ls or fs or self.as_of,
                   "created_by_ref": PRODUCER["id"],
                   "labels": ["car:inferred", "car:reconstructed"],
                   "confidence": CONFIDENCE["inferred"],
                   "x_car_inferred": True, "x_car_asserted": False,
                   "x_car_would_be": OBJECTS.get(n.get("object"), {}).get("sco"),
                   "x_car_object": n.get("object"), "x_car_node_id": node_id,
                   "x_car_source_host": host, "x_car_identity_key": n.get("identity_key"),
                   "x_car_identity_value": n.get("identity_value"), "x_car_method": n.get("method"),
                   "x_car_reason": n.get("reason"), "x_car_corroborated_by": corr,
                   "x_car_corroborating_refs": [o for g in corr
                                                for o in self.obs_by_guid.get((host, str(g)), [])],
                   "x_car_properties": n.get("properties") or {},
                   "x_car_first_seen": n.get("first_seen"), "x_car_last_seen": n.get("last_seen")})
        return nid

    def _end(self, host, obj, guid, inferred: bool, e: dict) -> str | None:
        if guid is None:
            return None
        if inferred:
            nid = case_id(self.ns, "x-car-inferred-node", host, guid)
            if nid not in self.objs:     # named by the edge only: flag it from the edge itself
                self.inferred({"node_id": guid, "source_host": host, "object": obj,
                               "identity_key": e.get("identity_key"), "identity_value": guid,
                               "method": e.get("method"), "corroborated_by": e.get("corroborated_by"),
                               "reason": "referenced by a derived relationship only; "
                                         "no observed record (reconstructed, not evidence)"})
            return nid
        key = (host, obj, str(guid))
        if OBJECTS.get(obj, {}).get("sro_end") == "observed-data":
            return self.obs.get(key)
        sco = self.primary.get(key)
        if sco is None and obj == "process":
            sco = case_id(self.ns, "process", host, guid)
            if sco not in self.objs:
                sco = None
        return sco

    def edge(self, e: dict) -> None:
        cls = e.get("class") or superset.DECLARED
        inf = e.get("inferred_end")
        host = e.get("source_host")
        s = self._end(host, e.get("source_object"), e.get("source_guid"), inf == "source", e)
        t = self._end(host, e.get("target_object"), e.get("target_guid"), inf == "target", e)
        if s is None or t is None:
            self.stats["relationships_unresolved"] += 1
            return
        verb = re.sub(r"[^a-z0-9-]+", "-", str(e.get("relationship") or "").lower()).strip("-") \
            or "related-to"
        evidence_ts = stix_ts(e.get("timestamp"))
        ts = evidence_ts or self.as_of
        corr = e.get("corroborated_by")
        if isinstance(corr, str):
            try:
                corr = json.loads(corr)
            except ValueError:
                corr = [corr]
        rid = case_id(self.ns, "relationship", cls, verb, s, t, e.get("timestamp"), e.get("method"))
        self._put({"type": "relationship", "spec_version": SPEC, "id": rid, "created": ts,
                   "modified": ts, "created_by_ref": PRODUCER["id"], "relationship_type": verb,
                   "source_ref": s, "target_ref": t, "start_time": evidence_ts,
                   "labels": [f"car:{cls}"] + ([f"car:{e['method']}"] if e.get("method") else []),
                   "confidence": CONFIDENCE.get(e.get("confidence")),
                   "x_car_class": cls, "x_car_method": e.get("method"),
                   "x_car_confidence": e.get("confidence"), "x_car_identity_key": e.get("identity_key"),
                   "x_car_inferred_end": inf, "x_car_corroborated_by": corr,
                   "x_car_source_host": host})
        self.stats[f"relationships_{cls}"] += 1

    # -- the bundle -----------------------------------------------------------
    def bundle(self) -> dict:
        def key(o):
            return (_ORDER.get(o["type"], 1), o["type"],
                    o.get("first_observed") or o.get("start_time") or o.get("created") or "",
                    o["id"])
        return {"type": "bundle", "id": case_id(self.ns, "bundle", self.case),
                "objects": [PRODUCER] + sorted(self.objs.values(), key=key)}


# --------------------------------------------------------------------------- #
# Per-object builders: the row's ENTITY SCO(s); return the primary id
# --------------------------------------------------------------------------- #
def _b_process(p: Projection, r: _Row, c: _Ctx) -> str:
    entity = c.owning_guid or c.guid           # ECS: owning_guid names the ACTING process when set
    props = {"pid": r.int("pid"), "command_line": r.get("command_line"),
             "cwd": r.get("current_working_directory")}
    if c.action == "create":
        props["created_time"] = c.ts
    il = r.peek("integrity_level")
    if il is not None and str(il).lower() in _INTEGRITY:
        props["extensions"] = {"windows-process-ext": {"integrity_level": str(r.get("integrity_level")).lower()}}
    parent = r.get("parent_guid")
    if parent:
        props["parent_ref"] = p.process(c.host, parent,
                                        {"pid": r.int("ppid"), "command_line": r.get("parent_command_line")},
                                        image_path=r.get("parent_image_path"), image_name=r.get("parent_exe"))
    else:                                       # a parent the cascade did not resolve: what the row says, no SCO
        pp = {"pid": r.int("ppid"), "image_path": r.get("parent_image_path"), "exe": r.get("parent_exe"),
              "command_line": r.get("parent_command_line")}
        props["x_car_parent"] = _clean(pp)
    ident = r.get("sid")
    if ident is None:
        ident = r.get("uid")
    props["creator_user_ref"] = p.user(c.host, ident, r.get("user"), "sid" if ident is not None else "user")
    pid_ = p.process(c.host, entity, props, image_path=r.get("image_path"), image_name=r.get("exe"),
                     hashes=_hashes(r), role="process", x_car_signer=r.get("signer"),
                     x_car_signature_valid=r.get("signature_valid"))
    if c.action == "access":
        tg = r.get("target_guid")
        if tg:
            p.process(c.host, tg, {"pid": r.int("target_pid")}, image_path=r.get("target_name"),
                      role="target_guid")
    return pid_


def _b_file(p: Projection, r: _Row, c: _Ctx) -> str | None:
    fid = p.file_instance(c.host, r.get("file_path"), r.get("file_name"), _hashes(r), "file",
                          (c.obj, c.key), ctime=r.ts("creation_time"), mime_type=r.get("mime_type"),
                          x_car_signer=r.get("signer"), x_car_signature_valid=r.get("signature_valid"))
    p.user(c.host, r.get("owner_uid"), r.get("owner"), "owner_uid")
    p.user(c.host, r.get("uid"), r.get("user"), "uid")
    return fid


def _b_module(p: Projection, r: _Row, c: _Ctx) -> str | None:
    return p.file_instance(c.host, r.get("module_path"), r.get("module_name"), _hashes(r), "module",
                           (c.obj, c.key), x_car_signer=r.get("signer"),
                           x_car_signature_valid=r.get("signature_valid"),
                           x_car_base_address=r.get("base_address"))


def _b_driver(p: Projection, r: _Row, c: _Ctx) -> str | None:
    return p.file_instance(c.host, r.get("image_path"), r.get("module_name"), _hashes(r), "driver",
                           (c.obj, c.key), x_car_signer=r.get("signer"),
                           x_car_signature_valid=r.get("signature_valid"),
                           x_car_base_address=r.get("base_address"))


def _b_registry(p: Projection, r: _Row, c: _Ctx) -> str:
    key = r.get("key")
    kid = case_id(p.ns, "windows-registry-key", c.host,
                  *(("key", key) if key is not None else ("row", c.obj, c.key)))
    o = {"type": "windows-registry-key", "spec_version": SPEC, "id": kid, "x_car_source_host": c.host,
         "key": str(key) if key is not None else None}
    if r.peek("value") is not None or r.peek("data") is not None:
        val = {"name": r.get("value"), "data": r.get("data")}
        typ = r.peek("type")
        if typ is not None and str(typ).upper().startswith("REG_"):
            val["data_type"] = str(r.get("type")).upper()
        o["values"] = [{k: str(v) for k, v in val.items() if v is not None}]
    o["creator_user_ref"] = p.user(c.host, None, r.get("user"), "user")
    p._put(o)  # noqa: SLF001
    p.ref(kid, "registry")
    return kid


def _network(p: Projection, r: _Row, c: _Ctx, src: str, dst: str, sport: str, dport: str) -> dict:
    """The network-traffic instance shared by flow/socket: keyed by the row,
    its ends the GLOBAL address SCOs."""
    nid = case_id(p.ns, "network-traffic", c.host, c.obj, c.key)
    return {"type": "network-traffic", "spec_version": SPEC, "id": nid, "x_car_source_host": c.host,
            "x_car_object": c.obj, "src_ref": p.ip(r, src, src), "dst_ref": p.ip(r, dst, dst),
            "src_port": r.int(sport), "dst_port": r.int(dport)}


def _b_flow(p: Projection, r: _Row, c: _Ctx) -> str:
    o = _network(p, r, c, "src_ip", "dest_ip", "src_port", "dest_port")
    protos = [str(v).lower() for v in (r.get("transport_protocol"), r.get("application_protocol")) if v]
    o.update({"protocols": protos or ["ip"],           # required by the spec; "ip" is the honest floor
              "src_byte_count": r.int("out_bytes"), "dst_byte_count": r.int("in_bytes"),
              "start": r.ts("start_time"), "end": r.ts("end_time")})
    if o["end"]:
        o["is_active"] = False
    p._put(o)  # noqa: SLF001
    p.ref(o["id"], "flow")
    return o["id"]


def _b_socket(p: Projection, r: _Row, c: _Ctx) -> str:
    o = _network(p, r, c, "local_address", "remote_address", "local_port", "remote_port")
    proto = r.get("protocol")
    o["protocols"] = [str(proto).lower()] if proto else ["ip"]
    fam = r.peek("family")
    if fam is not None and str(fam).upper().startswith("AF_"):  # address_family is required in the ext
        o["extensions"] = {"socket-ext": {"address_family": str(r.get("family")).upper(),
                                          "is_listening": c.action == "listen"}}
    p._put(o)  # noqa: SLF001
    p.ref(o["id"], "socket")
    return o["id"]


def _b_http(p: Projection, r: _Row, c: _Ctx) -> str:
    nid = case_id(p.ns, "network-traffic", c.host, c.obj, c.key)
    host_hdr = r.peek("url_domain")
    scheme = r.get("url_scheme")
    o = {"type": "network-traffic", "spec_version": SPEC, "id": nid, "x_car_source_host": c.host,
         "x_car_object": c.obj, "src_ref": p.ip(r, "requester_ip_address", "requester_ip_address"),
         "dst_ref": p.domain(r, "url_domain", "url_domain"),
         "protocols": ["tcp", str(scheme).lower() if scheme and str(scheme).lower() in ("http", "https") else "http"],
         "x_car_url_ref": p.url(r, "url_full", "url_full"),
         "x_car_response_status_code": r.get("response_status_code"),
         "x_car_response_body_bytes": r.int("response_body_bytes")}
    value = r.get("url_remainder")
    if value is None and r.peek("url_full") is not None:
        value = r.peek("url_full")
    if value is not None:                     # request_method + request_value are required in the ext
        ext = {"request_method": str(c.action).lower(), "request_value": str(value),
               "request_version": r.get("http_version"),
               "request_header": _clean({"User-Agent": r.get("user_agent_full"),
                                         "Referer": r.get("request_referrer"), "Host": host_hdr}),
               "message_body_length": r.int("request_body_bytes")}
        o["extensions"] = {"http-request-ext": _clean(ext)}
    p._put(o)  # noqa: SLF001
    p.ref(nid, "http")
    return nid


def _b_authentication(p: Projection, r: _Row, c: _Ctx) -> str | None:
    target = p.user(c.host, r.get("target_uid"), r.get("target_user"), "target_uid")
    subject = p.user(c.host, r.get("uid"), r.get("user"), "uid")
    return target or subject


def _b_user_session(p: Projection, r: _Row, c: _Ctx) -> str | None:
    u = p.user(c.host, r.get("uid"), r.get("user"), "uid")
    p.ip(r, "src_ip", "src_ip")
    p.ip(r, "dest_ip", "dest_ip")
    return u


def _b_service(p: Projection, r: _Row, c: _Ctx) -> str:
    """STIX has no service SCO: a process with the windows-service-ext, keyed by
    the service name on the host."""
    name = r.get("name")
    sid = case_id(p.ns, "process", c.host, *(("service", name) if name else ("row", c.obj, c.key)))
    image_path, exe = r.get("image_path"), r.get("exe")
    o = {"type": "process", "spec_version": SPEC, "id": sid, "x_car_source_host": c.host,
         "x_car_object": "service", "command_line": r.get("command_line"), "pid": r.int("pid"),
         "creator_user_ref": p.user(c.host, r.get("uid"), r.get("user"), "uid")}
    if image_path is not None or exe is not None:
        o["image_ref"] = p.file_instance(c.host, image_path, exe, {}, None, (c.obj, c.key))
    if name:
        o["extensions"] = {"windows-service-ext": {"service_name": str(name)}}
    p._put(o)  # noqa: SLF001
    p.ref(sid, "service")
    return sid


def _b_thread(p: Projection, r: _Row, c: _Ctx) -> str:
    """STIX 2.1 has no thread SCO: the thread observation is carried as an
    x-car-thread; its processes are the owning process (acting) and, via the
    declared/derived SROs, the target."""
    tid = case_id(p.ns, "x-car-thread", c.host, c.key)
    o = {"type": "x-car-thread", "spec_version": SPEC, "id": tid, "x_car_source_host": c.host,
         "src_pid": r.peek("src_pid")}                       # peeked: the acting column fills the owner
    for f in ("src_tid", "tgt_pid", "tgt_tid", "start_address", "start_function", "start_module_name",
              "stack_base", "stack_limit", "user_stack_base", "user_stack_limit"):
        o[f] = r.get(f)
    sm = r.get("start_module")
    if sm is not None:
        o["start_module_ref"] = p.file_instance(c.host, sm, None, {}, None, (c.obj, c.key))
    o["creator_user_ref"] = p.user(c.host, r.get("uid"), r.get("user"), "uid")
    p._put(o)  # noqa: SLF001
    p.ref(tid, "thread")
    return tid


def _split(v) -> list:
    out = []
    for x in derive._values(v):  # noqa: SLF001 — a list column, JSON text or scalar
        out.extend(s.strip() for s in re.split(r"[;,]", str(x)) if s.strip())
    return out


def _b_email(p: Projection, r: _Row, c: _Ctx) -> str:
    eid = case_id(p.ns, "email-message", c.host, c.key)
    o = {"type": "email-message", "spec_version": SPEC, "id": eid, "is_multipart": False,
         "x_car_source_host": c.host, "from_ref": p.email_addr(r.get("from"), "from"),
         "sender_ref": p.email_addr(r.get("return_address"), "return_address"),
         "subject": r.get("subject"), "date": r.ts("date"), "body": r.get("message_body")}
    if r.peek("to") is not None:
        o["to_refs"] = [x for x in (p.email_addr(v, "to") for v in _split(r.get("to"))) if x]
    att = r.get("attachment_name")
    if att is not None:
        o["x_car_attachment_ref"] = p.file_instance(c.host, None, att, {}, "attachment_name", (c.obj, c.key),
                                                    mime_type=r.get("attachment_mime_type"),
                                                    size=r.int("attachment_size"))
    if r.peek("message_links") is not None:
        o["x_car_link_refs"] = [x for x in (p._value_sco("url", v, "message_links")  # noqa: SLF001
                                            for v in _split(r.get("message_links"))) if x]
    p.ip(r, "src_ip", "src_ip")
    p.ip(r, "dest_ip", "dest_ip")
    p._put(o)  # noqa: SLF001
    p.ref(eid, "email")
    return eid


_BUILDERS = {"authentication": _b_authentication, "driver": _b_driver, "email": _b_email,
             "file": _b_file, "flow": _b_flow, "http": _b_http, "module": _b_module,
             "process": _b_process, "registry": _b_registry, "service": _b_service,
             "socket": _b_socket, "thread": _b_thread, "user_session": _b_user_session}


# --------------------------------------------------------------------------- #
# The pass
# --------------------------------------------------------------------------- #
def project(events: list[dict], edges: list[dict] = (), inferred_nodes: list[dict] = (),
            case: str = "default", as_of: str | None = None) -> tuple[dict, dict]:
    """The bundle + a summary from in-memory stores: the enriched events (native
    as _native), superset relationship rows, inferred_node rows. `as_of` is the
    `created` stamp for objects that carry no evidence time (default: the
    latest evidence time, so a re-export is byte-identical)."""
    if as_of is None:
        stamps = [stix_ts(x.get("timestamp")) for x in list(events) + list(edges)]
        as_of = max([s for s in stamps if s], default=EPOCH)
    p = Projection(case, as_of)
    p.content(events)
    for ev in events:
        p.row(ev)
    for n in inferred_nodes:
        p.inferred(n)
    for e in edges:
        p.edge(e)
    bundle = p.bundle()
    summary = {"case": case, "as_of": as_of, "objects": len(bundle["objects"]),
               "by_type": dict(sorted(Counter(o["type"] for o in bundle["objects"]).items()))}
    summary.update(sorted(p.stats.items()))
    return bundle, summary


def load(car_dir: str) -> tuple[list[dict], list[dict], list[dict]]:
    """(events, relationship rows, inferred_node rows) from <car_dir>/car.db +
    superset.db — the finished stores, read as they are."""
    car_db, sup_db = os.path.join(car_dir, "car.db"), os.path.join(car_dir, "superset.db")
    if not os.path.isfile(car_db):
        raise SystemExit(f"no car.db under {car_dir!r}")
    events = derive.load_events(car_db)
    edges, nodes = [], []
    if os.path.isfile(sup_db):
        st = superset.SupersetStore(sup_db)
        try:
            for table, dst in (("relationship", edges), ("inferred_node", nodes)):
                cur = st.conn.execute(f"SELECT * FROM {table} ORDER BY id")
                cols = [c[0] for c in cur.description]
                dst.extend(superset._row_dict(cols, row) for row in cur)  # noqa: SLF001
        finally:
            st.close()
    return events, edges, nodes


def export(car_dir: str, out_path: str | None = None, case: str | None = None,
           as_of: str | None = None) -> dict:
    """Derive <car_dir>/stix_bundle.json (or `out_path`) from the stores.
    `case` scopes the instance ids (default: the car directory's name)."""
    case = case or os.path.basename(os.path.abspath(car_dir.rstrip("/\\"))) or "default"
    events, edges, nodes = load(car_dir)
    bundle, summary = project(events, edges, nodes, case=case, as_of=as_of)
    out_path = out_path or os.path.join(car_dir, "stix_bundle.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, default=str)
        fh.write("\n")
    summary["bundle"] = out_path
    summary["bundle_id"] = bundle["id"]
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="piiat_mitrecar.stix",
                                 description="STIX 2.1, derived from a source's stores at export")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export", help="derive <car-dir>/stix_bundle.json from car.db + superset.db")
    ex.add_argument("car_dir", help="a source's car directory (car.db [+ superset.db])")
    ex.add_argument("--out", default=None, help="bundle path (default: <car-dir>/stix_bundle.json)")
    ex.add_argument("--case", default=None,
                    help="case id scoping the instance ids (default: the car directory's name)")
    ex.add_argument("--as-of", default=None,
                    help="ISO timestamp stamped as `created` where no evidence time exists "
                         "(default: the latest evidence time)")
    args = ap.parse_args(argv)
    as_of = stix_ts(args.as_of) if args.as_of else None
    if args.as_of and not as_of:
        ap.error(f"--as-of is not an ISO-8601 timestamp: {args.as_of!r}")
    json.dump(export(args.car_dir, args.out, args.case, as_of), sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
