"""Normalize a raw artefact record into a MITRE CAR event (epic #86).

The same declarative-map + marker engine proven in PIIAT-Mem, generalized for
the DX_DFIR artefacts. A per-artefact map (see `mappings.py`) says which CAR
object/action a record is, its timestamp, the identity that becomes `guid`, and
how each raw field maps to a canonical CAR property. Markers (nestable) do the
small transforms; a canonical column is left null rather than filled with a
near-miss — never faked.

`normalize(artefact, record)` returns one CAR event dict, or None if the record
matches no map (unmapped rows are dropped, not guessed at).
"""
from __future__ import annotations

import ntpath
import posixpath
import re
from datetime import datetime, timedelta, timezone

from . import ids, spindle

_EPOCH_ZERO = re.compile(r"^(1601-01-01|1970-01-01|0001-01-01|1600-12-)")


# --- marker constructors (also importable by mappings.py) -------------------

def first(*srcs):
    """First non-empty of the given field names / markers."""
    return ("first", srcs)


def const(value):
    """A constant the observation itself proves."""
    return ("const", value)


def basename(src):
    """Windows-or-POSIX basename of a path field/marker."""
    return ("basename", src)


def ext(src):
    """Lowercase file extension (no dot) of a path field/marker."""
    return ("ext", src)


def lower(src):
    return ("lower", src)


def regex1(src, pattern):
    """First capture group of `pattern` against the field, or None."""
    return ("regex1", (src, pattern))


def domain_of(src):
    """The domain label of a dotted host/email/url field (after the first '@' or
    the host portion), lowercased — or None."""
    return ("domain_of", src)


def epoch_ts(src):
    """A timestamp field rendered as UTC ISO-8601: epoch-seconds (int/float) are
    converted; a value that is already an ISO string passes through (the zeek
    lane emits ISO8601 in processed json). The store's timestamp form —
    lexicographically ordered, comparable across artefacts."""
    return ("epoch_ts", src)


def map_value(src, table, upper=False):
    """Look the field's value up in a literal table ('GET' -> 'get'); None if
    absent. `upper=True` uppercases before the lookup."""
    return ("map_value", (src, table, upper))


def concat(*parts):
    """Concatenate resolved parts (field names or markers; use const("...") for
    literals) — null if ANY part is missing: a reconstruction made only from
    provable pieces."""
    return ("concat", parts)


def exe_path(src):
    """The executable path parsed out of an ImagePath-style command line
    ('"C:\\p q\\x.exe" -k net' -> 'C:\\p q\\x.exe'; unquoted svchost-style
    lines cut at .exe). Parsing, not guessing — the path is verbatim inside."""
    return ("exe_path", src)


def payload(key, field="Payload"):
    """A key out of an EvtxECmd `Payload` JSON string (EZ tools stamp the event
    data as a JSON blob) — the Python analogue of the KQL EvtxPayload().
    Handles the EventData.Data[] ({@Name,#text}) shape and a flat dict."""
    return ("payload", (field, key))


def userdata(key, field="Payload"):
    """A key out of the OTHER EvtxECmd payload shape — `UserData` with one nested
    child dict of named fields (TerminalServices, WMI-Activity, ...): Payload ->
    UserData -> <single child> -> key."""
    return ("userdata", (field, key))


def host_label(src):
    """The first DNS label of a hostname/FQDN ('HOST1.dom.com' -> 'HOST1')."""
    return ("host_label", src)


def hex_int(src):
    """A PID/handle rendered as an int, accepting decimal or Windows-hex form
    ('0x150' -> 336) so a CAR column is uniform whatever the source's rendering.
    Parsing, not a near-miss — the value is exact."""
    return ("hex_int", src)


def unescape_backslashes(src):
    """Collapse doubled backslashes to single ('C:\\\\x' -> 'C:\\x') — some Plaso
    renderings (lnk link_target) double them; a rendering artifact, not
    evidence."""
    return ("unescape_backslashes", src)


def replace(src, old, new):
    """Literal substring replacement on the resolved value ('2018-04-02 01:15' ->
    '2018-04-02T01:15') — a rendering normalisation, never a semantic change."""
    return ("replace", (src, old, new))


def at(src, index):
    """The element at `index` of a list-valued field/marker (Plaso exposes event-
    log EventData as a positional `strings` list, not named fields) — None if the
    list is absent or too short. Negative indices allowed."""
    return ("at", (src, index))


def ts_before(src, other):
    """True when the timestamp in `src` is strictly earlier than the one in
    `other`, False when it is not, None when either is blank or unparseable.
    Both sides are parsed to the true UTC instant (`parse_ts`: 'T' or ' '
    separator, any fraction width, 'Z'/offset/none) — a comparison of
    instants, never of string bytes. A verdict the two evidence values prove
    (Sysmon 11: CreationUtcTime before UtcTime = the file pre-existed)."""
    return ("ts_before", (src, other))


# --- timestamps -------------------------------------------------------------

# YYYY-MM-DD, T or space, HH:MM:SS, optional .fraction, optional Z or ±HH[:]MM.
_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:(Z)|([+-])(\d{2}):?(\d{2}))?$")


def parse_ts(value):
    """An ISO-8601 timestamp as an aware UTC ``datetime``, or ``None`` if it
    can't be parsed. Tolerant of a trailing ``Z``, a space date/time separator,
    and *any* fractional-second precision — cases ``datetime.fromisoformat``
    rejects before 3.11 (this repo targets 3.10). Events arrive in mixed shapes
    (the epoch_ts path emits ``+00:00``; passthrough lanes emit ``Z`` or other
    fraction widths; Sysmon stamps ``YYYY-MM-DD HH:MM:SS.fff``), so comparing
    and sorting on the true instant — not the string bytes — is what keeps the
    ts_before marker, the timeline's ordering and its --after/--before correct."""
    if not value:
        return None
    m = _TS_RE.match(str(value).strip())
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, _z, sign, oh, om = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss),
                      int((frac or "").ljust(6, "0")[:6]))
    except ValueError:
        return None
    if sign is None:            # Z or no zone → assume UTC (epoch_ts emits UTC)
        tz = timezone.utc
    else:
        off = timedelta(hours=int(oh), minutes=int(om))
        tz = timezone(off if sign == "+" else -off)
    return dt.replace(tzinfo=tz).astimezone(timezone.utc)


# --- resolver ---------------------------------------------------------------

def _blank(v) -> bool:
    return v is None or v == "" or v == "-"


def _clean_ts(v):
    if _blank(v):
        return None
    s = str(v)
    return None if _EPOCH_ZERO.match(s) else s


def _basename(v):
    if _blank(v):
        return None
    s = str(v)
    return (ntpath.basename(s) if "\\" in s else posixpath.basename(s)) or None


_PARSE_CACHE_KEY = "__car_parsed_payload__"


def _parsed_payload(rec, field):
    """Parse-and-index a payload blob ONCE per (record, field) — the cache lives
    on the record dict, so it persists across the whole map family run over the
    same record (payload() was re-parsing the JSON per field access, the main
    real-data cost). Returns (names_map_or_None, data): names_map indexes an
    EventData.Data list by @Name (values pre-stripped); data is the parsed
    object for the other shapes."""
    cache = rec.get(_PARSE_CACHE_KEY)
    if cache is None:
        cache = {}
        rec[_PARSE_CACHE_KEY] = cache
    raw = rec.get(field)
    hit = cache.get(field)
    if hit is not None and hit[0] is raw:
        # valid only while the raw value is the SAME object — a replaced
        # Payload (or a copied record with a new one) reparses, never stale
        return hit[1], hit[2]
    names, data = None, None
    if not _blank(raw):
        try:
            import json as _json
            data = raw if isinstance(raw, dict) else _json.loads(raw)
            datas = (data.get("EventData") or {}).get("Data") if isinstance(data, dict) else None
            if isinstance(datas, list):
                names = {}
                for d in datas:
                    if isinstance(d, dict) and "@Name" in d:
                        v = d.get("#text")
                        if isinstance(v, str):
                            v = v.strip()      # MS pads values ('Advapi  ')
                        names[d["@Name"]] = None if _blank(v) else v
        except (ValueError, AttributeError, TypeError):
            names, data = None, None
    cache[field] = (raw, names, data)
    return names, data


def _resolve(src, rec):
    """Resolve a plain field name or a (nestable) marker against a record."""
    if isinstance(src, str):
        return rec.get(src)
    kind, arg = src[0], src[1]
    if kind == "first":
        for f in arg:
            v = _resolve(f, rec)
            if not _blank(v):
                return v
        return None
    if kind == "const":
        return arg
    if kind == "basename":
        return _basename(_resolve(arg, rec))
    if kind == "ext":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        e = ntpath.splitext(_basename(v) or "")[1].lstrip(".").lower()
        return e or None
    if kind == "lower":
        v = _resolve(arg, rec)
        return str(v).lower() if not _blank(v) else None
    if kind == "regex1":
        field, pattern = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        m = re.search(pattern, str(v))
        return m.group(1) if m else None
    if kind == "domain_of":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s = str(v)
        if "@" in s:
            s = s.split("@", 1)[1]
        s = s.split("/")[0]                    # strip any URL path
        return s.lower() or None
    if kind == "concat":
        out = []
        for part in arg:
            v = _resolve(part, rec)
            if _blank(v):
                return None
            out.append(str(v))
        return "".join(out)
    if kind == "payload":
        field, key = arg
        names, data = _parsed_payload(rec, field)
        if names is not None:                  # EventData.Data indexed by @Name
            return names.get(key)
        if isinstance(data, dict):             # flat dict (e.g. the wrapped Record)
            v = data.get(key)
            if isinstance(v, str):
                v = v.strip()
            return None if _blank(v) else v
        return None
    if kind == "userdata":
        field, key = arg
        _names, data = _parsed_payload(rec, field)
        if not isinstance(data, dict):
            return None
        try:
            ud = data.get("UserData")
            if not isinstance(ud, dict):
                return None
            for child in ud.values():          # the single nested element
                if isinstance(child, dict) and key in child:
                    v = child[key]
                    if isinstance(v, str):
                        v = v.strip()
                    return None if _blank(v) else v
            return None
        except (ValueError, AttributeError, TypeError):
            return None
    if kind == "host_label":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        return str(v).split(".", 1)[0] or None
    if kind == "epoch_ts":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        try:
            import datetime as _dt
            return _dt.datetime.fromtimestamp(float(v), _dt.timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            s2 = str(v)
            return s2 if s2[:4].isdigit() and "-" in s2 else None  # already ISO
    if kind == "exe_path":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        s2 = str(v).strip()
        if s2.startswith('"'):
            end = s2.find('"', 1)
            return s2[1:end] if end > 0 else s2.strip('"')
        i = s2.lower().find(".exe")
        if i >= 0:
            return s2[:i + 4]
        return s2.split(" ")[0]
    if kind == "map_value":
        field, table, upper = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        s = str(v).upper() if upper else str(v)
        return table.get(s)
    if kind == "unescape_backslashes":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        return str(v).replace("\\\\", "\\")
    if kind == "replace":
        field, old, new = arg
        v = _resolve(field, rec)
        if _blank(v):
            return None
        return str(v).replace(old, new)
    if kind == "at":
        container, idx = arg
        v = _resolve(container, rec)
        if isinstance(v, (list, tuple)) and -len(v) <= idx < len(v):
            e = v[idx]
            if isinstance(e, str):
                e = e.strip()
            return None if _blank(e) else e
        return None
    if kind == "hex_int":
        v = _resolve(arg, rec)
        if _blank(v):
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            try:
                return int(str(v), 16)
            except (TypeError, ValueError):
                return None
    if kind == "ts_before":
        a, b = (parse_ts(_resolve(s, rec)) for s in arg)
        return None if a is None or b is None else a < b
    raise ValueError(f"unknown source marker: {src!r}")


def _guid(spec, obj, rec):
    """The event's CAR guid: an existing field, a marker, `<object>-<fields>`, or
    None (assigned later / genuinely absent). A None component voids a
    fields-guid; "" is a legitimate identity value. The `spindle` form (a
    minted, deterministic identity) is _spindle."""
    if spec is None or spec.get("none"):
        return None
    if "marker" in spec:
        return _resolve(spec["marker"], rec)
    if "field" in spec:
        v = rec.get(spec["field"])
        return None if _blank(v) else v
    parts = [rec.get(f) for f in spec["fields"]]
    if any(p is None for p in parts):
        return None
    return f"{obj}-" + "-".join(str(p) for p in parts)


def _lookup(event, path):
    """A value off the normalized event by path — native.<key>, else a CAR /
    header field: the path convention relationships.yml `derived` uses."""
    if path.startswith("native."):
        return (event.get("_native") or {}).get(path[len("native."):])
    return event.get(path)


def _spindle(name, obj, rec, event):
    """The spindle guid form — {"spindle": "<registry entry>"} — minted the
    way stix.py mints §2.9 ids: uuid5(SPINDLE_NS, canonical_json({"_obj": obj,
    name: value, ...})) over the record's OWN stable-identity values, keyed by
    name (ids.py). WHICH values is a rule, not code: spindle.yml declares each
    entry's identity as paths on the normalized event, so a map never spells
    fields and the registry cannot drift from the code (spindle.verify_registry).
    The source / parser / artefact name is never hashed, so two tools parsing
    the same artefact converge on one guid. A blank component voids the
    intrinsic identity and the row falls back to its POSITIONAL one — the
    registry's per-record index fields on the raw wrapped row (the l2t
    container + RecordId) — flagged positional, because that identity holds
    only inside this source (never equated across sources). Every minted row
    also carries its PROVENANCE — spindle_ref, the container + record index
    the row came from — OUTSIDE the key: an intrinsic guid never depends on
    it, and the fold lists it per contributor. Returns (guid, native extras):
    the readable key (spindle_key), its scope (spindle_scope: intrinsic |
    positional) and the provenance (spindle_ref)."""
    entry = spindle.entry(name)
    if entry.get("object") != obj:
        raise ValueError(f"spindle identity {name!r} is declared for {entry.get('object')!r}, not {obj!r}")
    ref = {f: rec.get(f) for f in spindle.positional()}
    identity, modes = {}, {}
    for ident_name, source, mode in spindle.identity_fields(entry):
        v = _lookup(event, source)
        if _blank(v):
            identity = None
            break
        identity[ident_name] = v
        if mode is not None:
            modes[ident_name] = mode
    if identity:
        guid, key = ids.mint(obj, identity, entry["version"], modes)
        return guid, {spindle.NATIVE_KEY: key, spindle.NATIVE_SCOPE: spindle.INTRINSIC,
                      spindle.NATIVE_REF: ref}
    positional = {}
    for f in spindle.positional():
        v = rec.get(f)
        if _blank(v):
            return None, {}            # no per-record index either: genuinely absent
        positional[f] = v
    if not positional:
        return None, {}
    guid, key = ids.mint(obj, positional, spindle.positional_version())
    return guid, {spindle.NATIVE_KEY: key, spindle.NATIVE_SCOPE: spindle.POSITIONAL,
                  spindle.NATIVE_REF: ref}


def _identity(spec, obj, rec, event):
    """(guid, native extras) for a map's guid spec: the spindle form mints and
    describes its identity; every other form is _guid, with nothing to add."""
    if spec and "spindle" in spec:
        return _spindle(spec["spindle"], obj, rec, event)
    return _guid(spec, obj, rec), {}


def _select(entry, rec):
    """The map for a record: the first matching variant, else the default/self."""
    from . import mappings  # deferred: mappings imports this module's markers
    if "variants" not in entry:
        return entry
    for pred_name, sub in entry["variants"]:
        if mappings.PREDICATES[pred_name](rec):
            return sub
    return entry.get("default")


def normalize(artefact: str, rec: dict) -> dict | None:
    """One raw record -> one CAR event, or None if unmapped."""
    from . import mappings  # deferred: mappings imports this module's markers
    entry = mappings.MAPPINGS.get(artefact)
    if entry is None:
        return None
    m = _select(entry, rec)
    if m is None:
        return None
    obj = m["object"]
    action = _resolve(m["action"], rec) if not isinstance(m["action"], str) else m["action"]
    if action is None:
        # a matched variant whose action marker resolves to nothing (e.g. an
        # HTTP method outside CAR's get/post/put/tunnel) is NOT a CAR event —
        # the row stays raw, never an action-less phantom.
        return None
    props = {car: _resolve(sp, rec) for car, sp in m["props"].items()}
    event = {
        "car_object": obj,
        "car_action": action,
        "timestamp": None if m.get("ts") is None else _clean_ts(_resolve(m["ts"], rec)),
        # the row identity — filled LAST (below): a spindle id is minted from
        # the event's own canonical values, which have to be in place first
        "guid": None,
        # process-context links, resolved by enrich (docs: car-store §3 logic).
        # An artefact that natively carries the owning process's GUID (Sysmon's
        # ProcessGuid) links DEFINITIVELY; a bare PID gets the create-time-window
        # heuristic join.
        "owning_pid": _resolve(m["owning_pid"], rec) if m.get("owning_pid") else None,
        "owning_guid_native": _resolve(m["owning_guid"], rec) if m.get("owning_guid") else None,
        "parent_pid": _resolve(m["parent_pid"], rec) if m.get("parent_pid") else None,
        "owning_guid": None,
        "parent_guid": None,
        "link_confidence": None,
        "source_artefact": artefact,
        # the enrich scope key: a map may derive it per record (e.g. Computer);
        # the pipeline fills a caller-supplied default where the map does not.
        "source_host": _resolve(m["host"], rec) if m.get("host") else None,
        "_native": {k: rec.get(k) for k in m.get("keep", []) if k in rec},
    }
    # parsed values promoted into _native (join keys the raw blob buries —
    # e.g. an EvtxECmd payload's TargetLogonId); never CAR-canonical columns.
    for name, spec in (m.get("native_extract") or {}).items():
        v = _resolve(spec, rec)
        if v is not None:
            event["_native"][name] = v
    event.update(props)
    # the identity: an existing field / marker / <object>-<fields>, or a MINTED
    # spindle id over the event's own values (the registry names them by path);
    # a minted guid is opaque, so its readable tuple + scope ride native
    event["guid"], identity_native = _identity(m.get("guid"), obj, rec, event)
    event["_native"].update(identity_native)
    return event
