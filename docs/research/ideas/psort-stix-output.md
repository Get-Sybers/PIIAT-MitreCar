# Research: Plaso `psort` → STIX Output Module

## Overview

This document investigates what would be required to develop a new plaso `psort` output module that serialises timeline events into [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) (Structured Threat Information Expression) bundles. The goal is to identify the exact code artefacts, STIX objects, library dependencies, and integration points needed, with all referenced information linked to its source.

---

## 1. Plaso Output Module Architecture

### 1.1 How Output Modules Work

Plaso's `psort` tool processes a `.plaso` storage file and routes each event through an **output module** chosen at runtime via the `--output_format` flag. The pipeline is:

```
psort → OutputMediator → OutputModule.GetFieldValues() → OutputModule.WriteFieldValues()
```

The full pipeline is documented at:  
<https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html>

### 1.2 Base Class: `OutputModule`

All output modules inherit from `OutputModule` defined in [`plaso/output/interface.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/interface.py).

Key abstract methods that every output module **must** implement:

| Method | Signature | Purpose |
|--------|-----------|---------|
| `GetFieldValues` | `(self, output_mediator, event, event_data, event_data_stream, event_tag)` | Extracts structured data from a plaso event and returns a `dict[str, str]` |
| `WriteFieldValues` | `(self, output_mediator, field_values)` | Consumes the dict returned by `GetFieldValues` and writes to the output |

Optional lifecycle hooks:

| Method | Purpose |
|--------|---------|
| `WriteHeader(output_mediator)` | Called once before the first event (e.g. open file, write preamble) |
| `WriteFooter()` | Called once after the last event (e.g. flush buffer, close file) |
| `Open(**kwargs)` | Opens the backing output resource |
| `Close()` | Closes the backing output resource |
| `WriteFieldValuesOfMACBGroup(output_mediator, macb_group)` | Default implementation loops over the MACB group calling `GetFieldValues` + `WriteFieldValues` per entry; can be overridden for bulk handling |

Class-level attributes that control behaviour:

```python
NAME = ""                        # Unique string identifier used with --output_format
DESCRIPTION = ""                 # Human-readable description shown in --help
SUPPORTS_ADDITIONAL_FIELDS = False
SUPPORTS_CUSTOM_FIELDS = False
WRITES_OUTPUT_FILE = True        # Set True when the module writes to a file path
```

Source: [`plaso/output/interface.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/interface.py)

### 1.3 File-Writing Base Class: `TextFileOutputModule`

Modules that write to a single output file should extend [`TextFileOutputModule`](https://github.com/log2timeline/plaso/blob/main/plaso/output/text_file.py) which provides:

- `Open(path=None, **kwargs)` — opens a UTF-8 text file at `path` (raises `OSError` if the file already exists)
- `Close()` — closes the file object
- `WriteLine(text)` / `WriteText(text)` — helpers that write to the open file

Source: [`plaso/output/text_file.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/text_file.py)

### 1.4 Registration Mechanism

At the bottom of each output module file, the class is registered with:

```python
manager.OutputManager.RegisterOutput(MyOutputModule)
```

`OutputManager` stores modules in a dict keyed by `NAME.lower()`.  
Source: [`plaso/output/manager.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/manager.py)

### 1.5 Module Discovery via `__init__.py`

`plaso/output/__init__.py` explicitly imports every output module so that the `RegisterOutput` call at module load time populates the manager:

```python
# plaso/output/__init__.py (current state)
from plaso.output import dynamic
from plaso.output import json_line
from plaso.output import json_out
from plaso.output import kml
from plaso.output import l2t_csv
# … etc.
```

Any new module **must** be added here.  
Source: [`plaso/output/__init__.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/__init__.py)

### 1.6 Existing Module Examples

Two closely analogous modules to study as templates:

| Module | File | Description |
|--------|------|-------------|
| `json` | [`plaso/output/json_out.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/json_out.py) | One JSON object per event, wrapped in a top-level `{}` |
| `json_line` | [`plaso/output/json_line.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/json_line.py) | One JSON object per line (NDJSON); simplest possible module |

Both extend `SharedJSONOutputModule` which handles the heavy lifting of field extraction.  
Source: [`plaso/output/shared_json.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/shared_json.py)

### 1.7 Event Data Available to Output Modules

Each call to `GetFieldValues` receives:

| Parameter | Type | Notable attributes |
|-----------|------|--------------------|
| `output_mediator` | `OutputMediator` | timezone, `use_fallback_path_spec`, formatter access |
| `event` | `EventObject` | `timestamp` (microseconds since epoch), `date_time`, `timestamp_desc`, `GetAttributes()` |
| `event_data` | `EventData` | `data_type` (e.g. `"fs:stat"`, `"windows:registry:key_value"`), `_parser_chain`, all parsed attributes |
| `event_data_stream` | `EventDataStream` | `path_spec` (dfVFS path) |
| `event_tag` | `EventTag` | analyst labels (may be `None`) |

`event.timestamp` is a Unix microsecond integer; ISO 8601 formatting logic lives in  
[`plaso/output/formatting_helper.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/formatting_helper.py) (`_FormatDateTime`).

The `OutputMediator` provides several helper methods useful for STIX field population:

| Method | Returns |
|--------|---------|
| `GetHostname(event_data)` | `str` — hostname associated with the event |
| `GetUsername(event_data)` | `str` — username associated with the event |
| `GetMACBRepresentation(event, event_data)` | `str` — MACB string (`"M..."`) |
| `GetMessageFormatter(data_type)` | Message formatter for human-readable description |
| `GetDisplayNameForPathSpec(path_spec)` | Human-readable path string |
| `time_zone` | pytz timezone object |
| `dynamic_time` | `bool` — whether to use dfdatetime |

Source: [`plaso/output/mediator.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/mediator.py)

### 1.8 How psort.py Uses Output Modules (End-to-End Flow)

`psort` calls output module methods in this exact lifecycle sequence:

```
psort --output_format stix --write out.json timeline.plaso
       │
       ▼
PsortTool._CreateOutputModule("stix")
  └─ OutputManager.NewOutputModule("stix") → STIXOutputModule()
  └─ output_module.Open(path="out.json")          # if WRITES_OUTPUT_FILE=True
       │
       ▼
OutputAndFormattingMultiProcessEngine.ExportEvents(...)
  ├─ output_module.WriteHeader(output_mediator)   # before first event
  │
  ├─ for each event (sorted by timestamp):
  │    ├─ GetFieldValues(mediator, event, ...)
  │    └─ WriteFieldValues(mediator, field_values)
  │         (or WriteFieldValuesOfMACBGroup for identical-timestamp groups)
  │
  └─ output_module.WriteFooter()                  # after last event
       │
       ▼
PsortTool: output_module.Close()
```

Sources:
- [`plaso/cli/psort_tool.py`](https://github.com/log2timeline/plaso/blob/main/plaso/cli/psort_tool.py) lines 500–562
- [`plaso/multi_process/output_engine.py`](https://github.com/log2timeline/plaso/blob/main/plaso/multi_process/output_engine.py) lines 617–644
- [`plaso/cli/tool_options.py`](https://github.com/log2timeline/plaso/blob/main/plaso/cli/tool_options.py) lines 120–165

---

## 2. STIX 2.1 Objects Relevant to Plaso Events

STIX 2.1 specification: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>

### 2.1 Primary Container: `Bundle`

All STIX content is shipped in a `Bundle` object. The output module should accumulate STIX objects and serialise them as a single Bundle at `WriteFooter` time.

```json
{
  "type": "bundle",
  "id": "bundle--<uuid4>",
  "objects": [ … ]
}
```

Spec: [§7.1 Bundle](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gms872kuzdmg)

### 2.2 `observed-data` (STIX Domain Object)

**This is the primary STIX type that maps to a plaso event.** An `observed-data` object captures one or more observations of real-world phenomena at a specific time window.

Required properties:

| Property | Type | Mapping to plaso |
|----------|------|-----------------|
| `first_observed` | timestamp | `event.timestamp` (converted from µs) |
| `last_observed` | timestamp | `event.timestamp` (same as first for single events; for MACB groups: timestamp of the last event in the group) |
| `number_observed` | integer ≥ 1 | `1` per event, or `len(macb_group)` when using `WriteFieldValuesOfMACBGroup` |
| `object_refs` | list of SCO refs | References to the Cyber Observable Objects below |
| `created_by_ref` | identity ref | Should reference the plaso `identity` object |

> **⚠️ Important:** In STIX 2.1 the `objects` embedded dict property of `observed-data` is **deprecated**. Only `object_refs` (a list of SCO IDs) should be used.  
> Source: [`stix2/v21/sdo.py`](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sdo.py) lines 621–627

Spec: [§7.7 Observed Data](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc)

### 2.3 STIX Cyber Observable Objects (SCOs) by Plaso Data Type

A plaso event's `event_data.data_type` determines which SCO(s) to create:

| Plaso `data_type` prefix | STIX SCO | Key STIX properties populated |
|--------------------------|----------|-------------------------------|
| `fs:stat` | [`file`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_99bl2dibcztv) | `name`, `size`, `hashes`, `ctime`, `mtime`, `atime`, `parent_directory_ref` |
| `fs:stat:ntfs` | `file` + [`windows-pebinary-ext`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gg5zibdavb24) or `ntfs-ext` | File attributes specific to NTFS |
| `windows:registry:key_value` | [`windows-registry-key`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y) | `key`, `values` (name/data/type tuples), `modified_time` |
| `windows:evt:record` / `windows:evtx:record` | [`process`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hpzl52rggcu5) or custom extension | Event ID, provider, message as custom properties |
| `bash:history` / `linux:syslog` / generic shell | `process` | `command_line`, `pid`, `created_time` |
| `chrome:history:file_downloaded` / browser history | [`url`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0) + `file` | `value` (URL string), `display_name` |
| `linux:utmp:event` / `windows:evtx:logon` | [`user-account`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2) | `user_id`, `account_login`, `account_type` |
| `syslog:ssh:login` / network logs | [`network-traffic`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy) + `ipv4-addr` or `ipv6-addr` | `src_ref`, `dst_ref`, `dst_port`, `protocols` |
| All others | [`x-plaso-event`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_4y7n6o2pgmgr) (custom SCO) | Fallback: serialise full `event_data` as a custom object |

SCO specification index: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_65bj30y3brs>

### 2.4 `identity` Object (Recommended)

An `identity` object identifying the tool that produced the data should be included once per bundle:

```json
{
  "type": "identity",
  "id": "identity--<deterministic-uuid>",
  "name": "plaso",
  "identity_class": "system",
  "description": "Log2Timeline plaso digital forensics tool"
}
```

Each `observed-data` object should set `created_by_ref` to this identity's ID.  
Spec: [§7.5 Identity](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp)

### 2.5 Custom Object: `x-plaso-event` (Fallback SCO)

For `data_type` values that do not map to a standard SCO, a custom STIX Cyber Observable Object is required. Custom SCO types must be prefixed with `x-` per the STIX 2.1 spec.

```json
{
  "type": "x-plaso-event",
  "id": "x-plaso-event--<uuid5>",
  "spec_version": "2.1",
  "data_type": "windows:prefetch:execution",
  "timestamp": "2024-01-15T08:22:10.000000Z",
  "parser": "winprefetch",
  "attributes": { … all event_data attributes … }
}
```

Spec for custom objects: [§11.2 Custom Objects](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p8al1nodeul4)  
stix2 Python library custom object docs: <https://github.com/oasis-open/cti-python-stix2/blob/master/docs/guide/custom.rst>

### 2.6 `note` Object (Optional — for Event Tags)

Plaso events may have an `EventTag` with analyst-applied labels. These can be represented as STIX `Note` objects, each referencing the `observed-data` object they annotate:

```json
{
  "type": "note",
  "id": "note--<uuid4>",
  "created_by_ref": "identity--<plaso>",
  "abstract": "analyst:suspicious",
  "object_refs": ["observed-data--<uuid>"]
}
```

Spec: [§7.13 Note](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9)

### 2.7 `sighting` Object (Optional — for Threat Intel Enrichment)

If the output is later used to match against known threat indicators, `Sighting` objects link `ObservedData` to `Indicator` objects from a threat intel feed. This is out of scope for the base output module but worth noting for future enrichment.

Spec: [§8.3 Sighting](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a795guqsap3r)

---

## 3. The `stix2` Python Library

The OASIS-maintained `stix2` library provides Python classes for all STIX 2.1 types and handles serialisation, deterministic ID generation, and validation.

Repository: <https://github.com/oasis-open/cti-python-stix2>  
PyPI: <https://pypi.org/project/stix2/>

### 3.1 Key Classes

```python
import stix2

# Identity (created once per bundle)
identity = stix2.Identity(name="plaso", identity_class="system")

# File SCO
file_obj = stix2.File(name="malware.exe", size=45056,
                      hashes={"MD5": "abc123"})

# ObservedData wrapping the SCO
obs = stix2.ObservedData(
    created_by_ref=identity,
    first_observed="2024-01-15T08:22:10Z",
    last_observed="2024-01-15T08:22:10Z",
    number_observed=1,
    object_refs=[file_obj]
)

# Bundle with all objects
bundle = stix2.Bundle(identity, file_obj, obs)
print(bundle.serialize(pretty=True))
```

### 3.2 Deterministic UUIDs (UUID5)

STIX 2.1 requires SCOs to use deterministic IDs where possible. The `stix2` library computes these automatically from "ID contributing properties" (e.g. `File.name + File.hashes`). Custom objects must implement this manually using `uuid.uuid5()`.  
Spec: [§2.9 Deterministic ID Generation](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c)

### 3.3 Custom SCO Registration

```python
from stix2 import CustomObservable
from stix2.properties import StringProperty, TimestampProperty, DictionaryProperty

@CustomObservable(
    "x-plaso-event",
    [
        ("data_type", StringProperty(required=True)),
        ("timestamp", TimestampProperty(required=True)),
        ("parser", StringProperty()),
        ("attributes", DictionaryProperty()),
    ]
)
class PlasoEvent:
    pass
```

---

## 4. What Would Need to Be Built

### 4.1 New File: `plaso/output/stix_out.py`

This is the main deliverable. Its structure would be:

```python
"""Output module that saves plaso events as a STIX 2.1 Bundle."""

import json
import stix2

from plaso.output import interface
from plaso.output import manager
from plaso.output import text_file


# --- Custom SCO for unmapped event types ---
@stix2.CustomObservable("x-plaso-event", [...])
class PlasoEventObservable:
    pass


# --- Mapper: EventData → SCO(s) ---
class _STIXObjectMapper:
    """Maps plaso event data to STIX Cyber Observable Objects."""

    def GetSCOs(self, event, event_data, event_data_stream):
        data_type = getattr(event_data, "data_type", "") or ""
        if data_type.startswith("fs:stat"):
            return self._MapFileEvent(event_data, event_data_stream)
        elif data_type.startswith("windows:registry"):
            return self._MapRegistryEvent(event_data)
        # … additional mappings …
        else:
            return self._MapGenericEvent(event, event_data)

    def _MapFileEvent(self, event_data, event_data_stream): ...
    def _MapRegistryEvent(self, event_data): ...
    def _MapGenericEvent(self, event, event_data): ...


# --- Output Module ---
class STIXOutputModule(text_file.TextFileOutputModule):
    """Output module for STIX 2.1 Bundle format."""

    NAME = "stix"
    DESCRIPTION = "Saves the events into a STIX 2.1 Bundle JSON file."

    def __init__(self):
        super().__init__()
        self._stix_objects = []
        self._identity = stix2.Identity(name="plaso", identity_class="system")
        self._mapper = _STIXObjectMapper()
        self._stix_objects.append(self._identity)

    def GetFieldValues(self, output_mediator, event, event_data,
                       event_data_stream, event_tag):
        timestamp_us = event.timestamp
        iso_ts = _microseconds_to_iso8601(timestamp_us)
        scos = self._mapper.GetSCOs(event, event_data, event_data_stream)
        obs = stix2.ObservedData(
            created_by_ref=self._identity,
            first_observed=iso_ts,
            last_observed=iso_ts,
            number_observed=1,
            object_refs=scos,
        )
        return {"scos": scos, "observed_data": obs}

    def WriteFieldValues(self, output_mediator, field_values):
        self._stix_objects.extend(field_values["scos"])
        self._stix_objects.append(field_values["observed_data"])

    def WriteFooter(self):
        bundle = stix2.Bundle(*self._stix_objects)
        self.WriteText(bundle.serialize(pretty=True))


manager.OutputManager.RegisterOutput(STIXOutputModule)
```

### 4.2 Modification: `plaso/output/__init__.py`

Add a single import line:

```python
from plaso.output import stix_out
```

Source to modify: [`plaso/output/__init__.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/__init__.py)

### 4.3 New Dependency: `stix2`

The `stix2` package must be added to plaso's dependency manifest. Plaso uses `setup.cfg` or `pyproject.toml` to declare dependencies.

```toml
# pyproject.toml (or setup.cfg [options] install_requires)
stix2 >= 3.0.0
```

PyPI: <https://pypi.org/project/stix2/>  
`stix2` itself depends on `stix2-patterns` (for pattern validation) and `requests`.

If the dependency cannot be guaranteed (e.g. optional feature), the module can use a try/import guard and register as **disabled** if the import fails — the same pattern used by the OpenSearch module:

```python
try:
    import stix2
except ImportError:
    stix2 = None

if stix2:
    manager.OutputManager.RegisterOutput(STIXOutputModule)
else:
    manager.OutputManager.RegisterOutput(STIXOutputModule, disabled=True)
```

Source reference for disabled registration: [`plaso/output/manager.py` — `RegisterOutput(disabled=True)`](https://github.com/log2timeline/plaso/blob/main/plaso/output/manager.py)

### 4.4 New Test File: `tests/output/stix_out_test.py`

Following plaso's existing test convention (see [`tests/output/json_out_test.py`](https://github.com/log2timeline/plaso/blob/main/tests/output/json_out_test.py)):

- Unit tests for `_STIXObjectMapper` with synthetic `EventData` objects
- Integration test that runs `STIXOutputModule` over a small set of test events and validates the output is a parseable STIX Bundle with `stix2.parse()`
- Tests for each data type branch: file events, registry events, generic fallback

---

## 5. Data Mapping Challenges and Design Decisions

### 5.1 Timestamp Conversion

Plaso stores timestamps as **microseconds since the Unix epoch** (signed integer). STIX timestamps must be RFC 3339 strings in UTC.

The preferred approach uses the `dfdatetime` library that is already a plaso dependency — the same approach used in `formatting_helper.py`:

```python
from dfdatetime import posix_time as dfdatetime_posix_time

def _microseconds_to_iso8601(timestamp_us: int) -> str:
    date_time = dfdatetime_posix_time.PosixTimeInMicroseconds(
        timestamp=timestamp_us
    )
    return date_time.CopyToDateTimeStringISO8601()
```

Source: [`plaso/output/formatting_helper.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/formatting_helper.py) lines 80–97

As a pure-stdlib fallback:

```python
import datetime

def _microseconds_to_iso8601(timestamp_us: int) -> str:
    dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) \
         + datetime.timedelta(microseconds=timestamp_us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
```

Edge cases: `timestamp_us = 0` (unknown time — should output `None` or skip), negative timestamps (pre-epoch). Note: while STIX 2.1 imposes no lower bound on timestamp values in its specification, the `stix2` Python library's `TimestampProperty` may have its own constraints — these should be verified against the installed library version when handling pre-1970 timestamps.

### 5.2 SCO Deduplication

Multiple plaso events may reference the same file (e.g. `mtime` and `atime` events from `fs:stat`). The module should deduplicate SCOs by their deterministic STIX ID to avoid duplicate objects in the bundle. A `dict` keyed on SCO `id` is the recommended approach.

### 5.3 Memory Usage for Large Timelines

Accumulating all SCOs and `observed-data` objects in memory until `WriteFooter` is called will cause memory pressure for large storage files. Mitigation options:

1. **Streaming NDJSON**: Emit one `observed-data` Bundle per line (similar to `json_line`). This breaks STIX Bundle semantics but is more scalable.
2. **Batched bundles**: Write a new Bundle every N events.
3. **External sort + merge**: Write objects to a temp file, deduplicate, then write the final Bundle.

For a first implementation, in-memory accumulation is simplest and acceptable for small-to-medium timelines.

### 5.4 MACB Group Handling

The plaso output engine groups events with identical timestamps into a MACB group and calls `WriteFieldValuesOfMACBGroup()`. The default implementation loops over members calling `GetFieldValues` + `WriteFieldValues` per entry. For STIX, overriding this is beneficial:

- Create one `observed-data` with `first_observed` = earliest timestamp, `last_observed` = latest timestamp, `number_observed` = len(group)
- Reference all distinct SCOs from the group in `object_refs`
- This better models the STIX semantics of an observation window

Source: [`plaso/output/interface.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/interface.py) — `WriteFieldValuesOfMACBGroup()`  
Example reference: [`plaso/output/l2t_csv.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/l2t_csv.py) — shows MACB group handling

### 5.5 STIX Pattern Language (Optional Enhancement)

If the goal is threat-intel sharing rather than just data export, `observed-data` objects alone are insufficient — analysts want `indicator` objects with STIX patterns. This would require post-processing: grouping `observed-data` by indicator logic and generating `Indicator` objects. This is out of scope for the basic output module but is a natural next step.

Spec: [§7.8 Indicator](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v)

---

## 6. Summary of Required Artefacts

| Artefact | Type | Action |
|----------|------|--------|
| `plaso/output/stix_out.py` | New file | Create output module with `STIXOutputModule` and `_STIXObjectMapper` |
| `plaso/output/__init__.py` | Existing file | Add `from plaso.output import stix_out` |
| `stix2 >= 3.0.0` | New dependency | Add to `setup.cfg` / `pyproject.toml` install_requires |
| `tests/output/stix_out_test.py` | New file | Unit + integration tests |
| `x-plaso-event` custom SCO | STIX object type | Defined within `stix_out.py` using `@stix2.CustomObservable` |
| `observed-data` | STIX SDO | One per plaso event (or MACB group), referencing SCO(s) via `object_refs` |
| `identity` | STIX SDO | One per bundle, identifying "plaso" as the producer; created in `__init__()` and added to `self._stix_objects` in `WriteHeader()` |
| `note` | STIX SDO | One per event with a non-empty `EventTag`, referencing the `observed-data` |

---

## 7. References

| Source | URL |
|--------|-----|
| Plaso output and formatting documentation | <https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html> |
| `plaso/output/interface.py` — `OutputModule` base class | <https://github.com/log2timeline/plaso/blob/main/plaso/output/interface.py> |
| `plaso/output/text_file.py` — `TextFileOutputModule` | <https://github.com/log2timeline/plaso/blob/main/plaso/output/text_file.py> |
| `plaso/output/manager.py` — `OutputManager` | <https://github.com/log2timeline/plaso/blob/main/plaso/output/manager.py> |
| `plaso/output/__init__.py` — module discovery | <https://github.com/log2timeline/plaso/blob/main/plaso/output/__init__.py> |
| `plaso/output/json_out.py` — JSON module example | <https://github.com/log2timeline/plaso/blob/main/plaso/output/json_out.py> |
| `plaso/output/json_line.py` — JSON line module example | <https://github.com/log2timeline/plaso/blob/main/plaso/output/json_line.py> |
| `plaso/output/shared_json.py` — shared JSON field extraction | <https://github.com/log2timeline/plaso/blob/main/plaso/output/shared_json.py> |
| `plaso/output/formatting_helper.py` — timestamp formatting | <https://github.com/log2timeline/plaso/blob/main/plaso/output/formatting_helper.py> |
| STIX 2.1 specification (OASIS) | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html> |
| STIX 2.1 — Bundle object | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gms872kuzdmg> |
| STIX 2.1 — Observed Data object | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc> |
| STIX 2.1 — Identity object | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp> |
| STIX 2.1 — Indicator object | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v> |
| STIX 2.1 — File SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_99bl2dibcztv> |
| STIX 2.1 — Windows Registry Key SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y> |
| STIX 2.1 — Process SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hpzl52rggcu5> |
| STIX 2.1 — User Account SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2> |
| STIX 2.1 — Network Traffic SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy> |
| STIX 2.1 — URL SCO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0> |
| STIX 2.1 — Custom objects | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p8al1nodeul4> |
| STIX 2.1 — Deterministic ID generation | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c> |
| STIX 2.1 — SCO index | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_65bj30y3brs> |
| `stix2` Python library — GitHub | <https://github.com/oasis-open/cti-python-stix2> |
| `stix2` Python library — PyPI | <https://pypi.org/project/stix2/> |
| `stix2` custom objects guide | <https://github.com/oasis-open/cti-python-stix2/blob/master/docs/guide/custom.rst> |
| `stix2/v21/sdo.py` — SDO classes source | <https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/sdo.py> |
| STIX 2.1 — Note object | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9> |
| STIX 2.1 — Sighting SRO | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a795guqsap3r> |
| `plaso/output/mediator.py` — OutputMediator | <https://github.com/log2timeline/plaso/blob/main/plaso/output/mediator.py> |
| `plaso/cli/psort_tool.py` — psort entry point | <https://github.com/log2timeline/plaso/blob/main/plaso/cli/psort_tool.py> |
| `plaso/multi_process/output_engine.py` — engine lifecycle | <https://github.com/log2timeline/plaso/blob/main/plaso/multi_process/output_engine.py> |
| `plaso/cli/tool_options.py` — output module creation | <https://github.com/log2timeline/plaso/blob/main/plaso/cli/tool_options.py> |
| `plaso/output/l2t_csv.py` — MACB group example | <https://github.com/log2timeline/plaso/blob/main/plaso/output/l2t_csv.py> |
| `plaso/output/null.py` — minimal module example | <https://github.com/log2timeline/plaso/blob/main/plaso/output/null.py> |
| `plaso/parsers/filestat.py` — `FileStatEventData` fields | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/filestat.py> |
| `plaso/parsers/winevt.py` — `WinEvtRecordEventData` fields | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winevt.py> |
| `plaso/parsers/winevtx.py` — `WinEvtxRecordEventData` fields | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winevtx.py> |
| `plaso/parsers/utmp.py` — `UtmpEventData` fields | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/utmp.py> |
| `plaso/parsers/winreg_plugins/appcompatcache.py` — `AppCompatCacheEventData` | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/appcompatcache.py> |
| `plaso/parsers/winreg_plugins/services.py` — `WindowsRegistryServiceEventData` | <https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/services.py> |
| `plaso/containers/events.py` — `EventData` base class | <https://github.com/log2timeline/plaso/blob/main/plaso/containers/events.py> |
| `plaso/output/opensearch.py` — disabled-module import-guard pattern | <https://github.com/log2timeline/plaso/blob/main/plaso/output/opensearch.py> |
| `plaso/output/shared_opensearch.py` — `FieldFormattingHelper` pattern | <https://github.com/log2timeline/plaso/blob/main/plaso/output/shared_opensearch.py> |
| STIX 2.1 — Unix File Extension | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s6glnbcq0scf> |
| STIX 2.1 — Windows Service Extension | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lkeg38ajjlv5> |
| STIX 2.1 — Windows Registry Value Type | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_msopxnhtqrbd> |
| STIX 2.1 — Data Markings (TLP) | <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hn8byemkezp6> |

---

## 8. Concrete Parser-to-STIX Field Mappings

This section provides exact field-by-field mappings from plaso's parser `EventData` classes to STIX SCO properties, using the real attribute names from the parser source files.

### 8.1 `fs:stat` → `file` SCO

Source: [`plaso/parsers/filestat.py` — `FileStatEventData`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/filestat.py)

| `FileStatEventData` attribute | STIX `file` property | Notes |
|-------------------------------|---------------------|-------|
| `filename` | `name` | Basename; full path context stored in `observed-data` labels |
| `file_size` | `size` | Integer bytes |
| `creation_time` | `ctime` | `dfdatetime.DateTimeValues` → ISO 8601 via `.CopyToDateTimeStringISO8601()` |
| `modification_time` | `mtime` | `dfdatetime.DateTimeValues` → ISO 8601 |
| `access_time` | `atime` | `dfdatetime.DateTimeValues` → ISO 8601 |
| `change_time` | — | Not in STIX `file`; add as `x_change_time` custom property |
| `inode` | `unix-file-ext.inode` | Requires the `unix-file-ext` extension |
| `mode` | `unix-file-ext.mode` | Octal access mode string e.g. `"0755"` |
| `owner_identifier` | `unix-file-ext.uid` | Owner UID as string |
| `group_identifier` | `unix-file-ext.gid` | Group GID as string |
| `number_of_links` | — | Not a standard STIX property; omit or store as custom |
| `file_system_type` | — | Store as `x_file_system_type` custom property on `observed-data` |
| `display_name` | — | Use for `observed-data` labels |
| `is_allocated` | — | Store as `x_is_allocated` custom property |
| `attribute_names` | — | NTFS alternate data stream names; omit in initial implementation |

Unix file extension spec: [STIX 2.1 §4.20 — Unix File Extension](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s6glnbcq0scf)

**Concrete mapping code:**

```python
def _MapFileStat(event, event_data, event_data_stream):
    """Maps FileStatEventData to a STIX File SCO."""
    kwargs = {}

    name = getattr(event_data, "filename", None)
    if name:
        # Use basename for 'name'
        kwargs["name"] = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or name

    size = getattr(event_data, "file_size", None)
    if size is not None:
        kwargs["size"] = size

    # Timestamps: dfdatetime objects → ISO 8601
    for plaso_attr, stix_prop in [
        ("creation_time", "ctime"),
        ("modification_time", "mtime"),
        ("access_time", "atime"),
    ]:
        dt_val = getattr(event_data, plaso_attr, None)
        if dt_val:
            iso = dt_val.CopyToDateTimeStringISO8601()
            if iso:
                kwargs[stix_prop] = iso

    # Unix file extension
    unix_ext = {}
    inode = getattr(event_data, "inode", None)
    if inode is not None:
        unix_ext["inode"] = inode
    mode = getattr(event_data, "mode", None)
    if mode is not None:
        unix_ext["mode"] = oct(mode)[2:]  # e.g. "644"
    uid = getattr(event_data, "owner_identifier", None)
    if uid is not None:
        unix_ext["uid"] = str(uid)
    gid = getattr(event_data, "group_identifier", None)
    if gid is not None:
        unix_ext["gid"] = str(gid)

    if unix_ext:
        kwargs["extensions"] = {"unix-file-ext": unix_ext}

    return stix2.File(**kwargs) if kwargs.get("name") else None
```

### 8.2 `windows:registry:*` → `windows-registry-key` SCO

Sources:
- [`plaso/parsers/winreg_plugins/appcompatcache.py`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/appcompatcache.py)
- [`plaso/parsers/winreg_plugins/services.py`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/services.py)

All Windows Registry `EventData` subclasses share a `key_path` attribute. The standard STIX `windows-registry-key` SCO maps cleanly:

| `EventData` attribute | STIX `windows-registry-key` property | Notes |
|----------------------|--------------------------------------|-------|
| `key_path` | `key` | Full Registry key path e.g. `HKEY_LOCAL_MACHINE\...` |
| `last_written_time` / `registry_last_written_time` | `modified_time` | `dfdatetime.DateTimeValues` → ISO 8601 |
| `values` (list of tuples: name, type, data) | `values` | List of `WindowsRegistryValueType` objects |

The `WindowsRegistryValueType` embedded object requires name, data_type, and data:

```python
from stix2.v21.observables import WindowsRegistryValueType

def _BuildRegistryValues(values_list):
    """Converts plaso registry values list to STIX WindowsRegistryValueType list."""
    # plaso stores: list[tuple[name: str, data_type: str, data: str|bytes]]
    result = []
    for item in (values_list or []):
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            name, dtype, data = item[0], item[1], item[2]
            if isinstance(data, bytes):
                data = data.hex()
            result.append(WindowsRegistryValueType(
                name=name or "(Default)",
                data_type=dtype or "REG_SZ",
                data=str(data) if data is not None else "",
            ))
    return result
```

Windows Registry value type vocab: [STIX 2.1 §4.26.3](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_msopxnhtqrbd)

**AppCompatCache-specific enrichment:** When `data_type == "windows:registry:appcompatcache"`, the `path` attribute contains the full executable path — additionally create a `file` SCO and a `related-to` relationship:

```python
if hasattr(event_data, "path") and event_data.path:
    exec_file = stix2.File(name=event_data.path.rsplit("\\", 1)[-1])
    rel = stix2.Relationship(
        relationship_type="related-to",
        source_ref=reg_key.id,
        target_ref=exec_file.id,
    )
```

### 8.3 `windows:evt:record` and `windows:evtx:record` → `process` SCO + per-Event-ID dispatch

Sources:
- [`plaso/parsers/winevt.py` — `WinEvtRecordEventData`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winevt.py)
- [`plaso/parsers/winevtx.py` — `WinEvtxRecordEventData`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winevtx.py)

Windows Event Log records require per-Event-ID dispatch. Well-known event IDs and their SCO mappings:

| Event ID | Description | Primary STIX SCO | Secondary SCO |
|----------|-------------|-----------------|---------------|
| 4624 | Successful logon | `user-account` (account_login from strings[5]) | — |
| 4625 | Failed logon | `user-account` | — |
| 4634 / 4647 | Logoff | `user-account` | — |
| 4688 | Process creation | `process` (command_line from strings[6]; Vista+) | `user-account` (creator SID) |
| 4689 | Process exit | `process` | — |
| 4698 / 4702 | Scheduled task | `x-plaso-event` | — |
| 5140 | Network share access | `network-traffic` | `user-account` |
| 7045 | New service installed | `process` (windows-service-ext) | `file` (image path) |

**Field-to-STIX mapping for EVTX (`WinEvtxRecordEventData`):**

| Attribute | STIX mapping |
|-----------|--------------|
| `event_identifier` | `x_event_id` custom property on `observed-data` labels |
| `source_name` | `x_source_name` custom property |
| `provider_identifier` | `x_provider_identifier` custom property |
| `hostname` | `network-traffic.dst_ref` or `user-account` host context |
| `user_sid` | `user-account.user_id` |
| `strings` | Substitution strings — used for process/user enrichment per Event ID |
| `record_number` | `x_record_number` on `observed-data` |
| `event_level` | `x_event_level` (0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info) |
| `xml_string` (EVTX only) | Full XML — can be stored in a STIX `Artifact` SCO |

**Concrete approach for Event ID 4688 (process creation):**

```python
def _MapEvtx4688(event_data):
    """Maps EVTX event ID 4688 (process creation) to Process + UserAccount SCOs."""
    strings = getattr(event_data, "strings", []) or []
    scos = []
    proc_kwargs = {}

    # strings[5] = new process name; strings[6] = command line (Vista+)
    # Only set command_line from strings[6]; strings[5] is the executable name
    if len(strings) > 6 and strings[6] and strings[6] != "-":
        proc_kwargs["command_line"] = strings[6]

    user_sid = getattr(event_data, "user_sid", None)
    if user_sid and user_sid != "S-1-0-0":
        account_login = strings[5] if len(strings) > 5 else None
        user = stix2.UserAccount(user_id=user_sid, account_login=account_login)
        scos.append(user)
        proc_kwargs["creator_user_ref"] = user.id

    if proc_kwargs:
        scos.append(stix2.Process(**proc_kwargs))
    return scos
```

### 8.4 `linux:utmp:event` → `user-account` + `network-traffic`

Source: [`plaso/parsers/utmp.py` — `UtmpEventData`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/utmp.py)

| `UtmpEventData` attribute | STIX mapping |
|--------------------------|--------------|
| `username` | `user-account.account_login` |
| `pid` | `process.pid` |
| `hostname` | `network-traffic.src_ref` hostname context |
| `ip_address` | `ipv4-addr.value` or `ipv6-addr.value` |
| `terminal` | Approximate: `user-account.extensions["unix-account-ext"].shell` |
| `login_type` | `x_login_type` custom property on `observed-data` |

```python
def _MapUtmp(event_data):
    """Maps UtmpEventData to user-account + optional network-traffic SCOs."""
    scos = []
    username = getattr(event_data, "username", None)
    if username:
        scos.append(stix2.UserAccount(
            account_login=username,
            account_type="unix",
        ))

    ip = getattr(event_data, "ip_address", None)
    if ip and ip not in ("0.0.0.0", "127.0.0.1", "::"):
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            src_ip = stix2.IPv6Address(value=ip) if isinstance(addr, ipaddress.IPv6Address) else stix2.IPv4Address(value=ip)
            scos.append(src_ip)
            scos.append(stix2.NetworkTraffic(
                src_ref=src_ip.id,
                protocols=["tcp"],
            ))
        except ValueError:
            pass
    return scos
```

### 8.5 `windows:registry:appcompatcache` → `file` + `windows-registry-key`

Source: [`plaso/parsers/winreg_plugins/appcompatcache.py`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/appcompatcache.py)

AppCompatCache records executables that have run on the system — high forensic value. The recommended STIX representation creates both a `file` SCO (the executable) and a `windows-registry-key` SCO (the AppCompatCache key), linked by a `related-to` SRO:

| `AppCompatCacheEventData` attribute | STIX mapping |
|------------------------------------|--------------|
| `path` | `file.name` (basename); full path in `x_full_path` custom property |
| `key_path` | `windows-registry-key.key` |
| `registry_last_written_time` | `windows-registry-key.modified_time` |
| `file_entry_modification_time` | `file.mtime` |
| `entry_index` | `x_entry_index` custom property on the `file` SCO |
| `insertion_flags` | `x_insertion_flags` custom property on the `file` SCO |

### 8.6 `windows:registry:service` → `process` (Windows Service Extension)

Source: [`plaso/parsers/winreg_plugins/services.py`](https://github.com/log2timeline/plaso/blob/main/plaso/parsers/winreg_plugins/services.py)

Windows service registry entries map to a `process` SCO with the Windows service extension:

```python
# Windows service start type → STIX open vocab
_WIN_SERVICE_START_TYPE = {
    0: "BOOT_START",
    1: "SYSTEM_START",
    2: "AUTO_START",
    3: "DEMAND_START",
    4: "DISABLED",
}

def _MapWindowsService(event_data):
    """Maps WindowsRegistryServiceEventData to Process + optional File SCOs."""
    scos = []
    image_path = getattr(event_data, "image_path", None)
    image_file = None
    if image_path:
        basename = image_path.rsplit("\\", 1)[-1]
        if basename:
            image_file = stix2.File(name=basename)
            scos.append(image_file)

    proc_kwargs = {}
    if image_file:
        proc_kwargs["image_ref"] = image_file.id

    service_name = getattr(event_data, "name", None) or "unknown"
    start_type_int = getattr(event_data, "start_type", None)
    proc_kwargs["extensions"] = {
        "windows-service-ext": {
            "service_name": service_name,
            "start_type": _WIN_SERVICE_START_TYPE.get(start_type_int, "AUTO_START"),
        }
    }
    scos.append(stix2.Process(**proc_kwargs))
    return scos
```

Windows Service Extension spec: [STIX 2.1 §4.23.2](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lkeg38ajjlv5)

---

## 9. Complete `stix_out.py` Implementation Skeleton

This is the full reference implementation skeleton for `plaso/output/stix_out.py`, ready for integration into the plaso codebase.

```python
# -*- coding: utf-8 -*-
"""Output module that saves plaso events as a STIX 2.1 Bundle.

Usage:
    psort.py -o stix -w output.stix.json timeline.plaso
"""

from dfdatetime import posix_time as dfdatetime_posix_time

from plaso.output import interface
from plaso.output import manager
from plaso.output import text_file

try:
    import stix2
    from stix2.properties import DictionaryProperty, StringProperty
    _STIX2_IMPORT_ERROR = None
except ImportError as e:
    stix2 = None
    _STIX2_IMPORT_ERROR = e


# ---------------------------------------------------------------------------
# Custom SCO: fallback for unmapped event types
# ---------------------------------------------------------------------------

if stix2:
    @stix2.CustomObservable(
        "x-plaso-event",
        [
            ("data_type", StringProperty(required=True)),
            ("timestamp_desc", StringProperty()),
            ("parser", StringProperty()),
            ("message", StringProperty()),
            ("attributes", DictionaryProperty()),
        ],
        id_contrib_props=["data_type", "attributes"],
    )
    class PlasoEventObservable:
        """Custom STIX SCO for plaso events with no standard SCO mapping."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WIN_SERVICE_START_TYPE = {
    0: "BOOT_START", 1: "SYSTEM_START", 2: "AUTO_START",
    3: "DEMAND_START", 4: "DISABLED",
}


def _MicrosecondsToISO8601(timestamp_us):
    """Converts a plaso microsecond epoch timestamp to ISO 8601 string."""
    if timestamp_us is None:
        return None
    dt = dfdatetime_posix_time.PosixTimeInMicroseconds(timestamp=timestamp_us)
    return dt.CopyToDateTimeStringISO8601()


# ---------------------------------------------------------------------------
# SCO Mapper
# ---------------------------------------------------------------------------

class _STIXObjectMapper:
    """Dispatches plaso EventData to appropriate STIX Cyber Observable Objects."""

    # data_type prefix → builder method name
    _DISPATCH = {
        "fs:stat": "_MapFileStat",
        "windows:registry:appcompatcache": "_MapAppCompatCache",
        "windows:registry:service": "_MapWindowsService",
        "windows:registry:": "_MapWindowsRegistry",
        "windows:evt:record": "_MapWindowsEventLog",
        "windows:evtx:record": "_MapWindowsEventLog",
        "linux:utmp:event": "_MapUtmp",
    }

    def GetSCOs(self, event, event_data, event_data_stream, output_mediator):
        """Returns a list of STIX SCOs for the given event."""
        data_type = getattr(event_data, "data_type", "") or ""
        builder = None

        if data_type in self._DISPATCH:
            builder = getattr(self, self._DISPATCH[data_type], None)
        else:
            for prefix, method_name in self._DISPATCH.items():
                if data_type.startswith(prefix):
                    builder = getattr(self, method_name, None)
                    break

        if builder:
            try:
                result = builder(event, event_data, event_data_stream)
                scos = result if isinstance(result, list) else [result]
                scos = [s for s in scos if s is not None]
                if scos:
                    return scos
            except Exception:  # pylint: disable=broad-except
                pass

        return [self._MapGeneric(event, event_data, output_mediator)]

    def _MapFileStat(self, event, event_data, event_data_stream):
        kwargs = {}
        name = getattr(event_data, "filename", None)
        if name:
            kwargs["name"] = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or name
        size = getattr(event_data, "file_size", None)
        if size is not None:
            kwargs["size"] = size
        for plaso_attr, stix_prop in (
            ("creation_time", "ctime"), ("modification_time", "mtime"),
            ("access_time", "atime"),
        ):
            dt_val = getattr(event_data, plaso_attr, None)
            if dt_val:
                iso = dt_val.CopyToDateTimeStringISO8601()
                if iso:
                    kwargs[stix_prop] = iso
        unix_ext = {}
        for plaso_attr, ext_key, transform in (
            ("inode", "inode", None), ("mode", "mode", lambda v: oct(v)[2:]),
            ("owner_identifier", "uid", str), ("group_identifier", "gid", str),
        ):
            val = getattr(event_data, plaso_attr, None)
            if val is not None:
                unix_ext[ext_key] = transform(val) if transform else val
        if unix_ext:
            kwargs["extensions"] = {"unix-file-ext": unix_ext}
        return stix2.File(**kwargs) if kwargs.get("name") else None

    def _MapWindowsRegistry(self, event, event_data, event_data_stream):
        key_path = getattr(event_data, "key_path", None)
        if not key_path:
            return None
        kwargs = {"key": key_path}
        for ts_attr in ("last_written_time", "registry_last_written_time"):
            dt_val = getattr(event_data, ts_attr, None)
            if dt_val:
                iso = dt_val.CopyToDateTimeStringISO8601()
                if iso:
                    kwargs["modified_time"] = iso
                    break
        values_raw = getattr(event_data, "values", None)
        if values_raw and isinstance(values_raw, list):
            from stix2.v21.observables import WindowsRegistryValueType
            stix_values = []
            for item in values_raw:
                if isinstance(item, (list, tuple)) and len(item) >= 3:
                    name, dtype, data = item[0], item[1], item[2]
                    if isinstance(data, bytes):
                        data = data.hex()
                    stix_values.append(WindowsRegistryValueType(
                        name=name or "(Default)", data_type=dtype or "REG_SZ",
                        data=str(data) if data is not None else "",
                    ))
            if stix_values:
                kwargs["values"] = stix_values
        return stix2.WindowsRegistryKey(**kwargs)

    def _MapAppCompatCache(self, event, event_data, event_data_stream):
        scos = []
        reg_key = self._MapWindowsRegistry(event, event_data, event_data_stream)
        if reg_key:
            scos.append(reg_key)
        exec_path = getattr(event_data, "path", None)
        if exec_path:
            basename = exec_path.rsplit("\\", 1)[-1]
            file_kwargs = {"name": basename} if basename else {}
            dt_val = getattr(event_data, "file_entry_modification_time", None)
            if dt_val:
                iso = dt_val.CopyToDateTimeStringISO8601()
                if iso:
                    file_kwargs["mtime"] = iso
            if file_kwargs.get("name"):
                scos.append(stix2.File(**file_kwargs))
        return scos

    def _MapWindowsService(self, event, event_data, event_data_stream):
        scos = []
        image_path = getattr(event_data, "image_path", None)
        image_file = None
        if image_path:
            basename = image_path.rsplit("\\", 1)[-1]
            if basename:
                image_file = stix2.File(name=basename)
                scos.append(image_file)
        proc_kwargs = {}
        if image_file:
            proc_kwargs["image_ref"] = image_file.id
        service_name = getattr(event_data, "name", None) or "unknown"
        start_type_int = getattr(event_data, "start_type", None)
        proc_kwargs["extensions"] = {
            "windows-service-ext": {
                "service_name": service_name,
                "start_type": _WIN_SERVICE_START_TYPE.get(start_type_int, "AUTO_START"),
            }
        }
        scos.append(stix2.Process(**proc_kwargs))
        return scos

    def _MapWindowsEventLog(self, event, event_data, event_data_stream):
        event_id = getattr(event_data, "event_identifier", None)
        user_sid = getattr(event_data, "user_sid", None)
        strings = getattr(event_data, "strings", []) or []
        scos = []

        if event_id == 4688 and len(strings) > 5:
            proc_kwargs = {}
            # strings[5] = new process name; strings[6] = command line (Vista+)
            if len(strings) > 6 and strings[6] and strings[6] != "-":
                proc_kwargs["command_line"] = strings[6]
            if user_sid and user_sid != "S-1-0-0":
                user = stix2.UserAccount(user_id=user_sid)
                scos.append(user)
                proc_kwargs["creator_user_ref"] = user.id
            if proc_kwargs:
                scos.append(stix2.Process(**proc_kwargs))
            return scos

        if event_id in (4624, 4625) and user_sid:
            account_login = strings[5] if len(strings) > 5 else None
            scos.append(stix2.UserAccount(
                user_id=user_sid, account_login=account_login,
            ))
            return scos

        return []  # Unrecognised event ID → fall through to generic

    def _MapUtmp(self, event, event_data, event_data_stream):
        scos = []
        username = getattr(event_data, "username", None)
        if username:
            scos.append(stix2.UserAccount(account_login=username, account_type="unix"))
        ip = getattr(event_data, "ip_address", None)
        if ip and ip not in ("0.0.0.0", "127.0.0.1", "::"):
            try:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                if isinstance(addr, ipaddress.IPv6Address):
                    src_ip = stix2.IPv6Address(value=ip)
                else:
                    src_ip = stix2.IPv4Address(value=ip)
                scos.append(src_ip)
                scos.append(stix2.NetworkTraffic(src_ref=src_ip.id, protocols=["tcp"]))
            except Exception:  # pylint: disable=broad-except
                pass
        return scos

    def _MapGeneric(self, event, event_data, output_mediator):
        """Fallback: creates an x-plaso-event custom SCO."""
        attributes = {}
        if hasattr(event_data, "GetAttributes"):
            for attr_name, attr_val in event_data.GetAttributes():
                if attr_name.startswith("_") or attr_val is None:
                    continue
                try:
                    attributes[attr_name] = str(attr_val)
                except Exception:  # pylint: disable=broad-except
                    pass

        return PlasoEventObservable(
            data_type=getattr(event_data, "data_type", "unknown") or "unknown",
            timestamp_desc=getattr(event, "timestamp_desc", None),
            parser=getattr(event_data, "_parser_chain", None),
            attributes=attributes or None,
        )


# ---------------------------------------------------------------------------
# Output Module
# ---------------------------------------------------------------------------

class STIXOutputModule(text_file.TextFileOutputModule):
    """Output module for the STIX 2.1 Bundle format.

    Produces a single STIX 2.1 Bundle containing:
    - One Identity SDO representing plaso
    - One or more SCOs + one ObservedData SDO per event
    - One Note SDO per event with analyst tags (EventTag)

    Usage:
        psort.py -o stix -w output.stix.json timeline.plaso
    """

    NAME = "stix"
    DESCRIPTION = "Saves the events into a STIX 2.1 Bundle JSON file."

    def __init__(self):
        """Initializes the STIX output module."""
        super().__init__()
        self._identity = None
        self._sco_cache = {}       # STIX ID → SCO object (for deduplication)
        self._observed_data = []
        self._notes = []
        self._mapper = _STIXObjectMapper()

    def WriteHeader(self, output_mediator):
        """Creates the tool Identity SDO and resets accumulators."""
        self._identity = stix2.Identity(
            name="plaso",
            identity_class="system",
            description=(
                "log2timeline plaso digital forensics timeline tool — "
                "https://github.com/log2timeline/plaso"
            ),
        )
        self._sco_cache = {}
        self._observed_data = []
        self._notes = []

    def GetFieldValues(self, output_mediator, event, event_data,
                       event_data_stream, event_tag):
        """Extracts event fields into a dict for WriteFieldValues."""
        ts_str = _MicrosecondsToISO8601(getattr(event, "timestamp", None))
        scos = self._mapper.GetSCOs(
            event, event_data, event_data_stream, output_mediator
        )
        return {
            "timestamp": ts_str,
            "timestamp_desc": getattr(event, "timestamp_desc", None),
            "scos": scos,
            "event_tag": event_tag,
            "data_type": getattr(event_data, "data_type", None),
        }

    def WriteFieldValues(self, output_mediator, field_values):
        """Converts field_values to STIX ObservedData + SCOs and caches them."""
        ts = field_values.get("timestamp")
        if not ts or not self._identity:
            return

        scos = field_values.get("scos") or []
        if not scos:
            return

        for sco in scos:
            if sco.id not in self._sco_cache:
                self._sco_cache[sco.id] = sco

        obs = stix2.ObservedData(
            created_by_ref=self._identity.id,
            first_observed=ts,
            last_observed=ts,
            number_observed=1,
            object_refs=[s.id for s in scos],
            labels=[field_values["data_type"]] if field_values.get("data_type") else [],
        )
        self._observed_data.append(obs)

        event_tag = field_values.get("event_tag")
        if event_tag and getattr(event_tag, "labels", None):
            note = stix2.Note(
                created_by_ref=self._identity.id,
                abstract="; ".join(event_tag.labels),
                content=f"Analyst tags: {', '.join(event_tag.labels)}",
                object_refs=[obs.id],
            )
            self._notes.append(note)

    def WriteFieldValuesOfMACBGroup(self, output_mediator, macb_group):
        """Overrides default to emit a single ObservedData for the whole MACB group.

        Sets first_observed/last_observed to the group's timestamp range and
        number_observed to the group size, correctly modelling an observation window.
        """
        if not self._identity or not macb_group:
            return

        timestamps = []
        group_scos = {}
        for evt, evt_data, evt_data_stream, _ in macb_group:
            ts = _MicrosecondsToISO8601(getattr(evt, "timestamp", None))
            if ts:
                timestamps.append(ts)
            for sco in self._mapper.GetSCOs(evt, evt_data, evt_data_stream,
                                            output_mediator):
                if sco.id not in self._sco_cache:
                    self._sco_cache[sco.id] = sco
                group_scos[sco.id] = sco

        if not timestamps or not group_scos:
            return

        obs = stix2.ObservedData(
            created_by_ref=self._identity.id,
            first_observed=min(timestamps),
            last_observed=max(timestamps),
            number_observed=len(macb_group),
            object_refs=list(group_scos.keys()),
        )
        self._observed_data.append(obs)

    def WriteFooter(self):
        """Serialises all accumulated STIX objects as a single Bundle JSON."""
        if not self._identity:
            return

        all_objects = (
            [self._identity]
            + list(self._sco_cache.values())
            + self._observed_data
            + self._notes
        )
        bundle = stix2.Bundle(*all_objects, allow_custom=True)
        self.WriteText(bundle.serialize(pretty=True))


manager.OutputManager.RegisterOutput(
    STIXOutputModule,
    disabled=(_STIX2_IMPORT_ERROR is not None),
)
```

---

## 10. Test File Structure: `tests/output/stix_out_test.py`

Following plaso's unit test conventions (Python `unittest`, mock objects for mediator):

```python
# -*- coding: utf-8 -*-
"""Tests for the STIX 2.1 output module."""

import io
import json
import unittest
from unittest import mock

import stix2

from plaso.output import stix_out


class _MockEvent:
    """Minimal mock EventObject."""
    def __init__(self, timestamp=1697356930000000, timestamp_desc="Creation Time"):
        self.timestamp = timestamp
        self.timestamp_desc = timestamp_desc


class _MockEventData:
    """Minimal mock EventData."""
    def __init__(self, data_type="fs:stat", **kwargs):
        self.data_type = data_type
        self._parser_chain = "filestat"
        for k, v in kwargs.items():
            setattr(self, k, v)

    def GetAttributes(self):
        return [(k, v) for k, v in self.__dict__.items() if not k.startswith("_")]


class _MockOutputMediator:
    """Minimal mock OutputMediator."""
    def GetHostname(self, event_data):
        return "testhost"

    def GetUsername(self, event_data):
        return "testuser"


class STIXObjectMapperTest(unittest.TestCase):
    """Unit tests for _STIXObjectMapper."""

    def setUp(self):
        self._mapper = stix_out._STIXObjectMapper()
        self._mediator = _MockOutputMediator()

    def test_file_stat_produces_file_sco(self):
        event = _MockEvent()
        event_data = _MockEventData(
            data_type="fs:stat", filename="/home/user/malware.exe", file_size=102400,
        )
        scos = self._mapper.GetSCOs(event, event_data, None, self._mediator)
        self.assertEqual(len(scos), 1)
        self.assertIsInstance(scos[0], stix2.File)
        self.assertEqual(scos[0].name, "malware.exe")
        self.assertEqual(scos[0].size, 102400)

    def test_registry_key_produces_windows_registry_key_sco(self):
        event = _MockEvent()
        event_data = _MockEventData(
            data_type="windows:registry:key_value",
            key_path="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
        )
        scos = self._mapper.GetSCOs(event, event_data, None, self._mediator)
        reg_keys = [s for s in scos if isinstance(s, stix2.WindowsRegistryKey)]
        self.assertEqual(len(reg_keys), 1)
        self.assertEqual(
            reg_keys[0].key, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows"
        )

    def test_utmp_produces_user_account_and_network_traffic(self):
        event = _MockEvent()
        event_data = _MockEventData(
            data_type="linux:utmp:event", username="jdoe", ip_address="10.0.0.5",
        )
        scos = self._mapper.GetSCOs(event, event_data, None, self._mediator)
        accounts = [s for s in scos if isinstance(s, stix2.UserAccount)]
        network = [s for s in scos if isinstance(s, stix2.NetworkTraffic)]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].account_login, "jdoe")
        self.assertEqual(len(network), 1)

    def test_generic_produces_x_plaso_event_sco(self):
        event = _MockEvent()
        event_data = _MockEventData(data_type="windows:prefetch:execution")
        scos = self._mapper.GetSCOs(event, event_data, None, self._mediator)
        self.assertEqual(len(scos), 1)
        self.assertEqual(scos[0].type, "x-plaso-event")

    def test_unknown_data_type_falls_through_to_generic(self):
        event = _MockEvent()
        event_data = _MockEventData(data_type="totally:unknown:type")
        scos = self._mapper.GetSCOs(event, event_data, None, self._mediator)
        self.assertEqual(len(scos), 1)
        self.assertEqual(scos[0].type, "x-plaso-event")


class STIXOutputModuleTest(unittest.TestCase):
    """Integration tests for STIXOutputModule."""

    def _CreateModule(self):
        module = stix_out.STIXOutputModule()
        mediator = _MockOutputMediator()
        output = io.StringIO()
        module._file_object = output
        module.WriteHeader(mediator)
        return module, mediator, output

    def test_bundle_is_valid_json(self):
        module, mediator, output = self._CreateModule()
        event = _MockEvent()
        event_data = _MockEventData(data_type="fs:stat", filename="/tmp/test.exe")
        fv = module.GetFieldValues(mediator, event, event_data, None, None)
        module.WriteFieldValues(mediator, fv)
        module.WriteFooter()
        data = json.loads(output.getvalue())
        self.assertEqual(data["type"], "bundle")

    def test_bundle_contains_identity_and_observed_data(self):
        module, mediator, output = self._CreateModule()
        event = _MockEvent()
        event_data = _MockEventData(data_type="fs:stat", filename="test.dll")
        fv = module.GetFieldValues(mediator, event, event_data, None, None)
        module.WriteFieldValues(mediator, fv)
        module.WriteFooter()
        data = json.loads(output.getvalue())
        types = {o["type"] for o in data["objects"]}
        self.assertIn("identity", types)
        self.assertIn("observed-data", types)

    def test_event_tag_produces_note_sdo(self):
        module, mediator, output = self._CreateModule()
        event = _MockEvent()
        event_data = _MockEventData(data_type="fs:stat", filename="bad.exe")
        event_tag = mock.Mock()
        event_tag.labels = ["malware", "suspicious"]
        fv = module.GetFieldValues(mediator, event, event_data, None, event_tag)
        module.WriteFieldValues(mediator, fv)
        module.WriteFooter()
        data = json.loads(output.getvalue())
        types = {o["type"] for o in data["objects"]}
        self.assertIn("note", types)

    def test_sco_deduplication_for_same_file(self):
        """Two events for the same file should produce only one File SCO."""
        module, mediator, output = self._CreateModule()
        for ts_desc in ("Creation Time", "Modification Time"):
            event = _MockEvent(timestamp_desc=ts_desc)
            event_data = _MockEventData(
                data_type="fs:stat", filename="shared.dll", file_size=512,
            )
            fv = module.GetFieldValues(mediator, event, event_data, None, None)
            module.WriteFieldValues(mediator, fv)
        module.WriteFooter()
        data = json.loads(output.getvalue())
        file_objs = [o for o in data["objects"] if o["type"] == "file"]
        self.assertEqual(len(file_objs), 1)

    def test_macb_group_produces_single_observed_data(self):
        module, mediator, output = self._CreateModule()
        macb_group = []
        for ts, ts_desc in (
            (1697356930000000, "Modification Time"),
            (1697356940000000, "Access Time"),
            (1697356950000000, "Change Time"),
        ):
            event = _MockEvent(timestamp=ts, timestamp_desc=ts_desc)
            event_data = _MockEventData(data_type="fs:stat", filename="macb.txt")
            macb_group.append((event, event_data, None, None))
        module.WriteFieldValuesOfMACBGroup(mediator, macb_group)
        module.WriteFooter()
        data = json.loads(output.getvalue())
        obs_list = [o for o in data["objects"] if o["type"] == "observed-data"]
        self.assertEqual(len(obs_list), 1)
        self.assertEqual(obs_list[0]["number_observed"], 3)

    def test_stix_bundle_is_parseable_by_stix2_library(self):
        """The bundle output must be accepted by stix2.parse()."""
        module, mediator, output = self._CreateModule()
        event = _MockEvent()
        event_data = _MockEventData(data_type="fs:stat", filename="valid.exe")
        fv = module.GetFieldValues(mediator, event, event_data, None, None)
        module.WriteFieldValues(mediator, fv)
        module.WriteFooter()
        # This raises on invalid STIX
        bundle = stix2.parse(output.getvalue(), allow_custom=True)
        self.assertEqual(bundle.type, "bundle")


if __name__ == "__main__":
    unittest.main()
```

---

## 11. Dependency Analysis

### 11.1 Direct Dependency: `stix2`

| Package | Minimum version | PyPI | Notes |
|---------|----------------|------|-------|
| `stix2` | `>= 2.0.0` | <https://pypi.org/project/stix2/> | Both 2.x and 3.x can produce STIX 2.1 content; 3.x makes STIX 2.1 the default |

### 11.2 Transitive Dependencies Introduced by `stix2`

| Package | Purpose | Already in plaso? |
|---------|---------|-------------------|
| `requests` | HTTP for TAXII feeds (optional use path) | Possibly — check `requirements.txt` |
| `simplejson` | JSON serialisation | Possibly |
| `stix2-patterns` | STIX pattern validation for `Indicator` objects | No — new dep |
| `antlr4-python3-runtime` | Required by `stix2-patterns` ANTLR grammar | No — new dep (~9 MB) |

`antlr4-python3-runtime` is a non-trivial addition. If `Indicator` objects are never created (only `ObservedData` output), pattern validation is never triggered. The `allow_custom=True` flag on `Bundle` also suppresses some validation. For a first implementation, the transitive ANTLR dependency is acceptable.

### 11.3 Recommended `setup.cfg` Addition

Add `stix2` as an **optional extra** so plaso's core install does not gain the ANTLR dependency:

```ini
# setup.cfg
[options.extras_require]
stix =
    stix2 >= 3.0.0
```

Install with: `pip install plaso[stix]`

The `ImportError` guard in `stix_out.py` ensures the module registers as disabled (`disabled=True`) when `stix2` is not installed, matching the pattern used by `plaso/output/opensearch.py`:

```python
# opensearch.py pattern (source reference):
manager.OutputManager.RegisterOutput(
    OpenSearchOutputModule, disabled=shared_opensearch.opensearchpy is None
)
```

Source: [`plaso/output/opensearch.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/opensearch.py)

---

## 12. Build, Test, and Integration Steps

### 12.1 Setting Up a Development Environment

```bash
git clone https://github.com/log2timeline/plaso.git
cd plaso
pip install -e ".[dev]"
pip install "stix2>=3.0.0"
```

### 12.2 Adding the Output Module

```bash
# 1. Place the implementation
cp stix_out.py plaso/output/stix_out.py

# 2. Register it in the package __init__
echo "from plaso.output import stix_out" >> plaso/output/__init__.py

# 3. Verify psort discovers it
python -m plaso.tools.psort --help | grep -A1 stix
# Expected:
#   stix          Saves the events into a STIX 2.1 Bundle JSON file.
```

### 12.3 Running the Tests

```bash
# Unit + integration tests for the new module only
python -m pytest tests/output/stix_out_test.py -v

# Lint (plaso uses pylint + pycodestyle)
pylint plaso/output/stix_out.py
pycodestyle plaso/output/stix_out.py
```

### 12.4 End-to-End Validation

```bash
# Run psort against a test .plaso file
python -m plaso.tools.psort \
    -o stix \
    -w /tmp/output.stix.json \
    /path/to/test.plaso

# Validate with the OASIS stix2-validator CLI tool
pip install stix2-validator
stix2_validator /tmp/output.stix.json
```

### 12.5 Programmatic Validation

```python
import stix2, json

with open("/tmp/output.stix.json") as f:
    raw = json.load(f)

bundle = stix2.parse(json.dumps(raw), allow_custom=True)
print(f"Bundle: {len(bundle.objects)} objects")
for obj in bundle.objects:
    print(f"  {obj.type}: {obj.id}")
```

---

## 13. Performance Considerations

### 13.1 Memory Profile for Typical Timelines

For a plaso file from a standard Windows investigation (~50,000 events):

| Object type | Estimated count | Per-object memory |
|-------------|----------------|------------------|
| `observed-data` | ~50,000 | ~1–2 KB |
| `file` SCOs (deduplicated) | ~5,000–15,000 | ~500 B |
| `windows-registry-key` SCOs | ~5,000–20,000 | ~500 B |
| `x-plaso-event` fallback | ~10,000–30,000 | ~1–3 KB |
| Peak RSS | — | ~300 MB – 1 GB |
| `bundle.serialize()` time | — | 5–30 seconds |

This is acceptable for investigation-scale workloads. For enterprise timelines (millions of events), use a streaming strategy.

### 13.2 Streaming NDJSON-Bundle Strategy (O(1) Memory)

Emit one mini-bundle per event instead of accumulating everything:

```python
def WriteFieldValues(self, output_mediator, field_values):
    scos = field_values.get("scos") or []
    if not scos or not field_values.get("timestamp"):
        return
    objects = [self._identity] + scos
    obs = stix2.ObservedData(
        created_by_ref=self._identity.id,
        first_observed=field_values["timestamp"],
        last_observed=field_values["timestamp"],
        number_observed=1,
        object_refs=[s.id for s in scos],
    )
    objects.append(obs)
    self.WriteLine(stix2.Bundle(*objects, allow_custom=True).serialize())

def WriteFooter(self):
    pass  # Nothing to flush
```

Trade-off: output file contains one bundle per line (not a single bundle). Compatible with line-by-line SIEM/TAXII ingestion.

### 13.3 Batched Bundle Strategy (Recommended Compromise)

Flush to file every N events, keeping SCO deduplication within each batch:

```python
_BATCH_SIZE = 10_000

def WriteFieldValues(self, output_mediator, field_values):
    # ... accumulate as in §9 ...
    if len(self._observed_data) >= self._BATCH_SIZE:
        self._FlushBatch()

def _FlushBatch(self):
    bundle = stix2.Bundle(
        self._identity,
        *self._sco_cache.values(),
        *self._observed_data,
        *self._notes,
        allow_custom=True,
    )
    self.WriteLine(bundle.serialize())
    # Reset per-batch state but retain identity and SCO cache for cross-batch dedup
    self._observed_data = []
    self._notes = []
```

---

## 14. Security and Privacy Considerations

### 14.1 Sensitive Data in STIX Bundles

Plaso timelines may contain data that should not leave an investigation environment:

| Data type | Where it appears in STIX |
|-----------|--------------------------|
| Usernames and SIDs | `user-account.account_login`, `.user_id` |
| File paths | `file.name`, `x-plaso-event.attributes` |
| Command lines (may contain passwords) | `process.command_line` |
| Registry values (credentials, licence keys) | `windows-registry-key.values[].data` |
| Internal network addresses | `ipv4-addr.value`, `network-traffic` |

Recommended mitigations:
1. A **scrubbing pass** on `attributes` dict in `_MapGeneric` (strip known-sensitive field names)
2. CLI option flags `--stix-redact-usernames`, `--stix-redact-paths`, `--stix-redact-cmdlines`
3. Apply TLP data markings to restrict bundle distribution

### 14.2 TLP Data Markings

Apply Traffic Light Protocol markings to restrict sharing:

```python
# In WriteHeader():
self._tlp_amber = stix2.MarkingDefinition(
    definition_type="tlp",
    definition=stix2.TLPMarking(tlp="amber"),
)

# In WriteFieldValues(), add to each observed-data:
obs = stix2.ObservedData(
    ...,
    object_marking_refs=[self._tlp_amber.id],
)
```

TLP marking spec: [STIX 2.1 §10 — Data Markings](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hn8byemkezp6)

### 14.3 Chain of Custody

For forensic reporting, the `identity` SDO can include the examiner's details to provide a chain of custody trail within the STIX bundle:

```python
examiner_identity = stix2.Identity(
    name=examiner_name,
    identity_class="individual",
    contact_information=examiner_email,
)
tool_identity = stix2.Identity(
    name="plaso",
    identity_class="system",
    created_by_ref=examiner_identity.id,
)
```
