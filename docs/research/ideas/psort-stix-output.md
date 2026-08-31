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
| `event` | `EventObject` | `timestamp` (microseconds since epoch), `date_time`, `GetAttributes()` |
| `event_data` | `EventData` | `data_type` (e.g. `"fs:stat"`, `"windows:registry:key_value"`), all parsed attributes |
| `event_data_stream` | `EventDataStream` | `path_spec` (dfVFS path) |
| `event_tag` | `EventTag` | analyst labels (may be `None`) |

`event.timestamp` is a Unix microsecond integer; ISO 8601 formatting logic lives in  
[`plaso/output/formatting_helper.py`](https://github.com/log2timeline/plaso/blob/main/plaso/output/formatting_helper.py) (`_FormatDateTime`).

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
| `last_observed` | timestamp | `event.timestamp` (same as first for single events) |
| `number_observed` | integer ≥ 1 | `1` per event |
| `object_refs` | list of SCO refs | References to the Cyber Observable Objects below |

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

Plaso stores timestamps as **microseconds since the Unix epoch** (signed integer). STIX timestamps must be RFC 3339 strings in UTC. The conversion:

```python
import datetime

def _microseconds_to_iso8601(timestamp_us: int) -> str:
    dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) \
         + datetime.timedelta(microseconds=timestamp_us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
```

Edge cases: `timestamp_us = 0` (unknown time), negative timestamps (pre-epoch).

### 5.2 SCO Deduplication

Multiple plaso events may reference the same file (e.g. `mtime` and `atime` events from `fs:stat`). The module should deduplicate SCOs by their deterministic STIX ID to avoid duplicate objects in the bundle. A `dict` keyed on SCO `id` is the recommended approach.

### 5.3 Memory Usage for Large Timelines

Accumulating all SCOs and `observed-data` objects in memory until `WriteFooter` is called will cause memory pressure for large storage files. Mitigation options:

1. **Streaming NDJSON**: Emit one `observed-data` Bundle per line (similar to `json_line`). This breaks STIX Bundle semantics but is more scalable.
2. **Batched bundles**: Write a new Bundle every N events.
3. **External sort + merge**: Write objects to a temp file, deduplicate, then write the final Bundle.

For a first implementation, in-memory accumulation is simplest and acceptable for small-to-medium timelines.

### 5.4 STIX Pattern Language (Optional Enhancement)

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
| `observed-data` | STIX SDO | One per plaso event, referencing SCO(s) |
| `identity` | STIX SDO | One per bundle, identifying "plaso" as the producer |

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
| `stix2/v21/observables.py` — SCO classes source | <https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/v21/observables.py> |
