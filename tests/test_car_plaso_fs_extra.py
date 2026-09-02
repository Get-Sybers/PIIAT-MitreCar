"""Tests for the plaso PE/COFF map (mappings/plaso_fs_extra.py, `plaso_pecoff`).

Rows are the wrapped l2t JSONL shape ({SourceImage, Timestamp, Parser,
Record}); synthetic, shaped per plaso's PEFileEventData and timeliner.yaml:
one row per PE-INTERNAL stamp — the header TimeDateStamp ('Creation Time'),
the export / load-configuration table stamps ('Content Modification Time'),
the undated placeholder ('Not a time') — plus the pe_coff:dll_import and
pe_coff:resource rows the map leaves raw.
"""
from __future__ import annotations

import json
import uuid

from piiat_mitrecar import normalize, pipeline

_PE_HEADER = {  # synthetic; the header TimeDateStamp row (compile/link time)
    "SourceImage": "log2timeline/jsonl/synth.jsonl",
    "Timestamp": "2019-06-01T12:34:56.000000Z",
    "Parser": "pe",
    "Record": {
        "data_type": "pe_coff:file",
        "display_name": "NTFS:\\Windows\\System32\\evil.dll",
        "export_dll_name": "evil.dll",
        "image_hostname": "HOST1.corp.example",
        "imphash": "d3310ce6cbcacb3a9f0809bc33e38abe",
        "parser": "pe",
        "pe_type": "Dynamic Link Library (DLL)",
        "section_names": [".text", ".rdata", ".data", ".reloc"],
        "sha256_hash": "b5de10a0" + "0" * 56,
        "timestamp_desc": "Creation Time",
    },
}


def _row(desc=None, data_type=None, ts="2019-06-01T12:34:56.000000Z"):
    rec = json.loads(json.dumps(_PE_HEADER))
    rec["Timestamp"] = ts
    if desc is not None:
        rec["Record"]["timestamp_desc"] = desc
    if data_type is not None:
        rec["Record"]["data_type"] = data_type
    return rec


def test_pe_header_stamp_is_a_compile_time_not_a_file_create_event():
    ev = normalize.normalize("plaso_pecoff", _PE_HEADER)
    assert ev is not None
    assert ev["car_object"] == "file" and ev["car_action"] == "create"
    # the compile time is NOT when the file was created on the host: no
    # timestamp (off the timeline); the stamp rides native as what it is
    assert ev["timestamp"] is None
    assert ev["_native"]["compile_time"] == "2019-06-01T12:34:56.000000Z"
    assert "pe_table_time" not in ev["_native"]
    assert ev["_native"]["timestamp_desc"] == "Creation Time"
    # the file identity + PE metadata survive for hash/path pivots
    assert ev["file_path"] == "\\Windows\\System32\\evil.dll"
    assert ev["file_name"] == "evil.dll" and ev["extension"] == "dll"
    assert ev["sha256_hash"].startswith("b5de10a0")
    assert ev["_native"]["imphash"] == "d3310ce6cbcacb3a9f0809bc33e38abe"
    assert ev["_native"]["pe_type"].startswith("Dynamic Link Library")
    assert ev["_native"]["section_names"] == [".text", ".rdata", ".data", ".reloc"]
    assert ev["hostname"] == "HOST1.corp.example" and ev["source_host"] == "HOST1"
    # its identity is the PE as an ENTITY (path + its own hash): minted,
    # time-free — no stamp of a PE is a host event (spindle.yml plaso_pecoff)
    assert ev["guid"] and uuid.UUID(ev["guid"]).version == 5
    assert ev["_native"]["spindle_scope"] == "intrinsic"
    assert set(ev["_native"]["spindle_key"]) == {"_obj", "_v", "file_path", "sha256"}


def test_pe_table_stamps_and_placeholder_are_records_without_a_time():
    table = normalize.normalize("plaso_pecoff", _row("Content Modification Time",
                                                     ts="2019-06-01T12:35:00.000000Z"))
    assert table["car_object"] == "file" and table["car_action"] == "create"
    assert table["timestamp"] is None
    assert table["_native"]["pe_table_time"] == "2019-06-01T12:35:00.000000Z"
    assert "compile_time" not in table["_native"]
    # the placeholder plaso emits for a PE it could not date at all
    holder = normalize.normalize("plaso_pecoff", _row("Not a time", ts="1970-01-01T00:00:00.000000Z"))
    assert holder["car_object"] == "file" and holder["timestamp"] is None
    assert "compile_time" not in holder["_native"] and "pe_table_time" not in holder["_native"]
    assert holder["sha256_hash"].startswith("b5de10a0")
    # the three rows of ONE PE differ only in native: one entity identity
    header = normalize.normalize("plaso_pecoff", _PE_HEADER)
    assert header["guid"] == table["guid"] == holder["guid"]


def test_pe_compile_time_never_yields_a_timestamped_file_event():
    # the pinned regression: no row on the .L2tPe route asserts a host file
    # event AT a PE-internal stamp
    stamped = [_PE_HEADER, _row("Content Modification Time"), _row("Not a time")]
    for key in pipeline.route("host.L2tPe"):
        for rec in stamped:
            ev = normalize.normalize(key, rec)
            assert ev is None or ev["timestamp"] is None, (key, rec["Record"]["timestamp_desc"])
        assert normalize.normalize(key, _PE_HEADER)["car_action"] != "modify"


def test_pe_import_and_resource_rows_stay_raw():
    assert normalize.normalize("plaso_pecoff", _row(data_type="pe_coff:dll_import")) is None
    assert normalize.normalize("plaso_pecoff", _row(data_type="pe_coff:resource")) is None
