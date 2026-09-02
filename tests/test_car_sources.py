"""Tests for the generated CAR source (sensor) definitions (epic #86).

The source definitions are DERIVED from the maps + routing, so these tests are
about that derivation staying correct and repeatable, not about hand-authored
content: every map has a traceable source, every claimed (object, action, field)
is real CAR, the end-to-end provenance is present, and generation is idempotent.
"""
import os

import pytest

from piiat_mitrecar import carmodel, gen_sources, mappings, sources_model

_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "sources")


def test_registry_is_consistent_with_maps_and_routing():
    # every map has a derivation, every derivation is a real map, every source
    # is reachable from the routing table
    assert sources_model.verify_registry() == []


def test_every_map_has_a_source_doc():
    for key in mappings.MAPPINGS:
        assert key in sources_model.DERIVATIONS, f"{key} missing provenance"
    docs = sources_model.all_source_docs()
    for key in mappings.MAPPINGS:
        assert key in docs


def test_docs_conform_to_car_sensor_schema():
    required = {"sensor_name", "sensor_version", "sensor_developer", "sensor_url",
                "mappings", "other_coverage"}
    for source_id, doc in sources_model.all_source_docs().items():
        assert required <= set(doc), f"{source_id} missing CAR sensor keys"
        assert isinstance(doc["mappings"], list)
        for m in doc["mappings"]:
            # object/action/notes/fields are the CAR sensor keys; field_provenance
            # is our documented extension (per-field has/infers/came-from).
            assert {"object", "action", "notes", "fields"} <= set(m)
            assert set(m) <= {"object", "action", "notes", "fields", "field_provenance"}
            assert isinstance(m["fields"], list)
            assert m["notes"]
        assert isinstance(doc["other_coverage"], list)


def test_every_claimed_object_action_field_is_real_car():
    # the generator must never emit coverage the CAR data model does not define
    assert sources_model.validate_against_car_model() == []
    model = carmodel.load()
    for source_id, doc in sources_model.all_source_docs().items():
        for m in doc["mappings"]:
            spec = model[m["object"]]
            assert m["action"] in spec["actions"]
            assert set(m["fields"]) <= set(spec["fields"])


def test_end_to_end_provenance_present():
    # raw evidence -> extractor/wrapper -> input pattern -> map -> CAR
    for source_id, doc in sources_model.all_source_docs().items():
        assert doc["derived_from"], f"{source_id}: no raw-evidence link"
        assert doc["extractor"]["tool"], f"{source_id}: no extractor tool"
        assert doc["extractor"]["url"]
        # every map-derived source is routed; the memory passthrough is too
        assert doc["input_pattern"], f"{source_id}: no input pattern"


def test_evtx_family_records_both_derivations():
    # EvtxECmd is primary; the Plaso winevt adapter is the alternate route, and
    # both input patterns must be present for traceability
    doc = sources_model.build_source_doc("evtx_sysmon")
    assert doc["extractor"]["tool"] == "EvtxECmd"
    assert any("winevt" in a.lower() for a in doc["extractor"]["alternates"])
    assert "_EvtxECmd_Output" in doc["input_pattern"]
    assert any(p in (".L2tWinevt", ".L2tWinevtx") for p in doc["input_pattern"])


def test_action_resolver_covers_marker_shapes():
    from piiat_mitrecar.normalize import const, first, map_value
    assert sources_model.resolve_actions("create") == {"create"}
    assert sources_model.resolve_actions(const("get")) == {"get"}
    assert sources_model.resolve_actions(
        map_value("m", {"GET": "get", "POST": "post"})) == {"get", "post"}
    assert sources_model.resolve_actions(
        first(map_value("t", {"7": "unlock"}), const("login"))) == {"unlock", "login"}
    with pytest.raises(ValueError):
        sources_model.resolve_actions(("basename", "x"))   # unresolvable action


def test_map_references_its_source_by_name():
    # a map and its source are 1:1 by name unless the map overrides "source"
    for key in mappings.MAPPINGS:
        assert sources_model.source_id_for(key) == key


def test_generation_is_deterministic_and_idempotent(tmp_path):
    first_paths = gen_sources.write_all(str(tmp_path))
    first = {os.path.basename(p): open(p, encoding="utf-8").read() for p in first_paths}
    gen_sources.write_all(str(tmp_path))          # regenerate over itself
    second = {os.path.basename(p): open(p, encoding="utf-8").read() for p in first_paths}
    assert first == second                         # byte-for-byte stable
    # and a fresh directory verifies clean
    assert sources_model.verify_coverage(str(tmp_path)) == []


def test_committed_sources_are_in_sync_if_present():
    # if the repo ships generated sources, they must match the current maps
    if not os.path.isdir(_SOURCES_DIR):
        pytest.skip("no committed sources/ directory")
    assert sources_model.verify_coverage(_SOURCES_DIR) == []


def test_sources_validate_against_yamale_schema():
    """Full yamale validation against car_source_schema.yaml — runs in CI (where
    yamale is installed), skips locally if it is not."""
    import glob
    yamale = pytest.importorskip("yamale")
    schema_path = os.path.join(os.path.dirname(__file__), "..",
                               "piiat_mitrecar", "car_source_schema.yaml")
    schema = yamale.make_schema(schema_path)
    docs = glob.glob(os.path.join(_SOURCES_DIR, "*.yaml"))
    assert docs, "no source manifests to validate"
    for path in docs:
        yamale.validate(schema, yamale.make_data(path))


def test_source_docs_state_the_row_identity_from_the_registry():
    """Every manifest says what its guid IS (car_source_schema.yaml `identity`):
    a Plaso-derived source names the spindle registry entries its map mints
    from (kind / scope / version); any other source names the external form(s)
    it carries verbatim; the memory passthrough names PIIAT-Mem's proc-<hex>.
    Resolved by the registry itself, and drift-checked like coverage."""
    import os
    import tempfile

    import yaml

    from piiat_mitrecar import gen_sources, spindle
    docs = sources_model.all_source_docs()
    plaso = {k for k, d in sources_model.DERIVATIONS.items() if d.tool == sources_model.PLASO_TOOL}
    for key in sources_model.DERIVATIONS:
        ident = docs[key]["identity"]
        if key in plaso:
            assert ident["registry"] == "piiat_mitrecar/spindle.yml", key
            assert ident["version"] == spindle.rules()["spindle"]["version"] and "external" not in ident
            assert ident["entries"], key
            for e in ident["entries"]:
                entry = spindle.entry(e["name"])
                assert e["name"] == key or e["name"].startswith(key + "/")
                assert (e["kind"], e["scope"], e["version"]) == (entry["kind"], entry["scope"], entry["version"])
        else:
            assert "entries" not in ident and ident["external"], key
            assert set(ident["external"]) <= set(spindle.externals())
    assert docs["evtx_sysmon"]["identity"]["external"] == ["evtx_record", "sysmon_process_guid"]
    assert docs["zeek_http"]["identity"]["external"] == ["zeek_uid_trans_depth"]
    assert docs["memory"]["identity"] == {"external": ["memory_proc_offset"]}
    assert [e["name"] for e in docs["plaso_exec_winreg"]["identity"]["entries"]] == [
        "plaso_exec_winreg/amcache", "plaso_exec_winreg/amcache_link_time", "plaso_exec_winreg/appcompatcache",
        "plaso_exec_winreg/bam", "plaso_exec_winreg/userassist"]
    # identity drift on disk is caught by gen_sources --check exactly like coverage drift
    with tempfile.TemporaryDirectory() as d:
        gen_sources.write_all(d)
        assert sources_model.verify_coverage(d) == []
        path = os.path.join(d, "l2t_mft.yaml")
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        doc["identity"]["entries"][0]["version"] = 2
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh)
        assert sources_model.verify_coverage(d) == ["l2t_mft: identity drifted from the spindle registry"]
