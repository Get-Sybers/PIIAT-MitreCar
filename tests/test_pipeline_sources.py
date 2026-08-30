"""The pipeline USES the source-manifest structure (epic #86, #8).

When a source is processed, its car.db is paired with a `sources.yaml` manifest
declaring what each contributing source yields + provenance, and the pipeline
CAR-validity-checks that coverage. This tests that wiring without needing real
evidence on disk.
"""
import os

import yaml

from piiat_mitrecar import pipeline


def test_write_source_manifests_emits_and_validates(tmp_path):
    used = ["evtx_security", "plaso_fseventsd", "memory (passthrough)"]
    ids, issues = pipeline._write_source_manifests(str(tmp_path), used)

    # contributing sources are recorded (the memory passthrough resolves to memory)
    assert "evtx_security" in ids
    assert "plaso_fseventsd" in ids
    assert "memory" in ids
    # a source may never claim coverage outside the CAR data model
    assert issues == []

    # the manifest file is written next to where the car.db would be, one doc per
    # source, each carrying end-to-end provenance
    docs = list(yaml.safe_load_all(open(os.path.join(tmp_path, "sources.yaml"))))
    assert {d["sensor_name"] for d in docs} == set(ids)
    for d in docs:
        assert d["derived_from"]
        assert d["extractor"]["tool"]
