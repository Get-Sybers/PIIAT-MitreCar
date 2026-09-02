"""The CAR->ECS projection contract stays in step with the CAR model.

Thin: the contract's own validator (validate.py) does the work; these tests
invoke it as the repo's checks do, and prove it actually catches drift.
"""
import importlib.util
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent


def _validator():
    spec = importlib.util.spec_from_file_location("car_ecs_validate", HERE / "validate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_validate_cli_passes():
    r = subprocess.run([sys.executable, str(HERE / "validate.py")],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "car-ecs projection OK" in r.stdout


def test_orphan_and_missing_fields_are_drift():
    v = _validator()
    car = v.load_car_model()
    conventions, objects = v.load_contract()
    assert v.validate(car, conventions, objects) == []

    objects["process"]["fields"].append({"car": "not_a_car_field", "ecs": "process.name"})
    dropped = objects["file"]["fields"].pop()
    errors = v.validate(car, conventions, objects)
    assert any("not_a_car_field" in e and "orphan" in e for e in errors)
    assert any(dropped["car"] in e and "no projection entry" in e for e in errors)
