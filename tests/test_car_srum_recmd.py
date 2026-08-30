"""SRUM (via Plaso esedb/srum) -> flow/process and RECmd batch JSON -> registry.
Fixtures mirror REAL LoneWolf shapes (SRUDB.dat 17,928 rows; hives 7,493)."""
from piiat_mitrecar import normalize


def _srum(dt, **extra):
    rec = {"data_type": dt, "parser": "esedb/srum", "timestamp_desc": "Recorded Time"}
    rec.update(extra)
    return {"SourceImage": "lw", "Timestamp": "2018-03-27T12:19:00Z",
            "Parser": "esedb/srum", "Record": rec}


def test_srum_network_usage_is_flow_message_with_attribution():
    ev = normalize.normalize("l2t_srum", _srum(
        "windows:srum:network_usage", application="DiagTrack",
        bytes_received=251792, bytes_sent=372082,
        user_identifier="S-1-5-21-1-2-3-1001", interface_luid=19985273102270464))
    assert ev["car_object"] == "flow" and ev["car_action"] == "message"
    assert ev["in_bytes"] == 251792 and ev["out_bytes"] == 372082
    assert ev["exe"] == "DiagTrack" and ev["image_path"] is None   # bare name != a path
    assert ev["uid"] == "S-1-5-21-1-2-3-1001"
    dev = normalize.normalize("l2t_srum", _srum(
        "windows:srum:network_usage",
        application=r"\Device\HarddiskVolume4\Program Files\S3 Browser\s3browser-win32.exe",
        bytes_received=1, bytes_sent=2, user_identifier=2))
    assert dev["exe"] == "s3browser-win32.exe"
    assert dev["image_path"].startswith("\\Device\\")
    assert dev["uid"] is None                        # an SRUM index is not an identity


def test_srum_application_usage_is_execution_evidence():
    ev = normalize.normalize("l2t_srum", _srum(
        "windows:srum:application_usage",
        application=r"\Device\HarddiskVolume4\Windows\System32\LogonUI.exe",
        user_identifier="S-1-5-18", foreground_cycle_time=3680219664))
    assert ev["car_object"] == "process" and ev["car_action"] == "create"
    assert ev["exe"] == "LogonUI.exe" and ev["sid"] == "S-1-5-18"
    assert ev["_native"]["foreground_cycle_time"] == 3680219664
    # connectivity telemetry has no honest CAR object -> raw
    assert normalize.normalize("l2t_srum", _srum(
        "windows:srum:network_connectivity", application=1)) is None


def _recmd(**over):
    rec = {"HivePath": r"/in/Users/jcloudy/AppData/Local/Microsoft/Windows/UsrClass.dat",
           "HiveType": "UsrClass", "Description": "MuiCache (Vista+)",
           "Category": "Program Execution",
           "KeyPath": r"S-1-5-21-1_Classes\Local Settings\...\MuiCache",
           "ValueName": "LangID", "ValueType": "RegBinary",
           "ValueData": "(Binary data)", "ValueData2": None, "ValueData3": None,
           "Comment": "Displays new applications", "Recursive": False,
           "Deleted": False, "LastWriteTimestamp": "2018-04-02 01:15:16.9540407"}
    rec.update(over)
    return rec


def test_recmd_value_record_is_registry_value_edit():
    ev = normalize.normalize("recmd_batch", _recmd())
    assert ev["car_object"] == "registry" and ev["car_action"] == "value_edit"
    assert ev["hive"] == "UsrClass" and ev["value"] == "LangID"
    assert ev["user"] == "jcloudy"                     # hive-path convention
    assert ev["timestamp"] == "2018-04-02T01:15:16.9540407"   # space -> T
    assert ev["_native"]["Category"] == "Program Execution"
    # a recovered-deleted record's deletion TIME is unknowable -> raw
    assert normalize.normalize("recmd_batch", _recmd(Deleted=True)) is None
