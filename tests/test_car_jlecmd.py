"""JLECmd jump lists -> file/read via the flattening adapter (real LoneWolf shape)."""
from piiat_mitrecar import normalize
from piiat_mitrecar.adapters import jlecmd


_RECORD = {
    "AppId": {"AppId": "fb3b0dbfee58fac8", "Description": "Microsoft Word 2016 64-bit"},
    "SourceFile": "/in/AutomaticDestinations/fb3b0dbfee58fac8.automaticDestinations-ms",
    "DestListEntries": [
        {"Path": r"C:\Users\jcloudy\Desktop\Planning.docx", "EntryNumber": 1,
         "CreatedOn": "/Date(1522187139502)/", "LastModified": "/Date(1522917168677)/",
         "Hostname": "desktop-pm6c56d", "InteractionCount": 13, "MRUPosition": 0,
         "Pinned": False, "MacAddress": "28:e3:47:01:77:77", "VolumeDroid": "bc75"},
    ],
}


def test_flatten_and_dotnet_dates():
    flats = list(jlecmd.flatten(_RECORD))
    assert len(flats) == 1
    f = flats[0]
    assert f["AppDescription"] == "Microsoft Word 2016 64-bit"
    assert f["LastModified"].startswith("2018-04-05T")     # /Date(ms)/ -> ISO
    assert f["CreatedOn"].startswith("2018-03-27T")
    assert list(jlecmd.flatten({"AppId": {}, "DestListEntries": []})) == []


def test_dest_entry_is_file_read():
    ev = normalize.normalize("jlecmd_dest", next(jlecmd.flatten(_RECORD)))
    assert ev["car_object"] == "file" and ev["car_action"] == "read"
    assert ev["file_name"] == "Planning.docx" and ev["extension"] == "docx"
    assert ev["hostname"] == "desktop-pm6c56d"
    assert ev["source_host"] == "desktop-pm6c56d"
    assert ev["_native"]["InteractionCount"] == 13
    assert ev["_native"]["AppDescription"] == "Microsoft Word 2016 64-bit"
    assert ev["timestamp"].startswith("2018-04-05T")       # last interaction
