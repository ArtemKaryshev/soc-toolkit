from soc_toolkit import reference as ref
from soc_toolkit.reference.updater import convert_lolbas_api, convert_mitre


def test_events():
    assert ref.search_events("4625")[0]["title"] == "Неудачный вход"
    assert all(e["log"] == "Sysmon" for e in ref.search_events("", "Sysmon"))
    assert any(e["id"] == 10 for e in ref.search_events("lsass"))
    assert len(ref.eventids()["events"]) >= 100


def test_mitre():
    assert len(ref.mitre()["techniques"]) > 600
    assert ref.technique_name("t1059.001") == "Command and Scripting Interpreter: PowerShell"
    ids = [t["id"] for t in ref.search_techniques("T1003")]
    assert ids[0] == "T1003" and "T1003.001" in ids
    assert ref.search_techniques("phishing")[0]["full_name"].startswith("Phishing")
    assert all("credential-access" in t["tactics"] for t in ref.search_techniques("", "credential-access"))


def test_lolbas_and_groups():
    assert len(ref.lolbas()) > 200
    assert ref.search_lolbas("certutil")[0]["name"].lower() == "certutil.exe"
    assert any("APT29" in g["name"] or "APT29" in g["aliases"] for g in ref.search_groups("apt29"))


def test_convert_mitre_minimal():
    bundle = {"objects": [
        {"type": "attack-pattern", "name": "Parent", "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1000", "url": "u"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
         "description": "Text (Citation: X) with [link](http://a)."},
        {"type": "attack-pattern", "name": "Child", "x_mitre_is_subtechnique": True, "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1000.001"}]},
        {"type": "attack-pattern", "name": "Old", "revoked": True, "external_references": [
            {"source_name": "mitre-attack", "external_id": "T9999"}]},
        {"type": "x-mitre-matrix", "modified": "2026-01-02T00:00:00Z"},
    ]}
    data = convert_mitre(bundle)
    assert [t["id"] for t in data["techniques"]] == ["T1000", "T1000.001"]
    assert data["techniques"][1]["full_name"] == "Parent: Child"
    assert data["techniques"][0]["description"] == "Text with link."
    assert data["version"] == "2026-01-02"


def test_convert_lolbas_api():
    out = convert_lolbas_api([{"Name": "Foo.exe", "Description": "d", "url": "https://x/lolbas/Binaries/Foo/",
                               "Commands": [{"Command": "foo -x", "Category": "Download", "MitreID": "T1105"}],
                               "Full_Path": [{"Path": "C:\\foo.exe"}], "Detection": [{"Sigma": "https://s"}]}])
    assert out[0]["categories"] == ["Download"] and out[0]["mitre"] == ["T1105"]
    assert out[0]["paths"] == ["C:\\foo.exe"] and out[0]["detection"] == ["Sigma: https://s"]
