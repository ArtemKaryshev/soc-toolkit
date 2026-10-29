from pathlib import Path

import pytest

from soc_toolkit.cases import Case, CaseStore
from soc_toolkit.ioc import extract


@pytest.fixture
def store(tmp_path):
    return CaseStore(Path(tmp_path) / "cases.sqlite")


def test_save_get_update(store):
    cid = store.save(Case(title="Алерт", verdict="TP", tags=["phish"]), extract("evil.com 8.8.8.8"))
    c = store.get(cid)
    assert c.title == "Алерт" and c.tags == ["phish"] and c.status == "open"
    c.notes = "проверено"
    store.save(c)
    assert store.get(cid).notes == "проверено"
    assert {i["value"] for i in store.iocs(cid)} == {"evil.com", "8.8.8.8"}


def test_sightings_and_search(store):
    a = store.save(Case(title="A", verdict="TP"), extract("evil.com"))
    b = store.save(Case(title="B", verdict="FP"), extract("EVIL.com other.org"))
    assert store.sightings(["evil.com"], exclude_case=b) == {"evil.com": [a]}
    assert [c.id for c in store.search("evil.com")] == [b, a]
    assert [c.id for c in store.search(verdict="FP")] == [b]


def test_status_delete_stats_export(store):
    cid = store.save(Case(title="A", verdict="TP", escalated=True), extract("evil.com"))
    store.save(Case(title="B", verdict="TP"), extract("evil.com"))
    store.set_status(cid, "closed")
    with pytest.raises(ValueError):
        store.set_status(cid, "weird")
    st = store.stats()
    assert st["total"] == 2 and st["open"] == 1 and st["escalated"] == 1
    assert st["top_iocs"][0]["value"] == "evil.com"
    assert '"iocs"' in store.export_json()
    assert store.delete(cid) and store.get(cid) is None
    assert store.iocs(cid) == []   # ON DELETE CASCADE
