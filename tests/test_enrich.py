from casebook.enrich import Context, enrich
from casebook.models import Alert, load_alert
from conftest import SAMPLE_ALERT


def test_known_user_and_ip_are_enriched():
    e = enrich(load_alert(SAMPLE_ALERT), Context.load())
    (user,) = e["users"]
    assert user["found"] and user["title"] == "Contracts Manager"
    assert user["alert_ips_not_known_for_user"] == ["203.0.113.7"]
    assert user["alert_countries_outside_usual"] == ["NL"]
    (ip,) = e["ips"]
    assert ip["found"] and ip["reputation"] == "suspicious"


def test_unknown_entities_are_reported_not_dropped():
    data = load_alert(SAMPLE_ALERT).model_dump(mode="json")
    data["entities"] = {
        "users": ["ghost@harborline.example"],
        "ips": ["192.0.2.200"],
        "apps": ["00000000-0000-0000-0000-000000000000"],
    }
    e = enrich(Alert.model_validate(data), Context.load())
    assert e["users"] == [{"upn": "ghost@harborline.example", "found": False}]
    assert e["ips"] == [{"ip": "192.0.2.200", "found": False}]
    assert e["apps"] == [{"app_id": "00000000-0000-0000-0000-000000000000", "found": False}]


def test_enrichment_is_deterministic():
    alert = load_alert(SAMPLE_ALERT)
    assert enrich(alert, Context.load()) == enrich(alert, Context.load())
