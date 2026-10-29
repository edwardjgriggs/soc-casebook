import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from casebook.models import Alert, load_alert, load_directory, load_ip_reputation

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests" / "fixtures" / "sample-alert.json"


def _sample() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def test_sample_alert_loads():
    alert = load_alert(SAMPLE)
    assert alert.detection.technique_id == "T1621"
    assert alert.entities.users == ["ada.marsh@harborline.example"]


def test_alert_rejects_real_world_ip():
    data = _sample()
    data["entities"]["ips"] = ["8.8.8.8"]
    with pytest.raises(ValidationError, match="RFC 5737"):
        Alert.model_validate(data)


def test_alert_rejects_outside_domain():
    data = _sample()
    data["entities"]["users"] = ["someone@aalismc.com"]
    with pytest.raises(ValidationError, match="harborline.example"):
        Alert.model_validate(data)


def test_alert_rejects_unknown_fields():
    data = _sample()
    data["surprise"] = True
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


def test_alert_requires_evidence():
    data = copy.deepcopy(_sample())
    data["evidence"] = []
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


def test_alert_rejects_bad_technique_id():
    data = _sample()
    data["detection"]["technique_id"] = "T16"
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


def test_directory_loads():
    directory = load_directory(ROOT / "context" / "directory.json")
    upns = {u.upn for u in directory.users}
    assert "ada.marsh@harborline.example" in upns
    assert any(u.is_admin for u in directory.users)


def test_ip_reputation_loads_and_is_unique():
    rep = load_ip_reputation(ROOT / "context" / "ip-reputation.json")
    ips = [r.ip for r in rep.records]
    assert len(ips) == len(set(ips))


def test_directory_known_ips_have_reputation():
    directory = load_directory(ROOT / "context" / "directory.json")
    rep = {r.ip for r in load_ip_reputation(ROOT / "context" / "ip-reputation.json").records}
    for user in directory.users:
        missing = set(user.known_ips) - rep
        assert not missing, f"{user.upn} has known IPs with no reputation record: {missing}"
