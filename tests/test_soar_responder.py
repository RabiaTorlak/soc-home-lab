"""soar_responder: IP çıkarma ve karar mantığı testleri."""
import soar_responder as sr


def test_extract_srcip_direct():
    assert sr.extract_srcip({"data": {"srcip": "1.2.3.4"}}) == "1.2.3.4"


def test_extract_srcip_windows_eventdata():
    alert = {"data": {"win": {"eventdata": {"ipAddress": "5.6.7.8"}}}}
    assert sr.extract_srcip(alert) == "5.6.7.8"


def test_extract_srcip_ignores_placeholder():
    alert = {"data": {"win": {"eventdata": {"ipAddress": "-"}}}}
    assert sr.extract_srcip(alert) is None


def test_extract_srcip_none():
    assert sr.extract_srcip({"data": {}}) is None


def test_should_act_by_level():
    cfg = {"triggers": {"min_level": 7, "always_rule_ids": []}}
    assert sr.should_act({"rule": {"level": 10, "id": "5712"}}, cfg) is True
    assert sr.should_act({"rule": {"level": 3, "id": "999"}}, cfg) is False


def test_should_act_always_rule_overrides_level():
    cfg = {"triggers": {"min_level": 7, "always_rule_ids": ["100101"]}}
    assert sr.should_act({"rule": {"level": 1, "id": "100101"}}, cfg) is True
