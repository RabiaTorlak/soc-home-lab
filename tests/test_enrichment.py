"""enrichment: özel IP tespiti ve tehdit kararı (verdict) testleri."""
import logging
import enrichment as e

log = logging.getLogger("test")


def test_is_private():
    assert e._is_private("192.168.1.1")
    assert e._is_private("10.0.0.5")
    assert e._is_private("127.0.0.1")
    assert not e._is_private("8.8.8.8")


def test_verdict_thresholds():
    assert e._verdict(0, 0, 0) == "clean"
    assert e._verdict(30, 0, 0) == "suspicious"
    assert e._verdict(90, 0, 0) == "malicious"
    assert e._verdict(0, 3, 0) == "malicious"
    assert e._verdict(0, 1, 0) == "suspicious"
    assert e._verdict(0, 0, 5) == "malicious"


def test_verdict_greynoise():
    assert e._verdict(0, 0, 0, "malicious") == "malicious"
    assert e._verdict(0, 0, 0, "benign") == "clean"
    assert e._verdict(0, 0, 0, "unknown") == "clean"


def test_enrich_private_ip_is_lab():
    cfg = {"enrichment": {}, "actions": {}}
    r = e.enrich("192.168.222.128", cfg, log)
    assert r["verdict"] == "lab_internal"
    assert r["ip"] == "192.168.222.128"
    assert r["abuse_confidence_score"] == 0
