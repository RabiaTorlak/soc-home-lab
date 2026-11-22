"""generate_ir_report: rapor üretimi testleri."""
import generate_ir_report as ir


def test_empty_report():
    out = ir.build_report([], "test kapsamı")
    assert "vaka bulunamadı" in out


def test_report_sections_and_content():
    cases = [{
        "case_id": "CASE-20261121-140000-5712",
        "received_at": "2026-11-21T14:00:00+00:00",
        "rule": {"id": "5712", "level": 10, "description": "brute force", "mitre": ["T1110"]},
        "agent": {"name": "soc-server", "ip": "192.168.222.130"},
        "src_ip": "192.168.222.128",
        "actions_taken": ["iptables_block:ok", "telegram_notify"],
        "enrichment": {"verdict": "lab_internal"},
    }]
    out = ir.build_report(cases, "Tüm vakalar")
    for expected in ("Yönetici Özeti", "Zaman Çizelgesi", "T1110",
                     "192.168.222.128", "5712", "iptables_block:ok"):
        assert expected in out


def test_mitre_helper_normalizes_list():
    assert ir._mitre({"rule": {"mitre": ["T1110"]}}) == ["T1110"]
