"""generate_attack_navigator: katman üretimi testleri."""
import generate_attack_navigator as nav


def test_build_layer_dedup_and_max_score():
    entries = [("T1110", 10, "5712 — brute"),
               ("T1110", 12, "other rule"),
               ("T1059.001", 12, "100101 — ps")]
    layer = nav.build_layer(entries)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110", "T1059.001"} <= ids

    t1110 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1110")
    assert t1110["score"] == 12          # iki kuraldan yüksek seviye
    assert "5712 — brute" in t1110["comment"]


def test_layer_has_navigator_metadata():
    layer = nav.build_layer([("T1016", 6, "100112 — net discovery")])
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
