#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Navigator Katman Üreteci
=====================================
rules/local_rules.xml dosyasını (ve projenin belgelenmiş temel kurallarını)
okuyup, hangi ATT&CK tekniklerini tespit ettiğini gösteren bir Navigator
katman (layer) JSON'u üretir.

Çıktıyı https://mitre-attack.github.io/attack-navigator/ adresinde
"Open Existing Layer → Upload from local" ile yükleyip renkli kapsama
matrisini görebilirsin.

Kullanım:
  python3 generate_attack_navigator.py                 # docs/attack-navigator-layer.json
  python3 generate_attack_navigator.py -r rules/local_rules.xml -o layer.json

Bağımlılık yok (yalnızca Python standart kütüphanesi).
"""

import os
import json
import argparse
import xml.etree.ElementTree as ET

# Projede tanımlı ama bu XML dosyasında olmayan (temel/Wazuh) tespitler
EXTRA_RULES = [
    ("T1059.001", 12, "100101 — Encoded PowerShell"),
    ("T1082", 10, "100102 — System Information Discovery (recon)"),
    ("T1110", 10, "Wazuh 5712 — SSH/RDP Brute-Force"),
    ("T1046", 10, "Wazuh — Network Service Scanning"),
]


def parse_rules(xml_path):
    """local_rules.xml'den (teknik, seviye, açıklama) üçlülerini çıkarır."""
    found = []
    try:
        root = ET.parse(xml_path).getroot()
    except (OSError, ET.ParseError) as e:
        print(f"[!] XML okunamadi ({xml_path}): {e}")
        return found
    for rule in root.iter("rule"):
        rid = rule.get("id", "?")
        try:
            level = int(rule.get("level", 0))
        except ValueError:
            level = 0
        desc = (rule.findtext("description") or "").strip()
        for mid in rule.findall("mitre/id"):
            if mid.text:
                found.append((mid.text.strip(), level, f"{rid} — {desc}"))
    return found


def build_layer(entries):
    """Teknik bazında birleştirir ve Navigator layer JSON'u kurar."""
    agg = {}   # technique -> {"score": maxlevel, "comments": [..]}
    for tech, level, comment in entries:
        a = agg.setdefault(tech, {"score": 0, "comments": []})
        a["score"] = max(a["score"], level)
        if comment not in a["comments"]:
            a["comments"].append(comment)

    techniques = []
    for tech, a in sorted(agg.items()):
        techniques.append({
            "techniqueID": tech,
            "score": a["score"],
            "comment": " | ".join(a["comments"]),
            "enabled": True,
        })

    max_score = max((t["score"] for t in techniques), default=12)
    return {
        "name": "SOC Home Lab — Tespit Kapsamı",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Wazuh SIEM + Python SOAR ev laboratuvarının MITRE ATT&CK "
                       "tespit kapsamı. Skor = tespit kuralının Wazuh seviyesi.",
        "sorting": 3,
        "hideDisabled": True,
        "techniques": techniques,
        "gradient": {
            "colors": ["#fff5f0", "#fb6a4a", "#a50f15"],
            "minValue": 1,
            "maxValue": max(max_score, 2),
        },
        "legendItems": [
            {"label": "Düşük seviye tespit", "color": "#fff5f0"},
            {"label": "Yüksek seviye tespit", "color": "#a50f15"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
    }


def main():
    ap = argparse.ArgumentParser(description="ATT&CK Navigator katmanı üretir.")
    ap.add_argument("-r", "--rules", default="rules/local_rules.xml")
    ap.add_argument("-o", "--output", default="docs/attack-navigator-layer.json")
    args = ap.parse_args()

    entries = parse_rules(args.rules) + EXTRA_RULES
    layer = build_layer(entries)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2, ensure_ascii=False)

    print(f"[+] Navigator katmani yazildi: {args.output}")
    print(f"[+] {len(layer['techniques'])} teknik: "
          + ", ".join(t["techniqueID"] for t in layer["techniques"]))


if __name__ == "__main__":
    main()
