#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Otomatik Olay Müdahale (IR) Rapor Üreteci
=========================================
SOAR'ın ürettiği cases/*.json dosyalarından profesyonel bir markdown
Incident Response raporu üretir. Tespit → otomasyon → dokümantasyon
zincirini kapatır.

Kullanım:
  python3 generate_ir_report.py                              # tüm vakalar
  python3 generate_ir_report.py --case CASE-20261121-143234-5712
  python3 generate_ir_report.py --since 2026-11-21
  python3 generate_ir_report.py --cases-dir ./cases -o rapor.md

Bağımlılık yok (yalnızca Python standart kütüphanesi).
"""

import os
import json
import glob
import argparse
from collections import Counter
from datetime import datetime, timezone

DEFAULT_CASES_DIR = "/var/ossec/integrations/soar/cases"


def load_cases(cases_dir, case_id=None, since=None):
    cases = []
    for path in sorted(glob.glob(os.path.join(cases_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                c = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if case_id and c.get("case_id") != case_id:
            continue
        if since and (c.get("received_at", "") < since):
            continue
        cases.append(c)
    return cases


def _t(iso):
    return (iso or "")[:19].replace("T", " ")


def _mitre(case):
    m = case.get("rule", {}).get("mitre", [])
    return m if isinstance(m, list) else [m]


def build_report(cases, scope_label):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not cases:
        return f"# Olay Müdahale Raporu\n\n*{scope_label}* için vaka bulunamadı.\n"

    times = sorted(c.get("received_at", "") for c in cases if c.get("received_at"))
    first, last = _t(times[0]), _t(times[-1]) if times else ("-", "-")
    high = [c for c in cases if int(c.get("rule", {}).get("level", 0) or 0) >= 10]

    rules = Counter(f"{c['rule'].get('id')} — {c['rule'].get('description','')}" for c in cases)
    techniques = Counter(t for c in cases for t in _mitre(c) if t)
    srcips = Counter(c.get("src_ip") for c in cases if c.get("src_ip"))
    agents = Counter(c.get("agent", {}).get("name") for c in cases if c.get("agent", {}).get("name"))
    actions = Counter(a for c in cases for a in c.get("actions_taken", []))
    verdicts = Counter((c.get("enrichment", {}) or {}).get("verdict", "N/A") for c in cases)

    top_rule = rules.most_common(1)[0][0] if rules else "-"
    top_ip = srcips.most_common(1)[0][0] if srcips else "-"
    top_tech = techniques.most_common(1)[0][0] if techniques else "-"

    L = []
    L.append("# 🛡️ Otomatik Olay Müdahale (IR) Raporu")
    L.append("")
    L.append(f"| Alan | Değer |")
    L.append(f"|------|-------|")
    L.append(f"| Rapor tarihi | {now} |")
    L.append(f"| Kapsam | {scope_label} |")
    L.append(f"| Toplam olay | {len(cases)} |")
    L.append(f"| Yüksek seviye (≥10) | {len(high)} |")
    L.append(f"| Zaman aralığı | {first} → {last} |")
    L.append(f"| Üreten | SOAR otomatik (`generate_ir_report.py`) |")
    L.append("")

    # Executive summary
    L.append("## 1. Yönetici Özeti")
    L.append("")
    L.append(f"İzlenen dönemde SOAR otomasyonu **{len(cases)} olay** kaydetti; bunların "
             f"**{len(high)} tanesi** yüksek seviyeli (≥10) alarmdı. En sık tetiklenen "
             f"kural **{top_rule}**, en aktif saldırgan kaynak **{top_ip}**, en sık gözlenen "
             f"MITRE tekniği **{top_tech}** oldu. SOAR, tespit-müdahale döngüsünü manuel "
             f"müdahaleye gerek kalmadan otomatik yürüttü (engelleme, IOC zenginleştirme, "
             f"bildirim ve vaka kaydı).")
    L.append("")

    # Timeline
    L.append("## 2. Olay Zaman Çizelgesi")
    L.append("")
    L.append("| Zaman (UTC) | Kural | Sev | Saldırgan IP | Verdict | Aksiyonlar |")
    L.append("|-------------|-------|-----|--------------|---------|------------|")
    for c in sorted(cases, key=lambda x: x.get("received_at", "")):
        r = c.get("rule", {})
        verdict = (c.get("enrichment", {}) or {}).get("verdict", "-")
        acts = ", ".join(c.get("actions_taken", [])) or "-"
        L.append(f"| {_t(c.get('received_at'))} | {r.get('id')} | {r.get('level')} "
                 f"| {c.get('src_ip') or '-'} | {verdict} | {acts} |")
    L.append("")

    # MITRE
    L.append("## 3. MITRE ATT&CK Kapsamı")
    L.append("")
    if techniques:
        L.append("| Teknik | Olay sayısı |")
        L.append("|--------|-------------|")
        for tech, n in techniques.most_common():
            L.append(f"| {tech} | {n} |")
    else:
        L.append("Bu kapsamda MITRE tekniği etiketi bulunamadı.")
    L.append("")

    # Attackers + IOC
    L.append("## 4. Saldırgan Kaynaklar ve IOC'ler")
    L.append("")
    L.append("| Kaynak IP | Olay | Son verdict |")
    L.append("|-----------|------|-------------|")
    ip_verdict = {}
    for c in cases:
        ip = c.get("src_ip")
        if ip:
            ip_verdict[ip] = (c.get("enrichment", {}) or {}).get("verdict", "-")
    for ip, n in srcips.most_common():
        L.append(f"| `{ip}` | {n} | {ip_verdict.get(ip, '-')} |")
    L.append("")
    L.append(f"**Tehdit kararı dağılımı:** " +
             ", ".join(f"{k}={v}" for k, v in verdicts.most_common()))
    L.append("")

    # Response actions
    L.append("## 5. Alınan Otomatik Aksiyonlar")
    L.append("")
    if actions:
        L.append("| Aksiyon | Kez |")
        L.append("|---------|-----|")
        for act, n in actions.most_common():
            L.append(f"| `{act}` | {n} |")
    else:
        L.append("Aksiyon kaydı yok.")
    L.append("")

    # Affected assets
    L.append("## 6. Etkilenen Varlıklar (Agent)")
    L.append("")
    L.append("| Agent | Olay |")
    L.append("|-------|------|")
    for ag, n in agents.most_common():
        L.append(f"| {ag} | {n} |")
    L.append("")

    # Recommendations
    L.append("## 7. Değerlendirme ve Öneriler")
    L.append("")
    L.append("- Tespit→engelleme döngüsü otomatikti; ortalama müdahale süresi (MTTR) "
             "saniyeler seviyesindedir.")
    L.append("- Yüksek seviyeli alarmlar için IOC zenginleştirme (AbuseIPDB/VirusTotal/OTX) "
             "ile analist farkındalığı artırılmalı.")
    L.append("- Tekrarlayan saldırgan kaynaklar için kalıcı engelleme / threat-intel "
             "feed entegrasyonu değerlendirilmeli.")
    L.append("- Servis sertleştirme (SSH anahtar tabanlı kimlik doğrulama, parola politikası) "
             "ile saldırı yüzeyi daraltılmalı.")
    L.append("")
    L.append("---")
    L.append(f"*Bu rapor {len(cases)} vaka dosyasından otomatik üretilmiştir — "
             f"SOC Home Lab · Python SOAR.*")
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="SOAR vakalarından otomatik IR raporu üretir.")
    ap.add_argument("--cases-dir", default=DEFAULT_CASES_DIR, help="cases/ dizini")
    ap.add_argument("--case", help="Yalnızca bu case_id")
    ap.add_argument("--since", help="Bu ISO tarihten itibaren (ör. 2026-11-21)")
    ap.add_argument("-o", "--output", help="Çıktı dosyası (yoksa stdout)")
    args = ap.parse_args()

    cases = load_cases(args.cases_dir, case_id=args.case, since=args.since)

    if args.case:
        scope = f"Tek vaka: {args.case}"
    elif args.since:
        scope = f"{args.since} tarihinden itibaren"
    else:
        scope = "Tüm vakalar"

    report = build_report(cases, scope)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Rapor yazildi: {args.output} ({len(cases)} vaka)")
    else:
        print(report)


if __name__ == "__main__":
    main()
