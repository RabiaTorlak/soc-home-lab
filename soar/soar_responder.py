#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Lab - Python SOAR Responder
================================
Wazuh Manager'ın ürettiği alerts.json dosyasını canlı olarak izler (tail -f).
Yüksek seviyeli / belirli kurallara eşleşen uyarılarda otomatik aksiyon alır:

  1. Saldırgan IP'yi SOC sunucusunda iptables ile engeller
  2. Wazuh API üzerinden hedef agent'ta firewall-drop (Active Response) çalıştırır
  3. IOC zenginleştirmesi yapar (AbuseIPDB)
  4. Telegram'a bildirim gönderir
  5. Her olay için JSON vaka (case) kaydı oluşturur

Kullanım:
    sudo python3 soar_responder.py --config config.yaml

Yazar: <senin adın> | Junior Blue Team / SOC Analyst Portfolio
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime, timezone

import yaml

import actions
import enrichment


# ----------------------------------------------------------------------
# Yapılandırma & Log
# ----------------------------------------------------------------------
def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("soar")


# ----------------------------------------------------------------------
# Uyarı okuma (dosyayı canlı takip et)
# ----------------------------------------------------------------------
def follow(path, log):
    """alerts.json dosyasını 'tail -f' gibi satır satır okur, rotasyona dayanıklıdır."""
    while not os.path.exists(path):
        log.warning("Uyarı dosyası henüz yok, bekleniyor: %s", path)
        time.sleep(2)

    f = open(path, "r", encoding="utf-8", errors="ignore")
    f.seek(0, os.SEEK_END)          # yalnızca YENİ uyarıları işle
    inode = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()
        if line:
            yield line
            continue
        # Yeni satır yok -> rotasyon olmuş mu kontrol et
        time.sleep(0.5)
        try:
            if os.stat(path).st_ino != inode:
                log.info("Log rotasyonu algılandı, dosya yeniden açılıyor.")
                f.close()
                f = open(path, "r", encoding="utf-8", errors="ignore")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            time.sleep(1)


# ----------------------------------------------------------------------
# Karar mantığı
# ----------------------------------------------------------------------
def should_act(alert, cfg):
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))
    rule_id = str(rule.get("id", ""))

    trig = cfg["triggers"]
    if rule_id in [str(r) for r in trig.get("always_rule_ids", [])]:
        return True
    return level >= int(trig["min_level"])


def extract_srcip(alert):
    """Uyarıdan saldırgan IP'sini çıkarmayı dener (farklı alanlarda olabilir)."""
    data = alert.get("data", {})
    for key in ("srcip", "src_ip", "source_ip"):
        if data.get(key):
            return data[key]
    # Windows olaylarında IP bazen iç içe alanlarda olur
    win = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
    for key in ("ipAddress", "IpAddress", "sourceAddress"):
        if win.get(key) and win[key] not in ("-", "::1"):
            return win[key]
    return None


# ----------------------------------------------------------------------
# Ana döngü
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SOC Lab Python SOAR Responder")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="Aksiyon alma, sadece ne yapacağını logla")
    args = parser.parse_args()

    cfg = load_config(args.config)
    log = setup_logging(cfg["output"]["log_file"])
    os.makedirs(cfg["output"]["cases_dir"], exist_ok=True)

    whitelist = set(cfg["triggers"].get("whitelist_ips", []))
    seen_ips = {}   # IP -> son aksiyon zamanı (aynı IP için spam engelle)
    dedup_window = 120  # saniye

    log.info("=" * 60)
    log.info("SOC Lab Python SOAR başlatıldı. Dry-run=%s", args.dry_run)
    log.info("İzlenen dosya: %s", cfg["wazuh"]["alerts_file"])
    log.info("Min seviye: %s | Her zaman: %s",
             cfg["triggers"]["min_level"], cfg["triggers"]["always_rule_ids"])
    log.info("=" * 60)

    for line in follow(cfg["wazuh"]["alerts_file"], log):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not should_act(alert, cfg):
            continue

        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        level = rule.get("level")
        desc = rule.get("description", "")
        mitre = rule.get("mitre", {}).get("id", [])
        agent = alert.get("agent", {})
        srcip = extract_srcip(alert)

        log.warning("[ALARM] id=%s lvl=%s mitre=%s agent=%s src=%s :: %s",
                    rule_id, level, mitre, agent.get("name"), srcip, desc)

        # ---- Vaka kaydı başlat ----
        case = {
            "case_id": datetime.now(timezone.utc).strftime("CASE-%Y%m%d-%H%M%S-") + rule_id,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": rule_id, "level": level, "description": desc, "mitre": mitre},
            "agent": {"name": agent.get("name"), "ip": agent.get("ip")},
            "src_ip": srcip,
            "actions_taken": [],
            "enrichment": {},
            "raw_alert": alert,
        }

        # ---- IP yoksa sadece bildir ----
        if not srcip:
            log.info("Kaynak IP bulunamadı, yalnızca bildirim yapılacak.")
        elif srcip in whitelist:
            log.info("IP beyaz listede (%s), engellenmeyecek.", srcip)
            case["actions_taken"].append("skipped_whitelisted")
        else:
            now = time.time()
            if srcip in seen_ips and (now - seen_ips[srcip]) < dedup_window:
                log.info("IP %s zaten yakın zamanda işlendi, tekrar aksiyon alınmadı.", srcip)
                case["actions_taken"].append("skipped_deduplicated")
            else:
                seen_ips[srcip] = now

                # 1) IOC zenginleştirme (çoklu kaynak: AbuseIPDB + VirusTotal + OTX)
                if any(cfg["actions"].get(k) for k in
                       ("enrich_abuseipdb", "enrich_virustotal", "enrich_otx")):
                    case["enrichment"] = enrichment.enrich(srcip, cfg, log)

                # 2) Yerel iptables engelleme
                if cfg["actions"].get("local_iptables_block"):
                    ok = actions.iptables_block(
                        srcip,
                        cfg["actions"].get("block_duration_minutes", 60),
                        log, dry_run=args.dry_run)
                    case["actions_taken"].append(
                        f"iptables_block:{'ok' if ok else 'fail'}")

                # 3) Wazuh Active Response (hedef agent'ta engelle)
                if cfg["actions"].get("wazuh_active_response") and agent.get("id"):
                    ok = actions.wazuh_active_response(
                        srcip, agent.get("id"), cfg, log, dry_run=args.dry_run)
                    case["actions_taken"].append(
                        f"wazuh_ar:{'ok' if ok else 'fail'}")

        # ---- 4) Bildirimler (Telegram + Discord) ----
        if cfg["actions"].get("notify_telegram"):
            actions.telegram_notify(case, cfg, log, dry_run=args.dry_run)
            case["actions_taken"].append("telegram_notify")

        if cfg["actions"].get("notify_discord"):
            actions.discord_notify(case, cfg, log, dry_run=args.dry_run)
            case["actions_taken"].append("discord_notify")

        # ---- Vakayı diske yaz ----
        case_path = os.path.join(cfg["output"]["cases_dir"], case["case_id"] + ".json")
        try:
            with open(case_path, "w", encoding="utf-8") as cf:
                json.dump(case, cf, indent=2, ensure_ascii=False)
            log.info("Vaka kaydedildi: %s", case_path)
        except OSError as e:
            log.error("Vaka yazılamadı: %s", e)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSOAR durduruldu.")
