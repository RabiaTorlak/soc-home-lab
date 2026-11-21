# -*- coding: utf-8 -*-
"""
SOAR aksiyonları: engelleme, Active Response, bildirim.
"""

import subprocess
import threading
import json
import requests

requests.packages.urllib3.disable_warnings()  # self-signed uyarılarını sustur


# ----------------------------------------------------------------------
# 1) SOC sunucusunda yerel iptables engelleme
# ----------------------------------------------------------------------
def iptables_block(ip, duration_minutes, log, dry_run=False):
    """Saldırgan IP'yi iptables INPUT zincirinde DROP eder.
    duration_minutes > 0 ise süre sonunda kuralı otomatik kaldırır."""
    rule = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    if dry_run:
        log.info("[DRY-RUN] iptables engelleme: %s", ip)
        return True
    try:
        # Zaten varsa tekrar ekleme
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True)
        if check.returncode != 0:
            subprocess.run(rule, check=True, capture_output=True)
            log.info("iptables: %s ENGELLENDİ.", ip)
        else:
            log.info("iptables: %s zaten engelli.", ip)

        if duration_minutes and duration_minutes > 0:
            t = threading.Timer(duration_minutes * 60, _iptables_unblock, args=(ip, log))
            t.daemon = True
            t.start()
            log.info("iptables: %s kuralı %s dk sonra kaldırılacak.", ip, duration_minutes)
        return True
    except subprocess.CalledProcessError as e:
        log.error("iptables engelleme hatası (%s): %s", ip, e.stderr.decode(errors="ignore"))
        return False


def _iptables_unblock(ip, log):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, capture_output=True)
        log.info("iptables: %s engeli SÜRE DOLDU, kaldırıldı.", ip)
    except subprocess.CalledProcessError as e:
        log.error("iptables engel kaldırma hatası (%s): %s", ip, e)


# ----------------------------------------------------------------------
# 2) Wazuh API üzerinden Active Response (hedef agent'ta firewall-drop)
# ----------------------------------------------------------------------
def _wazuh_token(cfg, log):
    w = cfg["wazuh"]
    try:
        r = requests.post(
            f"{w['api_url']}/security/user/authenticate",
            auth=(w["api_user"], w["api_password"]),
            verify=w.get("verify_ssl", False), timeout=10)
        r.raise_for_status()
        return r.json()["data"]["token"]
    except Exception as e:
        log.error("Wazuh API token alınamadı: %s", e)
        return None


def wazuh_active_response(ip, agent_id, cfg, log, dry_run=False):
    """Belirtilen agent'ta firewall-drop Active Response komutunu çalıştırır."""
    if dry_run:
        log.info("[DRY-RUN] Wazuh AR: agent=%s ip=%s", agent_id, ip)
        return True

    token = _wazuh_token(cfg, log)
    if not token:
        return False

    w = cfg["wazuh"]
    cmd = cfg["actions"].get("active_response_command", "firewall-drop0")
    # Wazuh 4.x Active Response API formatı
    payload = {
        "command": cmd,
        "arguments": [ip],
        "alert": {"data": {"srcip": ip}},
    }
    try:
        r = requests.put(
            f"{w['api_url']}/active-response",
            params={"agents_list": str(agent_id)},
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            data=json.dumps(payload),
            verify=w.get("verify_ssl", False), timeout=10)
        if r.status_code in (200, 201):
            log.info("Wazuh AR: agent %s üzerinde %s -> %s tetiklendi.", agent_id, cmd, ip)
            return True
        log.error("Wazuh AR başarısız (%s): %s", r.status_code, r.text[:300])
        return False
    except Exception as e:
        log.error("Wazuh AR isteği hatası: %s", e)
        return False


# ----------------------------------------------------------------------
# 3) Telegram bildirimi
# ----------------------------------------------------------------------
def telegram_notify(case, cfg, log, dry_run=False):
    tg = cfg["telegram"]
    enr = case.get("enrichment", {})
    score = enr.get("abuse_confidence_score", "N/A")
    country = enr.get("country_code", "N/A")
    verdict = str(enr.get("verdict", "N/A")).upper()
    vt = enr.get("vt_malicious", "N/A")
    otx = enr.get("otx_pulses", "N/A")

    msg = (
        "🚨 *SOC SOAR ALARM*\n"
        f"*Vaka:* `{case['case_id']}`\n"
        f"*Kural:* {case['rule']['id']} (seviye {case['rule']['level']})\n"
        f"*Açıklama:* {case['rule']['description']}\n"
        f"*MITRE:* {', '.join(case['rule'].get('mitre', []) or ['-'])}\n"
        f"*Agent:* {case['agent'].get('name')}\n"
        f"*Saldırgan IP:* `{case.get('src_ip') or '-'}`\n"
        f"*Tehdit Kararı:* {verdict}\n"
        f"*IOC:* AbuseIPDB={score} · VT_mal={vt} · OTX={otx} · ülke={country}\n"
        f"*Aksiyonlar:* {', '.join(case['actions_taken']) or '-'}"
    )

    if dry_run:
        log.info("[DRY-RUN] Telegram mesajı:\n%s", msg)
        return True
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage",
            data={"chat_id": tg["chat_id"], "text": msg, "parse_mode": "Markdown"},
            timeout=10)
        if r.status_code == 200:
            log.info("Telegram bildirimi gönderildi.")
            return True
        log.error("Telegram hatası (%s): %s", r.status_code, r.text[:200])
        return False
    except Exception as e:
        log.error("Telegram isteği hatası: %s", e)
        return False


# ----------------------------------------------------------------------
# 4) Discord webhook bildirimi (renk kodlu embed, verdict'e göre)
# ----------------------------------------------------------------------
def discord_notify(case, cfg, log, dry_run=False):
    url = cfg.get("discord", {}).get("webhook_url", "")
    if not url or url == "CHANGE_ME":
        log.info("Discord webhook tanimli degil, atlandi.")
        return False

    enr = case.get("enrichment", {})
    verdict = str(enr.get("verdict", "N/A")).upper()
    colors = {"MALICIOUS": 0xE01030, "SUSPICIOUS": 0xEA580C,
              "CLEAN": 0x16A34A, "LAB_INTERNAL": 0x2563EB}

    embed = {
        "title": "🚨 SOC SOAR ALARM",
        "description": case["rule"]["description"],
        "color": colors.get(verdict, 0x64748B),
        "fields": [
            {"name": "Vaka", "value": case["case_id"], "inline": False},
            {"name": "Kural", "value": f"{case['rule']['id']} (seviye {case['rule']['level']})", "inline": True},
            {"name": "Tehdit Kararı", "value": verdict, "inline": True},
            {"name": "Saldırgan IP", "value": str(case.get("src_ip") or "-"), "inline": True},
            {"name": "MITRE", "value": ", ".join(case["rule"].get("mitre", []) or ["-"]), "inline": True},
            {"name": "Agent", "value": str(case["agent"].get("name")), "inline": True},
            {"name": "IOC",
             "value": (f"AbuseIPDB={enr.get('abuse_confidence_score', 'N/A')} · "
                       f"VT_mal={enr.get('vt_malicious', 'N/A')} · "
                       f"OTX={enr.get('otx_pulses', 'N/A')}"),
             "inline": False},
            {"name": "Aksiyonlar", "value": ", ".join(case["actions_taken"]) or "-", "inline": False},
        ],
    }

    if dry_run:
        log.info("[DRY-RUN] Discord embed (verdict=%s)", verdict)
        return True
    try:
        r = requests.post(url, json={"embeds": [embed]}, timeout=10)
        if r.status_code in (200, 204):
            log.info("Discord bildirimi gonderildi.")
            return True
        log.error("Discord hatasi (%s): %s", r.status_code, r.text[:200])
        return False
    except Exception as e:
        log.error("Discord istegi hatasi: %s", e)
        return False
