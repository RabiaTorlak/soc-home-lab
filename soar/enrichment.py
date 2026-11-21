# -*- coding: utf-8 -*-
"""
IOC zenginleştirme modülü.
AbuseIPDB üzerinden saldırgan IP itibar sorgusu yapar.
"""

import requests

requests.packages.urllib3.disable_warnings()


def abuseipdb_lookup(ip, cfg, log):
    """AbuseIPDB'den IP itibar bilgisi çeker. Lab IP'leri için skor 0 döner,
    bu normaldir — asıl amaç gerçek IOC akışını göstermektir."""
    key = cfg["enrichment"].get("abuseipdb_api_key", "")
    if not key or key == "CHANGE_ME":
        log.info("AbuseIPDB anahtarı tanımlı değil, zenginleştirme atlandı.")
        return {"note": "no_api_key"}

    # Özel/yerel IP aralıklarını sorgulama (AbuseIPDB reddeder)
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "127.")):
        log.info("AbuseIPDB: %s özel IP, gerçek sorgu atlandı (lab ortamı).", ip)
        return {"note": "private_ip_lab", "ip": ip, "abuse_confidence_score": 0}

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip,
                    "maxAgeInDays": cfg["enrichment"].get("abuseipdb_max_age_days", 90)},
            timeout=10)
        r.raise_for_status()
        d = r.json().get("data", {})
        result = {
            "ip": ip,
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "total_reports": d.get("totalReports"),
            "is_tor": d.get("isTor"),
        }
        log.info("AbuseIPDB: %s skor=%s ülke=%s rapor=%s",
                 ip, result["abuse_confidence_score"],
                 result["country_code"], result["total_reports"])
        return result
    except Exception as e:
        log.error("AbuseIPDB sorgu hatası (%s): %s", ip, e)
        return {"note": "lookup_failed", "ip": ip}
