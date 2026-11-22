# -*- coding: utf-8 -*-
"""
IOC zenginleştirme modülü (çoklu kaynak).
AbuseIPDB + VirusTotal + AlienVault OTX sorgular, sonuçları birleştirip
tek bir tehdit kararı (verdict) üretir.

Lab/özel IP'ler için gerçek sorgu atlanır (skor 0) — bu normaldir; amaç
gerçek IOC akışını ve çoklu kaynak korelasyonunu göstermektir.
"""

import requests

requests.packages.urllib3.disable_warnings()

PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.2", "172.30.", "172.31.", "127.")


def _is_private(ip):
    return ip.startswith(PRIVATE_PREFIXES)


# ----------------------------------------------------------------------
# AbuseIPDB
# ----------------------------------------------------------------------
def abuseipdb_lookup(ip, cfg, log):
    key = cfg["enrichment"].get("abuseipdb_api_key", "")
    if not key or key == "CHANGE_ME":
        return {"note": "no_api_key"}
    if _is_private(ip):
        return {"note": "private_ip_lab", "abuse_confidence_score": 0}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip,
                    "maxAgeInDays": cfg["enrichment"].get("abuseipdb_max_age_days", 90)},
            timeout=10)
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "total_reports": d.get("totalReports"),
            "is_tor": d.get("isTor"),
        }
    except Exception as e:
        log.error("AbuseIPDB sorgu hatasi (%s): %s", ip, e)
        return {"note": "lookup_failed"}


# ----------------------------------------------------------------------
# VirusTotal (API v3)
# ----------------------------------------------------------------------
def virustotal_lookup(ip, cfg, log):
    key = cfg["enrichment"].get("virustotal_api_key", "")
    if not key or key == "CHANGE_ME":
        return {"note": "no_api_key"}
    if _is_private(ip):
        return {"note": "private_ip_lab", "vt_malicious": 0}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key}, timeout=15)
        r.raise_for_status()
        attr = r.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_reputation": attr.get("reputation"),
            "vt_as_owner": attr.get("as_owner"),
        }
    except Exception as e:
        log.error("VirusTotal sorgu hatasi (%s): %s", ip, e)
        return {"note": "lookup_failed"}


# ----------------------------------------------------------------------
# AlienVault OTX
# ----------------------------------------------------------------------
def otx_lookup(ip, cfg, log):
    key = cfg["enrichment"].get("otx_api_key", "")
    if not key or key == "CHANGE_ME":
        return {"note": "no_api_key"}
    if _is_private(ip):
        return {"note": "private_ip_lab", "otx_pulses": 0}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key}, timeout=15)
        r.raise_for_status()
        pulse = r.json().get("pulse_info", {})
        names = [p.get("name") for p in pulse.get("pulses", [])[:3]]
        return {
            "otx_pulses": pulse.get("count", 0),
            "otx_pulse_names": names,
        }
    except Exception as e:
        log.error("OTX sorgu hatasi (%s): %s", ip, e)
        return {"note": "lookup_failed"}


# ----------------------------------------------------------------------
# Shodan (açık port / servis / zafiyet bilgisi)
# ----------------------------------------------------------------------
def shodan_lookup(ip, cfg, log):
    key = cfg["enrichment"].get("shodan_api_key", "")
    if not key or key == "CHANGE_ME":
        return {"note": "no_api_key"}
    if _is_private(ip):
        return {"note": "private_ip_lab", "shodan_ports": []}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": key}, timeout=15)
        if r.status_code == 404:
            return {"shodan_ports": [], "note": "not_found"}
        r.raise_for_status()
        d = r.json()
        return {
            "shodan_ports": d.get("ports", []),
            "shodan_org": d.get("org"),
            "shodan_os": d.get("os"),
            "shodan_vulns": list(d.get("vulns", []))[:10],
        }
    except Exception as e:
        log.error("Shodan sorgu hatasi (%s): %s", ip, e)
        return {"note": "lookup_failed"}


# ----------------------------------------------------------------------
# GreyNoise (Community API — benign / malicious sınıflandırması)
# ----------------------------------------------------------------------
def greynoise_lookup(ip, cfg, log):
    key = cfg["enrichment"].get("greynoise_api_key", "")
    if not key or key == "CHANGE_ME":
        return {"note": "no_api_key"}
    if _is_private(ip):
        return {"note": "private_ip_lab", "greynoise_classification": "unknown"}
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                         headers={"key": key}, timeout=15)
        if r.status_code == 404:
            return {"greynoise_classification": "unknown", "note": "not_observed"}
        r.raise_for_status()
        d = r.json()
        return {
            "greynoise_classification": d.get("classification", "unknown"),
            "greynoise_name": d.get("name"),
            "greynoise_noise": d.get("noise"),
        }
    except Exception as e:
        log.error("GreyNoise sorgu hatasi (%s): %s", ip, e)
        return {"note": "lookup_failed"}


# ----------------------------------------------------------------------
# Birleştirici + tehdit kararı
# ----------------------------------------------------------------------
def _verdict(abuse_score, vt_mal, otx_pulses, gn_class="unknown"):
    if gn_class == "malicious" or abuse_score >= 75 or vt_mal >= 3 or otx_pulses >= 5:
        return "malicious"
    if abuse_score >= 25 or vt_mal >= 1 or otx_pulses >= 1:
        return "suspicious"
    return "clean"


def enrich(ip, cfg, log):
    """Etkin kaynakları sorgular, birleştirir ve tek bir verdict üretir."""
    e = cfg.get("enrichment", {})
    a = cfg.get("actions", {})
    sources = {}

    if a.get("enrich_abuseipdb"):
        sources["abuseipdb"] = abuseipdb_lookup(ip, cfg, log)
    if a.get("enrich_virustotal"):
        sources["virustotal"] = virustotal_lookup(ip, cfg, log)
    if a.get("enrich_otx"):
        sources["otx"] = otx_lookup(ip, cfg, log)
    if a.get("enrich_shodan"):
        sources["shodan"] = shodan_lookup(ip, cfg, log)
    if a.get("enrich_greynoise"):
        sources["greynoise"] = greynoise_lookup(ip, cfg, log)

    abuse_score = int(sources.get("abuseipdb", {}).get("abuse_confidence_score") or 0)
    vt_mal = int(sources.get("virustotal", {}).get("vt_malicious") or 0)
    otx_pulses = int(sources.get("otx", {}).get("otx_pulses") or 0)
    gn_class = sources.get("greynoise", {}).get("greynoise_classification", "unknown")

    if _is_private(ip):
        verdict = "lab_internal"
    else:
        verdict = _verdict(abuse_score, vt_mal, otx_pulses, gn_class)

    result = {
        "ip": ip,
        "verdict": verdict,
        "abuse_confidence_score": abuse_score,
        "vt_malicious": vt_mal,
        "otx_pulses": otx_pulses,
        "greynoise_classification": gn_class,
        "shodan_ports": sources.get("shodan", {}).get("shodan_ports", []),
        "country_code": sources.get("abuseipdb", {}).get("country_code"),
        "sources": sources,
    }
    log.info("Enrichment %s -> verdict=%s (abuse=%s vt=%s otx=%s gn=%s)",
             ip, verdict, abuse_score, vt_mal, otx_pulses, gn_class)
    return result
