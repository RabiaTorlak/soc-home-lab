#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wazuh Active Response otomatik doğrulama + config yaması.
config.yaml'den API bilgilerini okur, firewall-drop0 ve firewall-drop
komutlarını sırayla dener, çalışanı tespit edip config.yaml'e yazar.
Test IP olarak RFC 5737 test bloğu (203.0.113.77) kullanılır ve temizlenir.

Çalıştırma (root gerekir):  sudo python3 ar_selftest.py
"""
import sys
import re
import json
import time
import subprocess

import yaml
import requests

requests.packages.urllib3.disable_warnings()

CFG = "/var/ossec/integrations/soar/config.yaml"
TEST_IP = "203.0.113.77"
CANDIDATES = ("firewall-drop0", "firewall-drop")


def get_token(w):
    r = requests.post(
        f"{w['api_url']}/security/user/authenticate",
        auth=(w["api_user"], w["api_password"]),
        verify=w.get("verify_ssl", False), timeout=10)
    r.raise_for_status()
    return r.json()["data"]["token"]


def try_cmd(w, token, cmd):
    payload = {"command": cmd, "arguments": [TEST_IP],
               "alert": {"data": {"srcip": TEST_IP}}}
    r = requests.put(
        f"{w['api_url']}/active-response",
        params={"agents_list": "000"},
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        data=json.dumps(payload),
        verify=w.get("verify_ssl", False), timeout=10)
    try:
        ok = r.status_code in (200, 201) and r.json().get("error") == 0
    except Exception:
        ok = False
    return ok, r.status_code, r.text[:200]


def iptables_has(ip):
    return subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True).returncode == 0


def iptables_cleanup(ip):
    while iptables_has(ip):
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True)


def patch_config(cmd):
    data = open(CFG, encoding="utf-8").read()
    new = re.sub(r'(^\s*active_response_command:\s*).*$',
                 r'\g<1>"%s"' % cmd, data, flags=re.M)
    with open(CFG, "w", encoding="utf-8") as f:
        f.write(new)


def main():
    c = yaml.safe_load(open(CFG, encoding="utf-8"))
    w = c["wazuh"]

    if w.get("api_password") in (None, "", "CHANGE_ME"):
        print("[!] config.yaml icinde api_password ayarli degil. Once Adim 4'u tamamla.")
        sys.exit(3)

    print("[*] Wazuh API token aliniyor...")
    try:
        token = get_token(w)
    except Exception as e:
        print(f"[!] API token alinamadi: {e}")
        print("    -> api_user/api_password/api_url degerlerini kontrol et.")
        sys.exit(3)
    print("[+] Token alindi.")

    working = None
    for cmd in CANDIDATES:
        print(f"[*] AR komutu deneniyor: {cmd}")
        ok, sc, txt = try_cmd(w, token, cmd)
        print(f"    -> http={sc} error0={ok} resp={txt}")
        if ok:
            working = cmd
            break
        time.sleep(1)

    time.sleep(2)
    blocked = iptables_has(TEST_IP)
    iptables_cleanup(TEST_IP)   # test bloğunu temizle

    if working:
        print(f"[+] Calisan AR komutu: {working} (iptables test blok gorundu: {blocked})")
        patch_config(working)
        print(f"[+] config.yaml guncellendi: active_response_command=\"{working}\"")
        sys.exit(0)

    print("[!] Hicbir AR komutu error:0 donmedi.")
    print("    iptables yerel engelleme yine de calisir; Wazuh AR'i elle gozden gecir.")
    sys.exit(2)


if __name__ == "__main__":
    main()
