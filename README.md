# 🛡️ SOC Home Lab — SIEM + SOAR Tespit & Müdahale Projesi

Uçtan uca bir **Blue Team / SOC Analyst** ev laboratuvarı: Wazuh SIEM ile tespit,
Python tabanlı **SOAR** ile otomatik müdahale, MITRE ATT&CK eşleşmeli özel kurallar
ve örnek olay müdahale (Incident Response) akışı.

## 🧱 Mimari

```
                 192.168.222.0/24 (VMware NAT)
  ┌─────────────────┐      ┌──────────────────────────────┐
  │  Kali Linux     │      │  Ubuntu SOC Server (.130)     │
  │  (Attacker)     │─────▶│  • Wazuh Indexer/Mgr/Dash     │
  │  nmap, hydra    │ atak │  • Python SOAR (bu repo)      │
  └─────────────────┘      │  • Grafana, NetAlertX (Docker)│
                           └───────────────┬───────────────┘
  ┌─────────────────┐                      │ agent
  │ Win11 Endpoint  │──────────────────────┘
  │ Sysmon + Wazuh  │  log/telemetri
  └─────────────────┘
```

## ⚙️ Bileşenler

| Katman | Teknoloji |
|--------|-----------|
| SIEM | Wazuh (Indexer, Manager, Dashboard) |
| Endpoint telemetri | Sysmon (SwiftOnSecurity config) + Wazuh Agent |
| SOAR | Python 3 (bu repo — `soar/`) |
| Görselleştirme | Grafana, Wazuh Dashboard |
| Ağ keşfi | NetAlertX |
| Saldırı emülasyonu | Kali Linux (nmap, hydra) |

## 🔁 SOAR İş Akışı

1. Wazuh Manager uyarıyı `alerts.json`'a yazar
2. `soar_responder.py` dosyayı canlı izler, seviye/kural filtreler
3. Saldırgan IP çıkarılır → **AbuseIPDB** ile zenginleştirilir (IOC)
4. **iptables** (yerel) + **Wazuh Active Response** (hedef agent) ile engellenir
5. **Telegram**'a alarm gönderilir
6. JSON **vaka (case)** kaydı oluşturulur → IR raporunun kaynağı

## 🎯 MITRE ATT&CK Kapsamı

| Kural ID | Teknik | Açıklama |
|----------|--------|----------|
| 100101 | T1059.001 | Encoded PowerShell |
| 100102 | T1082 | System Information Discovery (recon tool) |
| (Wazuh) | T1110 | SSH/RDP Brute-Force |
| (Wazuh) | T1046 | Network Service Scanning |

## 🚀 Hızlı Başlangıç

Ayrıntılı adımlar için **[SETUP.md](SETUP.md)**.

```bash
# SOC sunucusunda
sudo pip3 install -r soar/requirements.txt
sudo python3 soar/soar_responder.py --config soar/config.yaml --dry-run
```

## 📁 Repo Yapısı

```
soc-lab-soar/
├── README.md
├── SETUP.md                 # kurulum + çalıştırma adımları
├── soar/
│   ├── soar_responder.py    # ana SOAR servisi
│   ├── actions.py           # engelleme, Active Response, bildirim
│   ├── enrichment.py        # AbuseIPDB IOC zenginleştirme
│   ├── config.yaml          # yapılandırma (örnek — gerçek anahtarları koyma!)
│   ├── requirements.txt
│   └── soar.service         # systemd servis birimi
├── attack-scenarios/
│   └── kali_attack.sh       # adversary emulation (nmap + hydra)
├── rules/                   # özel Wazuh/Sigma kuralları (Sprint 4.2)
└── incident-response/       # örnek IR raporu (Sprint 4.3)
```

## ⚠️ Yasal Uyarı

Bu proje yalnızca **kendi izole lab ortamında** eğitim ve savunma amaçlıdır.
Saldırı scriptlerini yalnızca sahibi olduğun / yetkin olan sistemlerde çalıştır.

---
*Junior Blue Team / SOC Analyst Portfolio Projesi*
