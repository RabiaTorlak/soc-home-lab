# Olay Müdahale Raporu — SSH Brute-Force & Otomatik Engelleme

| Alan | Değer |
|------|-------|
| **Rapor No** | IR-2026-001 |
| **Olay Başlığı** | SOC sunucusuna yönelik SSH brute-force ve otomatik SOAR müdahalesi |
| **Önem Derecesi** | Yüksek (Wazuh Level 10) |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Tespit Tarihi** | 2026-11-21 14:32 (UTC) |
| **Analist** | Junior SOC Analyst |
| **Durum** | Kapatıldı (Contained & Recovered) |

---

## 1. Yönetici Özeti (Executive Summary)

21 Kasım 2026'da, `192.168.222.128` IP adresli bir ana bilgisayardan SOC
sunucusunun (`192.168.222.130`) SSH servisine yönelik bir **brute-force**
saldırısı gerçekleştirildi. Saldırı, Wazuh SIEM tarafından **Rule 5712
(Level 10, MITRE T1110)** olarak tespit edildi. Geliştirilen **Python SOAR**
otomasyonu, uyarıyı gerçek zamanlı yakalayarak saldırgan IP'yi **iptables** ile
otomatik engelledi, IOC zenginleştirmesi yaptı ve olay için yapılandırılmış bir
vaka kaydı (`CASE-20261121-143234-5712.json`) oluşturdu. Manuel müdahaleye gerek
kalmadan, tespitten engellemeye kadar geçen süre **saniyeler** mertebesindedir.

## 2. Olay Zaman Çizelgesi (Timeline — UTC)

| Zaman | Olay |
|-------|------|
| 14:32:30 | `192.168.222.128`'den SOC sunucusuna çoklu başarısız SSH oturum denemesi başladı |
| 14:32:34 | Wazuh, eşik aşımıyla **Rule 5712** (SSHD brute force) alarmını üretti (Level 10) |
| 14:32:34 | SOAR, `alerts.json` akışından alarmı yakaladı (`[ALARM] id=5712`) |
| 14:32:34 | IOC zenginleştirme tetiklendi (özel IP → lab notu) |
| 14:32:35 | **iptables** ile `192.168.222.128` için `DROP` kuralı eklendi |
| 14:32:35 | Wazuh Active Response (firewall-drop) agent üzerinde tetiklendi |
| 14:32:35 | Vaka dosyası diske yazıldı: `CASE-20261121-143234-5712.json` |
| ~15:30 | Doğrulama sonrası engel temizlendi (`--cleanup`) |

## 3. Tespit Detayları (Detection)

- **Kaynak:** Wazuh Manager, `/var/ossec/logs/alerts/alerts.json`
- **Tetikleyen kural:** `5712 — sshd: brute force trying to get access to the system`
- **Seviye:** 10
- **Kaynak IP (srcip):** `192.168.222.128` (Kali Linux — saldırı makinesi)
- **Hedef:** `192.168.222.130` (Ubuntu SOC sunucusu), SSH/22
- **Korelasyon:** Kısa sürede eşik üstü başarısız kimlik doğrulama (5710/5711)
  olaylarının toplanmasıyla 5712 brute-force kuralı tetiklendi.

## 4. MITRE ATT&CK Eşlemesi

| Taktik | Teknik | ID |
|--------|--------|-----|
| Credential Access | Brute Force | **T1110** |
| (İlgili kurallar) | Valid Accounts / Recon | T1078 / T1046 |

## 5. Müdahale (Containment · Eradication · Recovery)

- **Containment (Sınırlama):** SOAR, saldırgan IP'yi `iptables -I INPUT -s
  192.168.222.128 -j DROP` ile otomatik engelledi. Ek olarak Wazuh Active
  Response ile hedef agent üzerinde firewall-drop uygulandı.
- **Eradication (Temizleme):** Başarılı bir oturum açma gözlenmedi; hesap ele
  geçirme kanıtı yok. Kötücül kalıcılık (persistence) tespit edilmedi.
- **Recovery (Kurtarma):** Doğrulama sonrası engel kaldırıldı; `block_duration`
  politikası gereği SOAR engelleri 60 dk sonra otomatik düşmektedir. Servis
  normal operasyona döndü.

## 6. Uzlaşma Göstergeleri (IOCs)

| Tür | Değer | Not |
|-----|-------|-----|
| IPv4 | `192.168.222.128` | Saldırı kaynağı (lab) |
| Port | `22/tcp` | Hedef servis (SSH) |
| Rule ID | `5712` | Wazuh brute-force korelasyonu |
| Vaka | `CASE-20261121-143234-5712.json` | Yapılandırılmış kanıt |

## 7. Alınan Dersler ve Öneriler (Lessons Learned)

1. **Olumlu:** Tespit→engelleme döngüsü otomatikti; MTTR (ortalama müdahale
   süresi) saniyeler seviyesine indi.
2. **İyileştirme:** Public/gerçek IP'ler için AbuseIPDB zenginleştirmesi ve
   Telegram bildirimi etkinleştirilerek analist farkındalığı artırılmalı.
3. **Sertleştirme:** SSH'ta anahtar tabanlı kimlik doğrulama, `fail2ban` ve
   parola politikası ile saldırı yüzeyi daraltılmalı.
4. **Kapsam:** RDP (T1110.001) ve diğer servisler için de brute-force tespit ve
   SOAR engelleme senaryoları genişletilmeli.

## 8. Ekler (Artifacts)

- SOAR log kesiti: `/var/ossec/integrations/soar/soar.log`
- Vaka dosyası: `cases/CASE-20261121-143234-5712.json`
- Tespit kuralı: Wazuh Rule 5712 (yerleşik), özel kurallar `rules/local_rules.xml`
