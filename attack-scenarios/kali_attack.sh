#!/usr/bin/env bash
# ============================================================
#  SOC Lab - Kali Saldırı Senaryosu (Adversary Emulation)
#  SADECE kendi izole lab ortamında kullan!
#  Amaç: Wazuh tespit kurallarını ve SOAR otomasyonunu tetiklemek.
# ============================================================
set -u

# ---- Hedefler (kendi lab IP'lerine göre düzenle) ----
WIN_ENDPOINT="192.168.222.131"   # Windows 11 endpoint IP'si
SOC_SERVER="192.168.222.130"     # Ubuntu SOC sunucusu
ATTACKER_IP="$(hostname -I | awk '{print $1}')"

banner() { echo -e "\n\033[1;31m[+] $1\033[0m"; }
pause()  { echo "    -> devam için ENTER"; read -r; }

echo "=============================================="
echo " SOC LAB - KALI ADVERSARY EMULATION"
echo " Saldırgan IP : $ATTACKER_IP"
echo " Win Endpoint : $WIN_ENDPOINT"
echo " SOC Server   : $SOC_SERVER"
echo "=============================================="
echo "UYARI: Bu script yalnızca izinli lab ortamı içindir."
pause

# ------------------------------------------------------------
# SENARYO 1: Ağ Keşfi / Port Taraması (MITRE T1046, T1595)
#   -> Wazuh/Sysmon üzerinde recon alarmı üretir
# ------------------------------------------------------------
banner "Senaryo 1: Nmap ile port + servis taraması (T1046)"
nmap -sS -sV -T4 -p 1-1000 "$WIN_ENDPOINT"
echo "    [i] Agresif tarama (gürültülü, IDS tetikler):"
nmap -A -T4 "$WIN_ENDPOINT"
pause

# ------------------------------------------------------------
# SENARYO 2: SSH Brute-Force (MITRE T1110)
#   -> SOC sunucusunun SSH servisine karşı
#   -> Wazuh kuralı 5710/5712/5763 + SOAR engelleme tetikler
#   (Not: brute-force'un alarm üretmesi için SOC sunucusunda
#    SSH açık olmalı. Gerçek hesap ele geçirmek değil, FAILED
#    LOGON üretmek amaçtır -> kullanıcı adı/şifre listesi kasıtlı yanlış.)
# ------------------------------------------------------------
banner "Senaryo 2: Hydra ile SSH brute-force (T1110)"
cat > /tmp/userlist.txt <<'EOF'
admin
root
soc
test
EOF
cat > /tmp/passlist.txt <<'EOF'
123456
password
admin123
letmein
toor
EOF
echo "    [i] $SOC_SERVER SSH'a brute-force (başarısız denemeler üretir)..."
hydra -L /tmp/userlist.txt -P /tmp/passlist.txt -t 4 -f \
      ssh://"$SOC_SERVER" || true
pause

# ------------------------------------------------------------
# SENARYO 3: RDP Brute-Force (MITRE T1110.001 / Windows 4625)
#   -> Windows endpoint'e karşı, Wazuh Windows auth kurallarını tetikler
# ------------------------------------------------------------
banner "Senaryo 3: Windows RDP brute-force (T1110.001)"
echo "    [i] $WIN_ENDPOINT RDP'ye başarısız oturum denemeleri..."
hydra -L /tmp/userlist.txt -P /tmp/passlist.txt -t 2 -f \
      rdp://"$WIN_ENDPOINT" || true
pause

# ------------------------------------------------------------
# SENARYO 4: Encoded PowerShell (MITRE T1059.001)
#   -> Senin 100101 kuralını tetikler. Bu komutu WINDOWS endpoint'te
#      çalıştır (buradan uzaktan değil). Referans olarak bırakıyoruz:
# ------------------------------------------------------------
banner "Senaryo 4 (Windows'ta çalıştır): Encoded PowerShell (T1059.001)"
cat <<'EOF'
    # Windows 11 endpoint'te PowerShell'de çalıştır:
    $cmd = 'Write-Host "SOC-LAB test: encoded powershell"'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    powershell.exe -EncodedCommand $enc
EOF
pause

banner "Senaryo tamamlandı. Wazuh Dashboard + SOAR loglarını kontrol et:"
echo "    SOC sunucusunda:  tail -f /var/ossec/integrations/soar/soar.log"
echo "    Vakalar:          ls -l /var/ossec/integrations/soar/cases/"
