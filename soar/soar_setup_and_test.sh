#!/usr/bin/env bash
# ============================================================
#  SOC Lab - SOAR Otonom Kurulum + Canlı Test
#  SOC sunucusunda (192.168.222.130) TEK komutla çalışır:
#      sudo bash soar_setup_and_test.sh
#  Temizlik (test sonrası Kali engelini kaldır):
#      sudo bash soar_setup_and_test.sh --cleanup
# ============================================================
set -uo pipefail

SOAR_DIR="/var/ossec/integrations/soar"
KALI_IP="192.168.222.128"
SOC_IP="192.168.222.130"

GREEN="\033[1;32m"; RED="\033[1;31m"; YEL="\033[1;33m"; NC="\033[0m"
say() { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn(){ echo -e "${YEL}[UYARI]${NC} $*"; }
err() { echo -e "${RED}[HATA]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then err "Root gerekli: sudo bash $0"; exit 1; fi

# ---- Temizlik modu ----
if [[ "${1:-}" == "--cleanup" ]]; then
  n=0
  while iptables -C INPUT -s "$KALI_IP" -j DROP 2>/dev/null; do
    iptables -D INPUT -s "$KALI_IP" -j DROP; n=$((n+1))
  done
  say "Kali ($KALI_IP) icin $n engel kurali kaldirildi."
  exit 0
fi

echo "============================================================"
echo " SOC LAB - SOAR OTONOM KURULUM + CANLI TEST"
echo "============================================================"

# ---- 1) firewall-drop komutu ----
say "1/5 firewall-drop komutu kontrol ediliyor..."
if grep -q "firewall-drop" /var/ossec/etc/ossec.conf; then
  say "firewall-drop ossec.conf'ta tanimli."
else
  warn "firewall-drop ossec.conf'ta bulunamadi. Wazuh AR calismayabilir (iptables yine calisir)."
fi

# ---- 2) soar.service dosyasini yaz ----
say "2/5 soar.service olusturuluyor..."
cat > /etc/systemd/system/soar.service <<'SVCEOF'
[Unit]
Description=SOC Lab Python SOAR Responder
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
WorkingDirectory=/var/ossec/integrations/soar
ExecStart=/usr/bin/python3 /var/ossec/integrations/soar/soar_responder.py --config /var/ossec/integrations/soar/config.yaml
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

# ---- 3) Wazuh Active Response otomatik dogrulama + config yamasi ----
say "3/5 Wazuh Active Response otomatik dogrulaniyor..."
if [[ -f "$SOAR_DIR/ar_selftest.py" ]]; then
  python3 "$SOAR_DIR/ar_selftest.py" || warn "AR self-test uyari dondu (iptables engelleme yine aktif)."
else
  warn "ar_selftest.py bulunamadi, AR dogrulamasi atlandi."
fi

# ---- 4) Servisi baslat ----
say "4/5 soar.service etkinlestiriliyor..."
systemctl daemon-reload
systemctl enable --now soar.service
sleep 2
if systemctl is-active --quiet soar.service; then
  say "soar.service CALISIYOR (gercek mod, engelleme aktif)."
else
  err "soar.service baslamadi. Son loglar:"
  journalctl -u soar.service --no-pager -n 20
  exit 1
fi

# ---- 5) Canli test talimati ----
say "5/5 Kurulum tamam. CANLI ENGELLEME TESTI:"
echo ""
echo "  >> KALI'DE ($KALI_IP) calistir (SSH brute-force):"
echo "     for i in \$(seq 1 8); do sshpass -p 'yanlis123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 baduser@${SOC_IP} 2>/dev/null; done; echo bitti"
echo ""
echo "  >> SOC'ta canli log:   sudo tail -f ${SOAR_DIR}/soar.log"
echo "  >> Engeli dogrula:     sudo iptables -L INPUT -n --line-numbers | grep ${KALI_IP}"
echo "  >> Son vaka dosyasi:   sudo cat \$(sudo ls -t ${SOAR_DIR}/cases/*.json | head -1)"
echo ""
echo "  >> TEST SONRASI TEMIZLIK (Kali tekrar calissin):"
echo "     sudo bash $0 --cleanup"
echo ""
say "Beklenen loglar: 'iptables: ${KALI_IP} ENGELLENDI' ve 'Wazuh AR: ... tetiklendi'"
