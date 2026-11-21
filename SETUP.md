# Kurulum ve Çalıştırma Kılavuzu (SOC Sunucusu)

> Tüm komutlar **Ubuntu SOC sunucusunda** (`192.168.222.130`) çalıştırılır.
> Aksi belirtilmedikçe `sudo` gerekir.

## 1. Dosyaları sunucuya yerleştir

```bash
sudo mkdir -p /var/ossec/integrations/soar/cases
# soar/ klasöründeki dosyaları bu dizine kopyala:
#   soar_responder.py  actions.py  enrichment.py  config.yaml  requirements.txt
sudo cp soar_responder.py actions.py enrichment.py config.yaml requirements.txt \
        /var/ossec/integrations/soar/
cd /var/ossec/integrations/soar
```

## 2. Python bağımlılıkları

```bash
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install -r requirements.txt
```

## 3. config.yaml'i düzenle

```bash
sudo nano /var/ossec/integrations/soar/config.yaml
```

Doldurulması gerekenler:
- `wazuh.api_password` — Wazuh API şifren
- `enrichment.abuseipdb_api_key` — https://www.abuseipdb.com (ücretsiz kayıt)
- `telegram.bot_token` ve `telegram.chat_id` — @BotFather'dan bot oluştur

> Telegram chat_id'yi öğrenmek için: botuna bir mesaj at, sonra
> `https://api.telegram.org/bot<TOKEN>/getUpdates` adresini aç.

## 4. Wazuh Active Response'u etkinleştir (firewall-drop)

Windows endpoint'te saldırgan IP'yi engellemek için `/var/ossec/etc/ossec.conf`
dosyasına (Manager tarafında) şu bloğu ekle (`<ossec_config>` içine):

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>7</level>
  <timeout>600</timeout>
</active-response>
```

> `firewall-drop` komutu Wazuh ile hazır gelir; Windows'ta `netsh`, Linux'ta
> `iptables` kullanır. SOAR scriptimiz bunu API üzerinden de tetikleyebilir.

Değişiklikten sonra:

```bash
sudo systemctl restart wazuh-manager
```

## 5. SOAR'ı test modunda (dry-run) çalıştır

Önce hiçbir şeyi engellemeden, sadece ne yapacağını görmek için:

```bash
cd /var/ossec/integrations/soar
sudo python3 soar_responder.py --config config.yaml --dry-run
```

Başka bir terminalde Kali'den saldırı başlat (aşağıya bak). Loglarda
`[ALARM]` ve `[DRY-RUN]` satırlarını görmelisin.

## 6. Gerçek modda çalıştır (servis olarak)

```bash
sudo cp soar.service /etc/systemd/system/soar.service
sudo systemctl daemon-reload
sudo systemctl enable --now soar.service
sudo systemctl status soar.service
# Canlı log:
sudo journalctl -u soar.service -f
# veya
sudo tail -f /var/ossec/integrations/soar/soar.log
```

---

## 7. Kali'den saldırı senaryosunu çalıştır

Kali makinesinde:

```bash
sudo apt install -y hydra nmap        # yoksa
chmod +x kali_attack.sh
# Script içindeki WIN_ENDPOINT / SOC_SERVER IP'lerini düzenle, sonra:
./kali_attack.sh
```

## 8. Sonuçları doğrula

- **Wazuh Dashboard** → Security Events: recon / brute-force alarmları
- **SOAR logu**: `tail -f /var/ossec/integrations/soar/soar.log`
- **Vaka dosyaları**: `ls -l /var/ossec/integrations/soar/cases/`
- **Engel doğrulama**: `sudo iptables -L INPUT -n --line-numbers | grep <KALI_IP>`
- **Telegram**: telefonuna gelen alarm bildirimi

## Sorun Giderme

| Belirti | Çözüm |
|--------|-------|
| `alerts.json` yok | `sudo systemctl status wazuh-manager`; logging JSON açık mı kontrol et |
| Kaynak IP boş | Uyarıda `data.srcip` yok; Windows auth kuralları için `extract_srcip` zaten `win.eventdata`'ya bakıyor |
| API 401 | `config.yaml` içindeki `api_user/api_password` yanlış |
| iptables izni | servisi `root` ile çalıştır (soar.service öyle ayarlı) |
| Telegram gitmiyor | `bot_token`/`chat_id` kontrol; botu başlat (`/start`) |
