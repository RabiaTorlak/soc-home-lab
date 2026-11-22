# Ekran Görüntüleri

Ana `README.md`'deki "📸 Ekran Görüntüleri" bölümünün beklediği dosyalar.
Kendi lab ortamından alıp bu klasöre **tam olarak** şu adlarla kaydet:

| Dosya adı | İçerik |
|-----------|--------|
| `grafana-overview.png` | Grafana **SOC Overview** dashboard (dolu paneller) |
| `attack-navigator.png` | ATT&CK Navigator'da yüklü kapsama haritası (renkli matris) |
| `soar-live-block.png` | `soar.log` veya terminal — canlı `ENGELLENDI` satırları |
| `ir-report.png` | `generate_ir_report.py` çıktısı (üretilen IR raporu) |

## Nasıl eklenir

1. Görüntüleri yukarıdaki adlarla bu klasöre kopyala.
2. Commit edip push et:
   ```powershell
   git add docs/screenshots/
   git commit -m "Ekran goruntuleri eklendi"
   git push
   ```

> İpucu: PNG formatı ve ~1200px genişlik README'de temiz görünür.
> Navigator görüntüsü için katmanı yükle:
> `https://raw.githubusercontent.com/RabiaTorlak/soc-home-lab/main/docs/attack-navigator-layer.json`
