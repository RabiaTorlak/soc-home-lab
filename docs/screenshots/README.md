# Ekran Görüntüleri

Ana `README.md`'deki "📸 Ekran Görüntüleri" bölümünün beklediği dosyalar.
Kendi lab ortamından alıp bu klasöre **tam olarak** şu adlarla kaydet:

| Dosya adı | İçerik |
|-----------|--------|
| `grafana-overview.png` | Grafana **SOC Overview** dashboard (dolu paneller) — *bu sende zaten var* |
| `soar-live-block.png` | `soar.log` veya terminal — canlı `ENGELLENDI` satırları |

> Not: ATT&CK kapsama haritası ekran görüntüsü gerektirmez — `docs/coverage-matrix.svg`
> olarak otomatik üretilir ve README'de vektör olarak gösterilir.

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
