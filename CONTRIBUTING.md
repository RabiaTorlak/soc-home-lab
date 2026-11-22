# Katkı Rehberi

Bu proje bir öğrenme/portfolyo laboratuvarıdır; katkılar ve öneriler memnuniyetle karşılanır.

## Geliştirme ortamı

```bash
pip install -r soar/requirements.txt
pip install -r requirements-dev.txt
pytest -q           # testleri çalıştır
flake8 soar --select=E9,F63,F7,F82   # kritik lint
```

## Yeni tespit kuralı ekleme

1. Önce **Sigma** formatında yaz: `rules/sigma/<ad>.yml` (taşınabilir kaynak).
2. Wazuh karşılığını `rules/local_rules.xml`'e ekle (ID aralığı `1001xx`), `<mitre><id>` etiketiyle.
3. Kapsama haritasını güncelle: `python soar/generate_attack_navigator.py`.
4. Mümkünse bir birim testi ekle (`tests/`).

## Kurallar

- Her PR, CI'dan (lint + pytest + XML/YAML/JSON doğrulama) **geçmelidir**.
- Gerçek API anahtarları / şifreler **asla** commit edilmez (`config.yaml` `.gitignore`'dadır).
- Saldırı/test scriptleri yalnızca **kendi izole lab ortamında** kullanılır.

## Commit mesajları

Kısa ve açıklayıcı, Türkçe ya da İngilizce olabilir (ör. `Add T1021 lateral movement rule`).
