# Sigma Kuralları (Detection-as-Code)

Bu klasör, tespit mantığını **satıcıdan bağımsız [Sigma](https://sigmahq.io/)**
formatında tutar. Sigma, "detection-as-code" için standart kaynak formatıdır:
tek bir kuralı yazıp Wazuh, Elastic, Splunk gibi birçok SIEM'e dönüştürebilirsin.

## Kurallar

| Dosya | Teknik | Wazuh karşılığı |
|-------|--------|-----------------|
| `registry_run_key_persistence.yml` | T1547.001 | 100108 |
| `clear_windows_event_logs.yml` | T1070.001 | 100109 |
| `remote_system_discovery.yml` | T1018 | 100110 |
| `enable_rdp_lateral_movement.yml` | T1021.001 | 100111 |
| `network_config_discovery.yml` | T1016 | 100112 |

## Sigma → Wazuh dönüşümü

```bash
pip install sigma-cli pysigma-backend-elasticsearch
# Kuralları doğrula
sigma check rules/sigma/

# (İleri seviye) Wazuh/pcre2 çıktısı için uygun backend ile:
sigma convert -t <backend> rules/sigma/registry_run_key_persistence.yml
```

> Bu projede Sigma kuralları, `../local_rules.xml` içindeki Wazuh kurallarının
> **okunabilir, taşınabilir kaynak karşılığıdır**. Üretimde Sigma'yı tek kaynak
> (single source of truth) yapıp Wazuh kurallarını otomatik üretmek idealdir.
