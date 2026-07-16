# Relatório de Eficácia de Detecção — IoTEdu

- Janelas avaliadas: **16** (8 maliciosas, 8 benignas)
- Fonte: `execucoes.csv`  |  unidade = janela rotulada

## Métricas por IDS e Orquestração

| Alvo | TP | FP | TN | FN | Precisão | Recall(Sens.) | Especif. | F1 | FPR | FNR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 6 | 0 | 8 | 2 | 1.000 | 0.750 | 1.000 | 0.857 | 0.000 | 0.250 | 0.875 |
| **snort** | 6 | 1 | 7 | 2 | 0.857 | 0.750 | 0.875 | 0.800 | 0.125 | 0.250 | 0.812 |
| **zeek** | 7 | 3 | 5 | 1 | 0.700 | 0.875 | 0.625 | 0.778 | 0.375 | 0.125 | 0.750 |
| **orquestracao** | 8 | 4 | 4 | 0 | 0.667 | 1.000 | 0.500 | 0.800 | 0.500 | 0.000 | 0.750 |

## Falsos Negativos (ataques NÃO detectados)

- **suricata**: port-scan, udp-flood
- **snort**: http-flood, port-scan
- **zeek**: icmp-flood
- **orquestracao**: nenhum ✅

## Falsos Positivos (tráfego benigno que gerou alerta)

- **suricata**: nenhum ✅
- **snort**: icmp-flood
- **zeek**: port-scan, syn-flood, udp-flood
- **orquestracao**: port-scan, syn-flood, udp-flood, icmp-flood

## Detecção por cenário (alertas por janela maliciosa)

| Cenário | Suricata | Snort | Zeek |
|---|--:|--:|--:|
| http-flood | 12 | 0 | 67 |
| port-scan | 0 | 0 | 8794 |
| syn-flood | 1775 | 1980 | 6023 |
| udp-flood | 0 | 4250 | 1 |
| icmp-flood | 1470 | 4420 | 0 |
| sql-injection | 6424 | 4662 | 6825 |
| xss-scanner | 5920 | 4704 | 4540 |
| path-traversal | 1959 | 2403 | 3814 |
