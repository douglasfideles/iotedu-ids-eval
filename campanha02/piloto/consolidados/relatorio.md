# Relatório de Eficácia de Detecção — IoTEdu

- Janelas avaliadas: **16** (10 maliciosas, 6 benignas)
- Fonte: `execucoes.csv`  |  unidade = janela rotulada

## Métricas por IDS e Orquestração

| Alvo | TP | FP | TN | FN | Precisão | Recall(Sens.) | Especif. | F1 | FPR | FNR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 7 | 0 | 6 | 3 | 1.000 | 0.700 | 1.000 | 0.824 | 0.000 | 0.300 | 0.850 |
| **snort** | 4 | 0 | 6 | 6 | 1.000 | 0.400 | 1.000 | 0.571 | 0.000 | 0.600 | 0.700 |
| **zeek** | 1 | 0 | 6 | 9 | 1.000 | 0.100 | 1.000 | 0.182 | 0.000 | 0.900 | 0.550 |
| **orquestracao** | 7 | 0 | 6 | 3 | 1.000 | 0.700 | 1.000 | 0.824 | 0.000 | 0.300 | 0.850 |

## Falsos Negativos (ataques NÃO detectados)

- **suricata**: ssh-bruteforce, port-scanner-tcp, idor-path-traversal
- **snort**: ssh-bruteforce, port-scanner-tcp, dns-tunneling, idor-path-traversal, dos-http-simple, sql-injection
- **zeek**: ssh-bruteforce, port-scanner-tcp, dns-tunneling, idor-path-traversal, dos-http-simple, xss-scanner, sql-injection, syn-flood, icmp-flood
- **orquestracao**: ssh-bruteforce, port-scanner-tcp, idor-path-traversal

## Falsos Positivos (tráfego benigno que gerou alerta)

- **suricata**: nenhum ✅
- **snort**: nenhum ✅
- **zeek**: nenhum ✅
- **orquestracao**: nenhum ✅

## Detecção por cenário (alertas por janela maliciosa)

| Cenário | Suricata | Snort | Zeek |
|---|--:|--:|--:|
| udp-flood | 32854 | 18310 | 8999 |
| ssh-bruteforce | 0 | 0 | 0 |
| port-scanner-tcp | 0 | 0 | 0 |
| dns-tunneling | 204 | 0 | 0 |
| idor-path-traversal | 0 | 0 | 0 |
| dos-http-simple | 15 | 0 | 0 |
| xss-scanner | 2 | 2 | 0 |
| sql-injection | 2 | 0 | 0 |
| syn-flood | 1 | 241 | 0 |
| icmp-flood | 4 | 7034 | 0 |
