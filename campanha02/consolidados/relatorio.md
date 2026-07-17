# Relatório de Eficácia de Detecção — IoTEdu

- Janelas avaliadas: **118** (71 maliciosas, 47 benignas)
- Fonte: `execucoes.csv`  |  unidade = janela rotulada

## Métricas por IDS e Orquestração

| Alvo | TP | FP | TN | FN | Precisão | Recall(Sens.) | Especif. | F1 | FPR | FNR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 49 | 0 | 47 | 22 | 1.000 | 0.690 | 1.000 | 0.817 | 0.000 | 0.310 | 0.845 |
| **snort** | 31 | 0 | 47 | 40 | 1.000 | 0.437 | 1.000 | 0.608 | 0.000 | 0.563 | 0.718 |
| **zeek** | 36 | 6 | 41 | 35 | 0.857 | 0.507 | 0.872 | 0.637 | 0.128 | 0.493 | 0.690 |
| **orquestracao** | 61 | 6 | 41 | 10 | 0.910 | 0.859 | 0.872 | 0.884 | 0.128 | 0.141 | 0.866 |

## Falsos Negativos (ataques NÃO detectados)

- **suricata**: port-scanner-tcp, dos-http-simple, idor-path-traversal, idor-path-traversal, idor-path-traversal, port-scanner-tcp, port-scanner-tcp, idor-path-traversal, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, idor-path-traversal, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, port-scanner-tcp, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce
- **snort**: port-scanner-tcp, sql-injection, sql-injection, sql-injection, dns-tunneling, sql-injection, sql-injection, sql-injection, dos-http-simple, idor-path-traversal, idor-path-traversal, sql-injection, dns-tunneling, idor-path-traversal, port-scanner-tcp, port-scanner-tcp, idor-path-traversal, sql-injection, dos-http-simple, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, dos-http-simple, sql-injection, dns-tunneling, idor-path-traversal, ssh-bruteforce, idor-path-traversal, dns-tunneling, dns-tunneling, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, sql-injection, port-scanner-tcp, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, dos-http-simple
- **zeek**: icmp-flood, dos-http-simple, icmp-flood, dos-http-simple, icmp-flood, icmp-flood, syn-flood, dos-http-simple, xss-scanner, xss-scanner, xss-scanner, ssh-bruteforce, ssh-bruteforce, udp-flood, xss-scanner, udp-flood, ssh-bruteforce, dos-http-simple, syn-flood, dns-tunneling, sql-injection, dns-tunneling, idor-path-traversal, ssh-bruteforce, xss-scanner, syn-flood, syn-flood, dos-http-simple, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, syn-flood, ssh-bruteforce, xss-scanner, dos-http-simple
- **orquestracao**: dos-http-simple, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce

## Falsos Positivos (tráfego benigno que gerou alerta)

- **suricata**: nenhum ✅
- **snort**: nenhum ✅
- **zeek**: benigno-http, benigno-scan, benigno-scan, benigno-mix, benigno-mix, benigno-mix
- **orquestracao**: benigno-http, benigno-scan, benigno-scan, benigno-mix, benigno-mix, benigno-mix

## Detecção por cenário (alertas por janela maliciosa)

| Cenário | Suricata | Snort | Zeek |
|---|--:|--:|--:|
| port-scanner-tcp | 0 | 0 | 1956 |
| sql-injection | 2 | 0 | 2 |
| sql-injection | 2 | 0 | 2 |
| syn-flood | 2 | 307 | 30 |
| syn-flood | 2 | 321 | 17 |
| dns-tunneling | 204 | 50 | 190 |
| icmp-flood | 4 | 7578 | 0 |
| sql-injection | 2 | 0 | 2 |
| dns-tunneling | 204 | 0 | 181 |
| dos-http-simple | 11 | 38 | 0 |
| sql-injection | 2 | 0 | 2 |
| sql-injection | 2 | 0 | 2 |
| xss-scanner | 2 | 2 | 2 |
| sql-injection | 2 | 0 | 2 |
| icmp-flood | 4 | 7770 | 0 |
| dos-http-simple | 0 | 0 | 0 |
| xss-scanner | 2 | 2 | 2 |
| xss-scanner | 2 | 2 | 2 |
| idor-path-traversal | 0 | 0 | 598 |
| icmp-flood | 4 | 7290 | 0 |
| idor-path-traversal | 0 | 0 | 598 |
| icmp-flood | 4 | 7482 | 0 |
| sql-injection | 2 | 0 | 2 |
| dns-tunneling | 204 | 0 | 184 |
| syn-flood | 2 | 360 | 3 |
| idor-path-traversal | 0 | 0 | 598 |
| port-scanner-tcp | 0 | 0 | 1956 |
| xss-scanner | 2 | 2 | 2 |
| syn-flood | 2 | 347 | 0 |
| port-scanner-tcp | 0 | 0 | 2957 |
| idor-path-traversal | 0 | 0 | 598 |
| sql-injection | 2 | 0 | 2 |
| dos-http-simple | 7 | 0 | 0 |
| idor-path-traversal | 0 | 0 | 598 |
| udp-flood | 31341 | 18843 | 11999 |
| xss-scanner | 2 | 2 | 0 |
| xss-scanner | 2 | 2 | 0 |
| xss-scanner | 2 | 2 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| udp-flood | 21933 | 16519 | 0 |
| xss-scanner | 2 | 2 | 0 |
| udp-flood | 25809 | 16117 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| dos-http-simple | 28 | 0 | 0 |
| syn-flood | 2 | 281 | 0 |
| dns-tunneling | 204 | 53 | 0 |
| sql-injection | 2 | 0 | 0 |
| dns-tunneling | 204 | 0 | 0 |
| idor-path-traversal | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| xss-scanner | 2 | 2 | 0 |
| idor-path-traversal | 0 | 0 | 4 |
| dns-tunneling | 204 | 0 | 179 |
| dns-tunneling | 204 | 0 | 200 |
| syn-flood | 2 | 333 | 0 |
| idor-path-traversal | 0 | 0 | 598 |
| port-scanner-tcp | 0 | 0 | 1956 |
| syn-flood | 2 | 358 | 0 |
| dos-http-simple | 19 | 50 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| sql-injection | 2 | 0 | 2 |
| port-scanner-tcp | 0 | 0 | 1956 |
| ssh-bruteforce | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| syn-flood | 2 | 317 | 90 |
| udp-flood | 30662 | 20156 | 11633 |
| syn-flood | 2 | 342 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| xss-scanner | 2 | 2 | 0 |
| dos-http-simple | 11 | 0 | 0 |
