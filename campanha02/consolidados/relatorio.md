# Relatório de Eficácia de Detecção — IoTEdu

- Janelas avaliadas: **240** (150 maliciosas, 90 benignas)
- Fonte: `execucoes.csv`  |  unidade = janela rotulada

## Métricas por IDS e Orquestração

| Alvo | TP | FP | TN | FN | Precisão | Recall(Sens.) | Especif. | F1 | FPR | FNR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 101 | 0 | 90 | 49 | 1.000 | 0.673 | 1.000 | 0.805 | 0.000 | 0.327 | 0.837 |
| **snort** | 69 | 0 | 90 | 81 | 1.000 | 0.460 | 1.000 | 0.630 | 0.000 | 0.540 | 0.730 |
| **zeek** | 60 | 8 | 82 | 90 | 0.882 | 0.400 | 0.911 | 0.550 | 0.089 | 0.600 | 0.656 |
| **orquestracao** | 122 | 8 | 82 | 28 | 0.938 | 0.813 | 0.911 | 0.871 | 0.089 | 0.187 | 0.862 |

## Falsos Negativos (ataques NÃO detectados)

- **suricata**: port-scanner-tcp, dos-http-simple, idor-path-traversal, idor-path-traversal, idor-path-traversal, port-scanner-tcp, port-scanner-tcp, idor-path-traversal, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, idor-path-traversal, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, port-scanner-tcp, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, port-scanner-tcp, port-scanner-tcp, idor-path-traversal, idor-path-traversal, dos-http-simple, port-scanner-tcp, idor-path-traversal, port-scanner-tcp, dos-http-simple, dos-http-simple, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, port-scanner-tcp, port-scanner-tcp, ssh-bruteforce, port-scanner-tcp, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, port-scanner-tcp, ssh-bruteforce
- **snort**: port-scanner-tcp, sql-injection, sql-injection, sql-injection, dns-tunneling, sql-injection, sql-injection, sql-injection, dos-http-simple, idor-path-traversal, idor-path-traversal, sql-injection, dns-tunneling, idor-path-traversal, port-scanner-tcp, port-scanner-tcp, idor-path-traversal, sql-injection, dos-http-simple, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, dos-http-simple, sql-injection, dns-tunneling, idor-path-traversal, ssh-bruteforce, idor-path-traversal, dns-tunneling, dns-tunneling, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, sql-injection, port-scanner-tcp, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, dos-http-simple, port-scanner-tcp, sql-injection, port-scanner-tcp, sql-injection, idor-path-traversal, idor-path-traversal, dns-tunneling, dns-tunneling, dns-tunneling, dos-http-simple, port-scanner-tcp, idor-path-traversal, port-scanner-tcp, dns-tunneling, dos-http-simple, dos-http-simple, dos-http-simple, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, port-scanner-tcp, port-scanner-tcp, dns-tunneling, dns-tunneling, ssh-bruteforce, port-scanner-tcp, sql-injection, sql-injection, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, dos-http-simple, idor-path-traversal, ssh-bruteforce, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, sql-injection, port-scanner-tcp, ssh-bruteforce, dos-http-simple
- **zeek**: icmp-flood, dos-http-simple, icmp-flood, dos-http-simple, icmp-flood, icmp-flood, syn-flood, dos-http-simple, xss-scanner, xss-scanner, xss-scanner, ssh-bruteforce, ssh-bruteforce, udp-flood, xss-scanner, udp-flood, ssh-bruteforce, dos-http-simple, syn-flood, dns-tunneling, sql-injection, dns-tunneling, idor-path-traversal, ssh-bruteforce, xss-scanner, syn-flood, syn-flood, dos-http-simple, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, syn-flood, ssh-bruteforce, xss-scanner, dos-http-simple, icmp-flood, icmp-flood, udp-flood, sql-injection, idor-path-traversal, icmp-flood, syn-flood, dos-http-simple, icmp-flood, icmp-flood, dns-tunneling, dos-http-simple, icmp-flood, dos-http-simple, dos-http-simple, dos-http-simple, dos-http-simple, icmp-flood, ssh-bruteforce, xss-scanner, ssh-bruteforce, syn-flood, dns-tunneling, ssh-bruteforce, port-scanner-tcp, udp-flood, udp-flood, dos-http-simple, sql-injection, idor-path-traversal, icmp-flood, port-scanner-tcp, ssh-bruteforce, icmp-flood, dos-http-simple, idor-path-traversal, ssh-bruteforce, udp-flood, syn-flood, idor-path-traversal, syn-flood, port-scanner-tcp, icmp-flood, ssh-bruteforce, icmp-flood, xss-scanner, sql-injection, xss-scanner, udp-flood, udp-flood, syn-flood, port-scanner-tcp, ssh-bruteforce, dos-http-simple, dns-tunneling
- **orquestracao**: dos-http-simple, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, idor-path-traversal, dos-http-simple, dos-http-simple, dos-http-simple, ssh-bruteforce, ssh-bruteforce, ssh-bruteforce, port-scanner-tcp, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, idor-path-traversal, ssh-bruteforce, idor-path-traversal, port-scanner-tcp, ssh-bruteforce, port-scanner-tcp, ssh-bruteforce

## Falsos Positivos (tráfego benigno que gerou alerta)

- **suricata**: nenhum ✅
- **snort**: nenhum ✅
- **zeek**: benigno-http, benigno-scan, benigno-scan, benigno-mix, benigno-mix, benigno-mix, benigno-icmp, benigno-dns
- **orquestracao**: benigno-http, benigno-scan, benigno-scan, benigno-mix, benigno-mix, benigno-mix, benigno-icmp, benigno-dns

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
| icmp-flood | 4 | 6395 | 0 |
| port-scanner-tcp | 0 | 0 | 1956 |
| sql-injection | 2 | 0 | 2 |
| port-scanner-tcp | 0 | 0 | 1956 |
| udp-flood | 29639 | 18475 | 11771 |
| icmp-flood | 4 | 7546 | 0 |
| udp-flood | 31543 | 18862 | 0 |
| sql-injection | 2 | 0 | 0 |
| idor-path-traversal | 0 | 0 | 0 |
| icmp-flood | 4 | 5818 | 0 |
| syn-flood | 2 | 344 | 0 |
| idor-path-traversal | 0 | 0 | 598 |
| dns-tunneling | 204 | 52 | 182 |
| dns-tunneling | 204 | 0 | 200 |
| udp-flood | 31055 | 19018 | 11317 |
| dos-http-simple | 53 | 70 | 0 |
| icmp-flood | 4 | 7657 | 0 |
| icmp-flood | 4 | 8060 | 0 |
| dns-tunneling | 204 | 0 | 0 |
| dns-tunneling | 204 | 0 | 200 |
| dos-http-simple | 0 | 0 | 0 |
| port-scanner-tcp | 0 | 0 | 1966 |
| idor-path-traversal | 0 | 0 | 598 |
| port-scanner-tcp | 0 | 0 | 1957 |
| syn-flood | 2 | 322 | 38 |
| dns-tunneling | 204 | 0 | 179 |
| icmp-flood | 4 | 7449 | 0 |
| dos-http-simple | 44 | 70 | 0 |
| dos-http-simple | 0 | 0 | 0 |
| udp-flood | 28444 | 18010 | 11999 |
| dos-http-simple | 11 | 0 | 0 |
| dos-http-simple | 0 | 0 | 0 |
| icmp-flood | 4 | 8154 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| xss-scanner | 2 | 2 | 0 |
| idor-path-traversal | 0 | 0 | 598 |
| ssh-bruteforce | 0 | 0 | 0 |
| port-scanner-tcp | 0 | 0 | 1958 |
| port-scanner-tcp | 0 | 0 | 1956 |
| dns-tunneling | 204 | 0 | 187 |
| udp-flood | 26557 | 17899 | 11999 |
| syn-flood | 1 | 262 | 0 |
| dns-tunneling | 204 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| port-scanner-tcp | 0 | 0 | 0 |
| udp-flood | 30750 | 18988 | 0 |
| udp-flood | 28094 | 18793 | 0 |
| dos-http-simple | 24 | 58 | 0 |
| sql-injection | 2 | 0 | 0 |
| xss-scanner | 2 | 2 | 2 |
| sql-injection | 2 | 0 | 2 |
| xss-scanner | 2 | 2 | 2 |
| udp-flood | 29421 | 18359 | 1054 |
| idor-path-traversal | 0 | 0 | 0 |
| icmp-flood | 4 | 8452 | 0 |
| port-scanner-tcp | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| icmp-flood | 4 | 8474 | 0 |
| dos-http-simple | 15 | 0 | 0 |
| idor-path-traversal | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| udp-flood | 32924 | 18019 | 0 |
| syn-flood | 1 | 252 | 0 |
| idor-path-traversal | 0 | 0 | 0 |
| syn-flood | 2 | 349 | 0 |
| port-scanner-tcp | 0 | 0 | 0 |
| icmp-flood | 4 | 4473 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| icmp-flood | 4 | 6585 | 0 |
| xss-scanner | 2 | 2 | 0 |
| sql-injection | 2 | 0 | 0 |
| xss-scanner | 2 | 2 | 0 |
| udp-flood | 31527 | 20074 | 0 |
| udp-flood | 37013 | 22573 | 0 |
| syn-flood | 2 | 308 | 0 |
| port-scanner-tcp | 0 | 0 | 0 |
| ssh-bruteforce | 0 | 0 | 0 |
| dos-http-simple | 3 | 0 | 0 |
| dns-tunneling | 204 | 55 | 0 |
