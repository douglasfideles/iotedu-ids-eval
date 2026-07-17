# Classificação por família — campanha02

- Janelas: **118** (71 maliciosas, 47 benignas)

## Rótulos por IDS (unidade = janela)

| IDS | TP | ERRO_CLASSIF | FN_PURO | FP | TN |
|---|--:|--:|--:|--:|--:|
| **suricata** | 49 | 9 | 13 | 0 | 47 |
| **snort** | 31 | 18 | 22 | 0 | 47 |
| **zeek** | 36 | 6 | 29 | 6 | 41 |

> **ERRO_CLASSIF** = houve detecção, mas com assinatura de OUTRA família (nem falso negativo puro, nem falso positivo). Ver matriz de confusão.

## Erros de classificação (ataque real → assinatura disparada)

| Cenário | IDS | Família correta | Classificada como | Janela |
|---|---|---|---|---|
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r06 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r04 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r05 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r01 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r15 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r12 |
| dos-http-simple | suricata | dos-http | flood-syn | campanha02-dos-http-simple-malicioso-r15 |
| dos-http-simple | zeek | dos-http | flood-icmp | campanha02-dos-http-simple-malicioso-r15 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r10 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r10 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r02 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r02 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r13 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r12 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r12 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r08 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r07 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r07 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r14 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r05 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r05 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r03 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r11 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r11 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r15 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r15 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r11 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r14 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r14 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r12 |
| dos-http-simple | zeek | dos-http | scan | campanha02-dos-http-simple-malicioso-r13 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r11 |
| ssh-bruteforce | zeek | ssh-brute | scan | campanha02-ssh-bruteforce-malicioso-r01 |
