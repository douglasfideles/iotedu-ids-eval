# Classificação por família — campanha02

- Janelas: **240** (150 maliciosas, 90 benignas)

## Rótulos por IDS (unidade = janela)

| IDS | TP | ERRO_CLASSIF | FN_PURO | FP | TN |
|---|--:|--:|--:|--:|--:|
| **suricata** | 101 | 19 | 30 | 0 | 90 |
| **snort** | 69 | 30 | 51 | 0 | 90 |
| **zeek** | 60 | 8 | 82 | 8 | 82 |

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
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r10 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r02 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r09 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r09 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r14 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r13 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r13 |
| dos-http-simple | suricata | dos-http | flood-syn | campanha02-dos-http-simple-malicioso-r07 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r06 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r06 |
| icmp-flood | zeek | flood-icmp | scan | campanha02-icmp-flood-malicioso-r10 |
| dos-http-simple | suricata | dos-http | flood-syn | campanha02-dos-http-simple-malicioso-r14 |
| dos-http-simple | suricata | dos-http | flood-syn | campanha02-dos-http-simple-malicioso-r10 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r07 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r09 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r08 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r08 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r03 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r03 |
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r04 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r04 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r08 |
