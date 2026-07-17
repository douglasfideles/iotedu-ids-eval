# Classificação por família — campanha02

- Janelas: **16** (10 maliciosas, 6 benignas)

## Rótulos por IDS (unidade = janela)

| IDS | TP | ERRO_CLASSIF | FN_PURO | FP | TN |
|---|--:|--:|--:|--:|--:|
| **suricata** | 7 | 1 | 2 | 0 | 6 |
| **snort** | 4 | 2 | 4 | 0 | 6 |
| **zeek** | 1 | 1 | 8 | 0 | 6 |

> **ERRO_CLASSIF** = houve detecção, mas com assinatura de OUTRA família (nem falso negativo puro, nem falso positivo). Ver matriz de confusão.

## Erros de classificação (ataque real → assinatura disparada)

| Cenário | IDS | Família correta | Classificada como | Janela |
|---|---|---|---|---|
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r01 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r01 |
