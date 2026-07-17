# Relatório — Campanha 02 (avaliação de IDS por interface de rede)

Ataques gerados a partir de `sbcup2026-ataques` contra alvos leves numa rede docker farejada pelos 3 IDS (Suricata, Snort, Zeek). **Sem a aplicação IoTEdu** — avaliação de como as regras se comportam diante do tráfego capturado.

## 1. Resumo da captura

- **Janelas avaliadas:** 16 (10 maliciosas, 6 benignas)
- **Horas de captura (total):** 0.44 h  (maliciosa: 0.25 h · benigna: 0.19 h)
- **Pacotes capturados (total):** 662,105 (maliciosa: 661,002 · benigna: 1,103)
- **Tipos de tráfego malicioso (10):** dns-tunneling, dos-http-simple, icmp-flood, idor-path-traversal, port-scanner-tcp, sql-injection, ssh-bruteforce, syn-flood, udp-flood, xss-scanner
- **Tipos de tráfego benigno (6):** benigno-dns, benigno-http, benigno-icmp, benigno-mix, benigno-scan, benigno-ssh

### Janelas e horas por cenário

| Cenário | Classe | Repetições | Horas | Pacotes |
|---|---|--:|--:|--:|
| benigno-dns | benigno | 1 | 0.03 | 3 |
| benigno-http | benigno | 1 | 0.03 | 605 |
| benigno-icmp | benigno | 1 | 0.03 | 129 |
| benigno-mix | benigno | 1 | 0.03 | 189 |
| benigno-scan | benigno | 1 | 0.03 | 134 |
| benigno-ssh | benigno | 1 | 0.03 | 43 |
| dns-tunneling | malicioso | 1 | 0.03 | 407 |
| dos-http-simple | malicioso | 1 | 0.02 | 2,005 |
| icmp-flood | malicioso | 1 | 0.02 | 403,429 |
| idor-path-traversal | malicioso | 1 | 0.01 | 3,068 |
| port-scanner-tcp | malicioso | 1 | 0.01 | 2,011 |
| sql-injection | malicioso | 1 | 0.08 | 10,985 |
| ssh-bruteforce | malicioso | 1 | 0.04 | 936 |
| syn-flood | malicioso | 1 | 0.02 | 5 |
| udp-flood | malicioso | 1 | 0.01 | 237,270 |
| xss-scanner | malicioso | 1 | 0.02 | 886 |

## 2. Métricas de detecção (família-correta) por IDS

> Detecção = ≥1 alerta com assinatura da **família correta**. Alertas de família errada NÃO contam como TP (ver §4).

| Alvo | TP | FP | TN | FN | Precisão | Recall | Especif. | F1 | FPR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 7 | 0 | 6 | 3 | 1.000 | 0.700 | 1.000 | 0.824 | 0.000 | 0.850 |
| **snort** | 4 | 0 | 6 | 6 | 1.000 | 0.400 | 1.000 | 0.571 | 0.000 | 0.700 |
| **zeek** | 1 | 0 | 6 | 9 | 1.000 | 0.100 | 1.000 | 0.182 | 0.000 | 0.550 |
| **orquestracao** | 7 | 0 | 6 | 3 | 1.000 | 0.700 | 1.000 | 0.824 | 0.000 | 0.850 |

## 3. Estatística por cenário e IDS (repetições, IC 95% de Wilson)

| Cenário | Classe | IDS | n | Taxa detec. | IC95 | Erro classif. | FN puro | FP |
|---|---|---|--:|--:|:--:|--:|--:|--:|
| benigno-dns | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-dns | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-dns | benigno | zeek | 1 | — | — | — | — | 0.000 |
| benigno-http | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-http | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-http | benigno | zeek | 1 | — | — | — | — | 0.000 |
| benigno-icmp | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-icmp | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-icmp | benigno | zeek | 1 | — | — | — | — | 0.000 |
| benigno-mix | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-mix | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-mix | benigno | zeek | 1 | — | — | — | — | 0.000 |
| benigno-scan | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-scan | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-scan | benigno | zeek | 1 | — | — | — | — | 0.000 |
| benigno-ssh | benigno | snort | 1 | — | — | — | — | 0.000 |
| benigno-ssh | benigno | suricata | 1 | — | — | — | — | 0.000 |
| benigno-ssh | benigno | zeek | 1 | — | — | — | — | 0.000 |
| dns-tunneling | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| dns-tunneling | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| dns-tunneling | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| dos-http-simple | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| dos-http-simple | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| dos-http-simple | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| icmp-flood | malicioso | snort | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| icmp-flood | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| icmp-flood | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| idor-path-traversal | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 1.000 | 0.000 | — |
| idor-path-traversal | malicioso | suricata | 1 | 0.000 | [0.000, 0.793] | 1.000 | 0.000 | — |
| idor-path-traversal | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| port-scanner-tcp | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| port-scanner-tcp | malicioso | suricata | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| port-scanner-tcp | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| sql-injection | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 1.000 | 0.000 | — |
| sql-injection | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| sql-injection | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| ssh-bruteforce | malicioso | snort | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| ssh-bruteforce | malicioso | suricata | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| ssh-bruteforce | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |
| syn-flood | malicioso | snort | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| syn-flood | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| syn-flood | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 1.000 | 0.000 | — |
| udp-flood | malicioso | snort | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| udp-flood | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| udp-flood | malicioso | zeek | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| xss-scanner | malicioso | snort | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| xss-scanner | malicioso | suricata | 1 | 1.000 | [0.207, 1.000] | 0.000 | 0.000 | — |
| xss-scanner | malicioso | zeek | 1 | 0.000 | [0.000, 0.793] | 0.000 | 1.000 | — |

## 4. Erros de classificação (detecção com assinatura errada)

Casos em que o IDS **detectou** o ataque mas atribuiu assinatura de **outra família** (ex.: flood classificado como SQLi). Não é falso negativo (houve detecção) nem falso positivo. Tratado como categoria própria.

| Cenário | IDS | Família correta | Classificada como | Janela |
|---|---|---|---|---|
| idor-path-traversal | suricata | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| idor-path-traversal | snort | path-traversal | dos-http | campanha02-idor-path-traversal-malicioso-r01 |
| sql-injection | snort | sqli | xss | campanha02-sql-injection-malicioso-r01 |
| syn-flood | zeek | flood-syn | scan | campanha02-syn-flood-malicioso-r01 |

### Matriz de confusão (família intencionada × prevista, janelas maliciosas)

| intencionada\prevista | NENHUM | dns-tunneling | dos-http | flood-icmp | flood-syn | flood-udp | scan | sqli | xss |
|---|---|---|---|---|---|---|---|---|---|
| dns-tunneling | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| dos-http | 2 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| flood-icmp | 1 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| flood-syn | 0 | 0 | 0 | 0 | 2 | 0 | 1 | 0 | 0 |
| flood-udp | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 |
| path-traversal | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| scan | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| sqli | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| ssh-brute | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| xss | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 |

## 5. Falsos positivos no tráfego benigno

Nenhum falso positivo observado no tráfego benigno. ✅

---
_Gerado por gera_relatorio.py (campanha02)._
