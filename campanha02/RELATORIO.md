# Relatório — Campanha 02 (avaliação de IDS por interface de rede)

Ataques gerados a partir de `sbcup2026-ataques` contra alvos leves numa rede docker farejada pelos 3 IDS (Suricata, Snort, Zeek). **Sem a aplicação IoTEdu** — avaliação de como as regras se comportam diante do tráfego capturado.

## 0. Metodologia e detalhes do experimento

**Objetivo.** Medir a eficácia de detecção dos IDS (e da orquestração dos três) frente a tráfego malicioso e benigno numa interface de rede, avaliando também falsos positivos e **erros de classificação** (detecção com assinatura de família errada).

**Topologia.** Rede docker dedicada `ids-eval-net` (172.30.0.0/24) farejada pela bridge `br-<netid>`. Na mesma rede: alvos leves (HTTP `172.30.0.5:80`, SSH `172.30.0.6:22`), o atacante (`172.30.0.10`), o gerador benigno (`172.30.0.20`) e um IP de *flush* descartável (`172.30.0.250`, nunca contado). Os IDS rodam em `network_mode: host` (Suricata/Snort/Zeek do `mvpv1-snapshot`), recriados com `--force-recreate` (nunca `restart`). **A aplicação IoTEdu (back/front) não é usada.**

**Unidade de análise.** A *janela rotulada*: uma execução isolada de UM cenário (malicioso ou benigno), sem tráfego concorrente. Por janela salvam-se as fatias de alertas de cada IDS (por *byte-offset* + filtro de *timestamp*, que remove notices do Zeek escritos em lote e evita vazamento entre janelas), o PCAP, o stdout do gerador e um manifesto.

**Os 10 ataques (família intencionada) e os 6 cenários benignos:**

| Ataque (sbcup26) | Família | Alvo | | Benigno | Tráfego legítimo |
|---|---|---|---|---|---|
| icmp-flood | flood-icmp | .5 | | benigno-icmp | ping baixa taxa |
| syn-flood | flood-syn | .5:80 | | benigno-http | GETs HTTP normais |
| udp-flood | flood-udp | .5:80 | | benigno-dns | consultas DNS legítimas |
| dos-http-simple | dos-http | .5:80 | | benigno-ssh | conexões SSH pontuais |
| sql-injection | sqli | .5:80 | | benigno-scan | acesso normal a 1 serviço |
| xss-scanner | xss | .5:80 | | benigno-mix | HTTP+DNS+ICMP+SSH leves |
| idor-path-traversal | path-traversal | .5:80 | | | |
| port-scanner-tcp | scan | .5 | | | |
| ssh-bruteforce | ssh-brute | .6:22 | | | |
| dns-tunneling | dns-tunneling | resolvers públicos | | | |

**Classificação por janela e IDS.** `TP` = ≥1 alerta da família correta; `FN_PURO` = nenhum alerta de ataque; `ERRO_CLASSIF` = detectou, mas só com assinatura de **outra** família (nem TP, nem FN puro); `FP` = janela benigna com qualquer alerta de ataque; `TN` = benigna sem alerta. A rajada de *flush* e alertas fora do intervalo da janela são descartados.

**Métricas.** Precisão, Recall (sensibilidade), Especificidade, F1, FPR, FNR, acurácia balanceada — por IDS e para a **orquestração** (detecta se qualquer IDS detecta). Denominador zero ⇒ métrica indefinida (nunca forçada a 0). As repetições são agregadas com **intervalo de confiança de Wilson 95%**.

## 1. Resumo da captura

- **Janelas avaliadas:** 118 (71 maliciosas, 47 benignas)
- **Horas de captura (total):** 3.58 h  (maliciosa: 1.98 h · benigna: 1.61 h)
- **Pacotes capturados (total):** 3,016,036 (maliciosa: 3,004,250 · benigna: 11,786)
- **Tipos de tráfego malicioso (10):** dns-tunneling, dos-http-simple, icmp-flood, idor-path-traversal, port-scanner-tcp, sql-injection, ssh-bruteforce, syn-flood, udp-flood, xss-scanner
- **Tipos de tráfego benigno (6):** benigno-dns, benigno-http, benigno-icmp, benigno-mix, benigno-scan, benigno-ssh

### Janelas e horas por cenário

| Cenário | Classe | Repetições | Horas | Pacotes |
|---|---|--:|--:|--:|
| benigno-dns | benigno | 7 | 0.25 | 21 |
| benigno-http | benigno | 8 | 0.28 | 6,361 |
| benigno-icmp | benigno | 7 | 0.23 | 1,193 |
| benigno-mix | benigno | 12 | 0.40 | 2,880 |
| benigno-scan | benigno | 5 | 0.18 | 879 |
| benigno-ssh | benigno | 8 | 0.27 | 452 |
| dns-tunneling | malicioso | 7 | 0.17 | 2,869 |
| dos-http-simple | malicioso | 6 | 0.11 | 12,030 |
| icmp-flood | malicioso | 4 | 0.07 | 1,908,912 |
| idor-path-traversal | malicioso | 8 | 0.11 | 24,293 |
| port-scanner-tcp | malicioso | 5 | 0.06 | 10,058 |
| sql-injection | malicioso | 10 | 0.81 | 116,533 |
| ssh-bruteforce | malicioso | 8 | 0.24 | 8,383 |
| syn-flood | malicioso | 9 | 0.15 | 9,415 |
| udp-flood | malicioso | 4 | 0.08 | 902,640 |
| xss-scanner | malicioso | 10 | 0.16 | 9,117 |

## 2. Métricas de detecção (família-correta) por IDS

> Detecção = ≥1 alerta com assinatura da **família correta**. Alertas de família errada NÃO contam como TP (ver §4).

| Alvo | TP | FP | TN | FN | Precisão | Recall | Especif. | F1 | FPR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 49 | 0 | 47 | 22 | 1.000 | 0.690 | 1.000 | 0.817 | 0.000 | 0.845 |
| **snort** | 31 | 0 | 47 | 40 | 1.000 | 0.437 | 1.000 | 0.608 | 0.000 | 0.718 |
| **zeek** | 36 | 6 | 41 | 35 | 0.857 | 0.507 | 0.872 | 0.637 | 0.128 | 0.690 |
| **orquestracao** | 61 | 6 | 41 | 10 | 0.910 | 0.859 | 0.872 | 0.884 | 0.128 | 0.866 |

## 3. Estatística por cenário e IDS (repetições, IC 95% de Wilson)

| Cenário | Classe | IDS | n | Taxa detec. | IC95 | Erro classif. | FN puro | FP |
|---|---|---|--:|--:|:--:|--:|--:|--:|
| benigno-dns | benigno | snort | 7 | — | — | — | — | 0.000 |
| benigno-dns | benigno | suricata | 7 | — | — | — | — | 0.000 |
| benigno-dns | benigno | zeek | 7 | — | — | — | — | 0.000 |
| benigno-http | benigno | snort | 8 | — | — | — | — | 0.000 |
| benigno-http | benigno | suricata | 8 | — | — | — | — | 0.000 |
| benigno-http | benigno | zeek | 8 | — | — | — | — | 0.125 |
| benigno-icmp | benigno | snort | 7 | — | — | — | — | 0.000 |
| benigno-icmp | benigno | suricata | 7 | — | — | — | — | 0.000 |
| benigno-icmp | benigno | zeek | 7 | — | — | — | — | 0.000 |
| benigno-mix | benigno | snort | 12 | — | — | — | — | 0.000 |
| benigno-mix | benigno | suricata | 12 | — | — | — | — | 0.000 |
| benigno-mix | benigno | zeek | 12 | — | — | — | — | 0.250 |
| benigno-scan | benigno | snort | 5 | — | — | — | — | 0.000 |
| benigno-scan | benigno | suricata | 5 | — | — | — | — | 0.000 |
| benigno-scan | benigno | zeek | 5 | — | — | — | — | 0.400 |
| benigno-ssh | benigno | snort | 8 | — | — | — | — | 0.000 |
| benigno-ssh | benigno | suricata | 8 | — | — | — | — | 0.000 |
| benigno-ssh | benigno | zeek | 8 | — | — | — | — | 0.000 |
| dns-tunneling | malicioso | snort | 7 | 0.286 | [0.082, 0.641] | 0.000 | 0.714 | — |
| dns-tunneling | malicioso | suricata | 7 | 1.000 | [0.646, 1.000] | 0.000 | 0.000 | — |
| dns-tunneling | malicioso | zeek | 7 | 0.714 | [0.359, 0.918] | 0.000 | 0.286 | — |
| dos-http-simple | malicioso | snort | 6 | 0.333 | [0.097, 0.700] | 0.000 | 0.667 | — |
| dos-http-simple | malicioso | suricata | 6 | 0.833 | [0.436, 0.970] | 0.167 | 0.000 | — |
| dos-http-simple | malicioso | zeek | 6 | 0.000 | [0.000, 0.390] | 0.333 | 0.667 | — |
| icmp-flood | malicioso | snort | 4 | 1.000 | [0.510, 1.000] | 0.000 | 0.000 | — |
| icmp-flood | malicioso | suricata | 4 | 1.000 | [0.510, 1.000] | 0.000 | 0.000 | — |
| icmp-flood | malicioso | zeek | 4 | 0.000 | [0.000, 0.490] | 0.000 | 1.000 | — |
| idor-path-traversal | malicioso | snort | 8 | 0.000 | [0.000, 0.324] | 1.000 | 0.000 | — |
| idor-path-traversal | malicioso | suricata | 8 | 0.000 | [0.000, 0.324] | 1.000 | 0.000 | — |
| idor-path-traversal | malicioso | zeek | 8 | 0.875 | [0.529, 0.978] | 0.000 | 0.125 | — |
| port-scanner-tcp | malicioso | snort | 5 | 0.000 | [0.000, 0.434] | 0.000 | 1.000 | — |
| port-scanner-tcp | malicioso | suricata | 5 | 0.000 | [0.000, 0.434] | 0.000 | 1.000 | — |
| port-scanner-tcp | malicioso | zeek | 5 | 1.000 | [0.566, 1.000] | 0.000 | 0.000 | — |
| sql-injection | malicioso | snort | 10 | 0.000 | [0.000, 0.278] | 1.000 | 0.000 | — |
| sql-injection | malicioso | suricata | 10 | 1.000 | [0.722, 1.000] | 0.000 | 0.000 | — |
| sql-injection | malicioso | zeek | 10 | 0.900 | [0.596, 0.982] | 0.000 | 0.100 | — |
| ssh-bruteforce | malicioso | snort | 8 | 0.000 | [0.000, 0.324] | 0.000 | 1.000 | — |
| ssh-bruteforce | malicioso | suricata | 8 | 0.000 | [0.000, 0.324] | 0.000 | 1.000 | — |
| ssh-bruteforce | malicioso | zeek | 8 | 0.000 | [0.000, 0.324] | 0.125 | 0.875 | — |
| syn-flood | malicioso | snort | 9 | 1.000 | [0.701, 1.000] | 0.000 | 0.000 | — |
| syn-flood | malicioso | suricata | 9 | 1.000 | [0.701, 1.000] | 0.000 | 0.000 | — |
| syn-flood | malicioso | zeek | 9 | 0.444 | [0.189, 0.733] | 0.333 | 0.222 | — |
| udp-flood | malicioso | snort | 4 | 1.000 | [0.510, 1.000] | 0.000 | 0.000 | — |
| udp-flood | malicioso | suricata | 4 | 1.000 | [0.510, 1.000] | 0.000 | 0.000 | — |
| udp-flood | malicioso | zeek | 4 | 0.500 | [0.150, 0.850] | 0.000 | 0.500 | — |
| xss-scanner | malicioso | snort | 10 | 1.000 | [0.722, 1.000] | 0.000 | 0.000 | — |
| xss-scanner | malicioso | suricata | 10 | 1.000 | [0.722, 1.000] | 0.000 | 0.000 | — |
| xss-scanner | malicioso | zeek | 10 | 0.400 | [0.168, 0.687] | 0.000 | 0.600 | — |

## 4. Erros de classificação (detecção com assinatura errada)

Casos em que o IDS **detectou** o ataque mas atribuiu assinatura de **outra família** (ex.: flood classificado como SQLi). Não é falso negativo (houve detecção) nem falso positivo. Tratado como categoria própria.

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

### Matriz de confusão (família intencionada × prevista, janelas maliciosas)

| intencionada\prevista | NENHUM | dns-tunneling | dos-http | flood-icmp | flood-syn | flood-udp | path-traversal | scan | sqli | xss |
|---|---|---|---|---|---|---|---|---|---|---|
| dns-tunneling | 7 | 14 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| dos-http | 8 | 0 | 7 | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| flood-icmp | 4 | 0 | 0 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| flood-syn | 2 | 0 | 0 | 0 | 22 | 0 | 0 | 3 | 0 | 0 |
| flood-udp | 2 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0 |
| path-traversal | 1 | 0 | 16 | 0 | 0 | 0 | 7 | 0 | 0 | 0 |
| scan | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 5 | 0 | 0 |
| sqli | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 19 | 10 |
| ssh-brute | 23 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| xss | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 24 |

## 5. Falsos positivos no tráfego benigno

| Cenário benigno | IDS | Família(s) alertada(s) | Janela |
|---|---|---|---|
| benigno-http | zeek | scan | campanha02-benigno-http-benigno-r01 |
| benigno-scan | zeek | flood-icmp | campanha02-benigno-scan-benigno-r13 |
| benigno-scan | zeek | flood-icmp | campanha02-benigno-scan-benigno-r04 |
| benigno-mix | zeek | scan | campanha02-benigno-mix-benigno-r01 |
| benigno-mix | zeek | scan | campanha02-benigno-mix-benigno-r08 |
| benigno-mix | zeek | scan | campanha02-benigno-mix-benigno-r15 |

## 6. Síntese por questão de pesquisa

- **RQ1 — Eficácia por IDS.** Recall (detecção família-correta): Suricata 0.690, Snort 0.437, Zeek 0.507; orquestração 0.859.
- **RQ2 — Piores falsos negativos.** Cenários não detectados por nenhum IDS (sem cobertura efetiva): ssh-bruteforce.
- **RQ3 — Falsos positivos (tráfego benigno).** 6 janela(s) benigna(s) com alerta indevido (cenários: benigno-http, benigno-mix, benigno-scan). FP por IDS: Suricata 0, Snort 0, Zeek 6.
- **RQ4 — Orquestração.** Recall combinado 0.859 vs. melhor IDS isolado 0.690 → ganho de +0.169. Combinar os três aumenta a cobertura.
- **RQ5 — Regras problemáticas / erro de classificação.** 33 janela(s) com detecção de família errada. Pares observados: dos-http→flood-icmp (zeek); dos-http→flood-syn (suricata); dos-http→scan (zeek); flood-syn→scan (zeek); path-traversal→dos-http (snort); path-traversal→dos-http (suricata); sqli→xss (snort); ssh-brute→scan (zeek). Ver §4 e a matriz de confusão.

---
_Gerado por gera_relatorio.py (campanha02)._
