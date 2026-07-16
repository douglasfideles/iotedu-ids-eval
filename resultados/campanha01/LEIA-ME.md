# Campanha 01 — Resultados de Eficácia dos IDS (IoTEdu)

Campanha piloto medindo a eficácia de detecção de **Suricata, Snort e Zeek** contra ataques
à aplicação IoTEdu (backend :8000 / frontend :3000), em **janelas rotuladas** (maliciosa/benigna).
Gerada com a ferramenta em `../../ferramenta_captura/`.

## Ambiente
- Regras: as canônicas do repositório **ataques-regras-e-assinaturas** (Snort 32, Suricata 32, Zeek 42).
- Interface monitorada: bridge da rede docker da app (os 3 IDS em `network_mode: host`).
- Unidade de classificação: janela rotulada. IDS "detectou" = ≥1 alerta na janela (filtrado pelo IP do atacante).
- 8 cenários × (1 maliciosa + 1 benigna) = **16 janelas**.

## Arquivos
- `consolidados/execucoes.csv` — uma linha por janela (contagem de alertas por IDS).
- `consolidados/metricas.csv` — TP/FP/TN/FN + precisão, recall, especificidade, F1, FPR, FNR, acurácia balanceada.
- `consolidados/relatorio.md` — relatório legível (destaca FN e FP).
- `regras/hashes.txt` — freeze (sha256) das regras usadas.

## Resultados (resumo)

| IDS | Recall | FPR | F1 | Acur.Bal. |
|---|--:|--:|--:|--:|
| Suricata | 0.750 | **0.000** | 0.857 | 0.875 |
| Snort | 0.750 | 0.125 | 0.800 | 0.812 |
| Zeek | **0.875** | 0.375 | 0.778 | 0.750 |
| **Orquestração** | **1.000** | 0.500 | 0.800 | 0.750 |

**Principal achado:** a **orquestração dos 3 IDS detecta 100% dos ataques (FN = 0)** — nenhum IDS
sozinho consegue isso. Suricata é o mais **preciso** (0 falso-positivo); Zeek tem o maior **recall**
(pega scans furtivos que os outros perdem), ao custo de mais falso-positivo (detecção comportamental).

### Falsos Negativos (por IDS)
- Suricata: port-scan, udp-flood
- Snort: http-flood, port-scan
- Zeek: icmp-flood
- Orquestração: **nenhum**

## Ressalvas de interpretação
- **Scans** (nmap -sS) são detectados sobretudo pelo **Zeek** (comportamental); as regras de rate do
  Snort/Suricata exigem alta taxa de SYN e podem não disparar em varreduras moderadas — resultado real.
- **http-flood** contra a porta 8000: as regras `dos-http` do Snort são fixas em `[80,443,8080]` →
  Snort não dispara (FN legítimo por porta), enquanto Suricata (`alert http any any`) e Zeek pegam.
- Os cenários de **flood** miram as portas que as regras cobrem (ex.: SYN flood → 80), refletindo
  o comportamento de um atacante que inunda portas comuns.
- Piloto: 1 repetição por cenário. Para métricas estatísticas, repetir (ex.: 15×) por cenário.
