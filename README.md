# Resumo dos Testes de Eficácia dos IDS — IoTEdu

## 1. Objetivo

Medir a **eficácia de detecção** dos 3 IDS orquestrados pelo IoTEdu (**Suricata, Snort, Zeek**) contra ataques à
aplicação IoTEdu, com foco em **Falso Positivo (FP)**, **Falso Negativo (FN)** e métricas de eficácia
(precisão, recall, especificidade, F1, FPR, FNR, acurácia balanceada).

## 2. Ambiente

- **Plataforma:** IoTEdu Core (`mvpv1-snapshot`) via Docker Compose — `db` (MySQL), `backend` (FastAPI :8000),
  `frontend` (Next.js :3000) e os **3 IDS** em `network_mode: host` farejando a bridge da rede docker da app.
- **Alvo dos ataques:** a própria app IoTEdu (backend :8000 / frontend :3000).
- **Regras:** conjunto canônico do `ataques-regras-e-assinaturas` (**Snort 32, Suricata 32, Zeek 42 detectores + 12 feeds**),
  validado (`snort -T`, `suricata -T` OK; Zeek sem erro) e com hashes congelados (`regras/hashes.txt`).
- **Monitoramento:** coletor SSE (`ids_log_monitor` :8001) + captura **PCAP por janela**.

## 3. Metodologia

- **Unidade de medida:** janela rotulada (maliciosa/benigna). Um IDS "detectou" se gerou ≥1 alerta atribuído ao IP do atacante.
- **Isolamento:** IP de atacante fixo (`172.18.0.240`); contagem de alertas e PCAP filtrados por ele → permite execução em paralelo.
- **Por janela:** inicia PCAP → dispara o ataque (container com IP fixo, `NET_RAW`) → rajada de *flush* de um IP descartável
  (força Snort/Suricata a gravarem o buffer) → conta alertas por IDS.
- **Escopo:** 8 ataques × (1 janela maliciosa + 1 benigna) = **16 janelas**, **1 repetição por cenário** (piloto).

## 4. Ataques enviados — ferramenta, volume e alvo

| # | Ataque | Ferramenta | Volume enviado por sessão | Alvo |
|--:|---|---|---|---|
| 1 | **http-flood** | Apache Bench (ab) | até 100.000 GET, 200 conexões simultâneas (limitado pela janela) | backend:8000 |
| 2 | **port-scan** | nmap -sS -T4 | varredura SYN das portas 1–2000 em 2 alvos (~4.000 SYN) | backend + frontend |
| 3 | **syn-flood** | nping | 2.000 pacotes SYN a 500 pps | backend:80 |
| 4 | **udp-flood** | nping | 1.500 pacotes UDP a 400 pps | backend:53 |
| 5 | **icmp-flood** | nping | 1.500 echo-request ICMP a 400 pps | backend |
| 6 | **sql-injection** | curl (loop contínuo) | 2 payloads/iteração (UNION SELECT / OR 1=1) por toda a janela | backend:8000 |
| 7 | **xss-scanner** | curl (loop contínuo) | payload <script>alert(1)</script> por toda a janela | backend:8000 |
| 8 | **path-traversal** | curl (loop contínuo) | 2 payloads/iteração (../../etc/passwd) por toda a janela | backend:8000 |

## 5. Execução — janelas MALICIOSAS (duração, pacotes e alertas por IDS)

| Ataque | Duração (s) | Pacotes | Suricata | Snort | Zeek | Detectado por |
|---|--:|--:|--:|--:|--:|---|
| http-flood | 39.6 | 62,649 | 12 | 0 | 67 | Suri, Zeek |
| port-scan | 17.6 | 8,017 | 0 | 0 | 8,794 | Zeek |
| syn-flood | 24.6 | 4,007 | 1,775 | 1,980 | 6,023 | Suri, Snort, Zeek |
| udp-flood | 21.9 | 1,517 | 0 | 4,250 | 1 | Snort, Zeek |
| icmp-flood | 20.1 | 3,008 | 1,470 | 4,420 | 0 | Suri, Snort |
| sql-injection | 37.0 | 17,649 | 6,424 | 4,662 | 6,825 | Suri, Snort, Zeek |
| xss-scanner | 37.0 | 18,941 | 5,920 | 4,704 | 4,540 | Suri, Snort, Zeek |
| path-traversal | 36.7 | 18,727 | 1,959 | 2,403 | 3,814 | Suri, Snort, Zeek |

*Soma das 8 janelas maliciosas: ~234 s (~3.9 min) de ataque; 134,515 pacotes capturados.*

## 6. Execução — janelas BENIGNAS (tráfego normal → alertas = Falso Positivo)

| Cenário | Duração (s) | Pacotes | Suricata | Snort | Zeek | FP? |
|---|--:|--:|--:|--:|--:|---|
| http-flood | 19.3 | 245 | 0 | 0 | 0 | não |
| port-scan | 18.8 | 71 | 0 | 0 | 2 | Zeek |
| syn-flood | 15.5 | 125 | 0 | 0 | 20 | Zeek |
| udp-flood | 26.8 | 41 | 0 | 0 | 18 | Zeek |
| icmp-flood | 22.4 | 18 | 0 | 5 | 0 | Snort |
| sql-injection | 16.6 | 185 | 0 | 0 | 0 | não |
| xss-scanner | 17.1 | 188 | 0 | 0 | 0 | não |
| path-traversal | 16.2 | 155 | 0 | 0 | 0 | não |

## 7. Métricas de eficácia (por IDS e orquestração)

| Alvo | TP | FP | TN | FN | Precisão | Recall | Especif. | F1 | FPR | FNR | Acur.Bal. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **suricata** | 6 | 0 | 8 | 2 | 1.000 | 0.750 | 1.000 | 0.857 | 0.000 | 0.250 | 0.875 |
| **snort** | 6 | 1 | 7 | 2 | 0.857 | 0.750 | 0.875 | 0.800 | 0.125 | 0.250 | 0.812 |
| **zeek** | 7 | 3 | 5 | 1 | 0.700 | 0.875 | 0.625 | 0.778 | 0.375 | 0.125 | 0.750 |
| **orquestracao** | 8 | 4 | 4 | 0 | 0.667 | 1.000 | 0.500 | 0.800 | 0.500 | 0.000 | 0.750 |

- **Falsos Negativos:** Suricata → port-scan, udp-flood · Snort → http-flood, port-scan · Zeek → icmp-flood · **Orquestração → nenhum** ✅
- **Falsos Positivos:** Suricata → nenhum ✅ · Snort → icmp-flood · Zeek → port-scan, syn-flood, udp-flood

## 8. Tempos

- **Duração total da campanha:** 02:42:31 → 03:16:01 = **~34 min** (ataques + flush + settle + cooldown entre janelas).
- **Tráfego de ataque efetivo:** ~3.9 min (só as 8 janelas maliciosas).
- **Por sessão:** ~18–40 s de ataque + ~6 s flush + 8 s settle + 4 s cooldown.
- **Pacotes capturados (16 janelas):** 135,543.
- **Build inicial das imagens (uma vez):** ~1h30–2h (Snort compilado do fonte — gargalo no WSL).

## 9. Conclusões

1. A **orquestração dos 3 IDS detecta 100% dos ataques (FN=0)** — nenhum IDS isolado consegue; é o argumento central da abordagem multi-IDS.
2. **Suricata:** mais preciso (0 FP, especificidade 1.0). **Zeek:** maior recall (pega scans furtivos), mais FP. **Snort:** forte em floods e web.
3. Ataques **web de conteúdo** (SQLi, XSS, path-traversal) foram pegos pelos **três** IDS.

## 10. Ressalvas

- `http-flood` na porta 8000: regra `dos-http` do Snort é fixa em `[80,443,8080]` → FN legítimo por porta (Suricata/Zeek pegam).
- `port-scan` (nmap): pego sobretudo pelo **Zeek**; regras de rate do Snort/Suricata exigem alta taxa de SYN.
- **Piloto de 1 repetição por cenário.** Para significância estatística, repetir (ex.: 15×).

## 11. Correções técnicas feitas durante os testes

- Init do banco (BUG-03: `start.sh` → `db.setup_database`).
- Sincronização das regras canônicas + correção de 1 SID duplicado (syn-flood `1000060`→`1000160`).
- `HTTP_PORTS` do Snort ampliado para cobrir 8000/3000.
- Descoberto que **`docker restart` quebra os IDS host-network** (perdem a interface) → usar `--force-recreate`.
- Atacantes precisam de `NET_RAW`/`NET_ADMIN`; contagem confiável exige *flush* do buffer do Snort/Suricata.

## 12. Artefatos

- Ferramenta reproduzível: `planejamentotestes/ferramenta_captura/`
- Resultados: `planejamentotestes/resultados/campanha01/` (`consolidados/`, `regras/hashes.txt`, `LEIA-ME.md`)
