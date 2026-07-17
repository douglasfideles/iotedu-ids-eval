# Campanha 02 — Avaliação de IDS por interface de rede (sem IoTEdu)

Avalia a eficácia dos 3 IDS (**Suricata, Snort, Zeek**) diante de tráfego capturado
numa interface de rede, **sem subir a aplicação IoTEdu**. Os ataques (10, do repositório
`sbcup2026-ataques`) atingem **alvos leves genéricos** numa rede docker dedicada que os
IDS farejam — nunca as APIs do IoTEdu. Cobre detecção, **falsos positivos** (tráfego
benigno), **repetições + estatística (IC 95%)** e **erro de classificação** (o IDS detecta
mas atribui assinatura de outra família).

## Topologia

```
rede docker  ids-eval-net (172.30.0.0/24)   <-- farejada por br-<netid>
  ├── alvo http  172.30.0.5:80   (sbcup26-servidor-http-server)
  ├── alvo ssh   172.30.0.6:22   (sbcup26-servidor-ssh-server)
  ├── atacante   172.30.0.10     (sbcup26-ataque-<slug>, por janela)
  ├── benigno    172.30.0.20     (iotedu-lab: curl/dig/nping legítimos)
  └── flush      172.30.0.250    (rajada descartável p/ esvaziar buffer; não contada)

IDS (network_mode: host) do mvpv1-snapshot, subidos com IDS_INTERFACE=br-<netid>.
```

## Os 10 ataques e a família intencionada

| Cenário (slug sbcup26) | Família | Alvo |
|---|---|---|
| icmp-flood | flood-icmp | 172.30.0.5 |
| syn-flood | flood-syn | 172.30.0.5:80 |
| udp-flood | flood-udp | 172.30.0.5:80 |
| dos-http-simple | dos-http | 172.30.0.5:80 |
| sql-injection | sqli | 172.30.0.5:80 |
| xss-scanner | xss | 172.30.0.5:80 |
| idor-path-traversal | path-traversal | 172.30.0.5:80 |
| port-scanner-tcp | scan | 172.30.0.5 |
| ssh-bruteforce | ssh-brute | 172.30.0.6:22 |
| dns-tunneling | dns-tunneling | resolvers públicos |

Benigno (avaliação de FP), tráfego legítimo do ambiente: `benigno-{icmp,http,dns,ssh,scan,mix}`.

## Como rodar

Pré-requisitos: Docker no ar; imagens dos IDS (`mvpv1-snapshot-*_ids`, `zeek`), do
`iotedu-lab`, dos 10 atacantes (`sbcup26-ataque-*`) e dos 2 alvos (`sbcup26-servidor-*`).
Construir imagens que faltarem: `sbcup2026-ataques/docker/build-images.sh` (ou seletivo).

```bash
cd iotedu-ids-eval/campanha02

# 1) prepara: rede + alvos + IDS (force-recreate) + freeze de hashes
./rodar-campanha.sh preparar

# 2) PILOTO (1 rep por cenário) — valida a cadeia antes da campanha longa
./rodar-campanha.sh piloto

# 3) CAMPANHA COMPLETA (15 reps + ~2h benigno, ordem aleatória)
REPS=15 ./rodar-campanha.sh completa

# (re)gerar só os relatórios a partir das janelas já capturadas
./rodar-campanha.sh analisar

# encerrar (remove alvos e a rede; IDS seguem de pé)
./rodar-campanha.sh parar
```

Variáveis úteis: `REPS`, `BENIGN_DUR` (s/janela benigna), `SETTLE`, `ATTACK_MAX`,
`PCAP=0/1`, `FLUSH=0/1`, IPs (`HTTP_IP`, `SSH_IP`, `ATT_IP`, ...).

> ⚠️ **NUNCA** `docker restart` nos IDS (host-net) — perdem a interface em silêncio.
> O orquestrador usa `docker compose up -d --force-recreate`.

## Saídas

```
campanha02/
  execucoes/<execucao_id>/   fatias por IDS (suricata.jsonl, snort.txt, zeek.txt),
                             trafego.pcap, gerador.stdout, manifesto.yaml
  consolidados/
    windows.csv              1 linha por janela (metadados + pcap_pacotes)
    execucoes.csv            contagens família-corretas p/ metricas.py
    metricas.csv             TP/FP/TN/FN + precisão/recall/F1/FPR por IDS+orquestração
    classificacao_detalhe.csv  rótulo por (janela,IDS): TP|ERRO_CLASSIF|FN_PURO|FP|TN
    matriz_confusao.csv      família intencionada × prevista (janelas maliciosas)
    estatistica.csv          por cenário/IDS: taxa de detecção + IC95, erro-classif, FN, FP
    classificacao.md         resumo + tabela de erros de classificação
  regras/hashes.txt          freeze (sha256 de regras/imagens/scripts)
  RELATORIO.md               relatório final (horas, pacotes, tipos de tráfego, análises)
```

## Componentes

- `rodar-campanha.sh` — orquestrador (infra, janelas isoladas, artefatos, análise).
- `benigno.sh` — gera tráfego benigno legítimo por família (baixa taxa) p/ avaliar FP.
- `mapa-assinaturas.yaml` — mapa `msg → família` (regex) + família intencionada por cenário.
- `classificar.py` — classifica alertas por família; separa TP / **ERRO_CLASSIF** / FN puro / FP / TN.
- `estatistica.py` — agrega repetições; taxa de detecção com **IC 95% de Wilson**, erro-classif, FP.
- `gera_relatorio.py` — monta `RELATORIO.md` (horas, pacotes, tipos de tráfego, tabelas).
- Reúsa `../ferramenta_captura/metricas.py` para as métricas binárias por IDS.

## Tratamento do erro de classificação

Se um ataque é detectado mas com assinatura de **outra família** (ex.: flood rotulado
como SQLi), a janela é marcada **ERRO_CLASSIF** — não é falso negativo (houve detecção)
nem falso positivo. Fica na matriz de confusão e na §4 do relatório. Nas métricas binárias
(`metricas.csv`) ela não conta como TP (contagem família-correta = 0).
