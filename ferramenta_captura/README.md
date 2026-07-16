# Ferramenta de Captura IoTEdu — medir FP / FN / eficácia dos IDS

Você roda **os seus ataques**; esta ferramenta apenas **captura os alertas dos IDS**
(Suricata, Snort, Zeek) durante o ataque e, no fim, gera **CSV + relatórios** de
**Falso Positivo (FP)**, **Falso Negativo (FN)** e métricas de eficácia
(precisão, recall/sensibilidade, especificidade, F1, FPR, FNR, acurácia balanceada),
por IDS e para a **orquestração** (qualquer IDS).

Funciona em **Linux** (Docker nativo ou Docker Desktop/WSL2). Caminhos, rede e logs dos
IDS são **auto-detectados** — pode rodar esta pasta de qualquer lugar.

## Arquivos

| Arquivo | Precisa? | Para quê |
|---|---|---|
| **`capturar.sh`** | **sim** | O script que você usa: marca a janela, conta alertas, gera relatórios |
| **`metricas.py`** | **sim** | Gera `metricas.csv` + `relatorio.md` (chamado pelo `capturar.sh relatorio`) |
| `Dockerfile.lab` | **opcional** | Só se quiser: (a) o **flush** automático, (b) `PCAP=1`, ou (c) um container atacante pronto |

> **Mínimo = `capturar.sh` + `metricas.py`.** O `Dockerfile.lab` é opcional: ele constrói a
> imagem `iotedu-lab` usada pelo **flush** (uma rajada que força Snort/Suricata a gravarem
> alertas de ataques de volume *moderado*). Se você **não** o tiver, rode com `FLUSH=0` — nesse
> caso, prefira ataques **fortes/sustentados** (floods), que os IDS gravam sozinhos. Se quiser
> medir bem scans e ataques leves, construa o `Dockerfile.lab` e deixe o flush ligado (padrão).

## Pré-requisitos

- A stack IoTEdu + os 3 IDS já **no ar e capturando** (quem hospeda cuida disso).
- Docker e `python3` na máquina.
- (Opcional, p/ flush/PCAP/atacante) construir a imagem uma vez:
  ```bash
  docker build -t iotedu-lab:latest -f Dockerfile.lab .
  ```

## Como usar

Defina um **IP de atacante exclusivo seu** (isola sua campanha das dos outros) e um nome de campanha:

```bash
export CAMP=amigo ATTACKER_IP=172.18.0.241
# (sem Dockerfile.lab? acrescente:  export FLUSH=0)

# Para CADA cenário, faça uma janela MALICIOSA e uma BENIGNA:

./capturar.sh inicio port-scan malicioso        # abre a janela
#   >>> rode SEU ataque agora, a partir de uma fonte com IP = ATTACKER_IP <<<
#   (ex., se tiver o Dockerfile.lab:)
docker run --rm --network <rede_da_app> --ip 172.18.0.241 \
    --cap-add=NET_RAW --cap-add=NET_ADMIN iotedu-lab:latest \
    nmap -sS -T4 -p1-2000 <ip_do_alvo>
./capturar.sh fim                                # fecha, conta e grava

./capturar.sh inicio port-scan benigno
#   >>> gere tráfego normal do mesmo IP (ex.: alguns curl/ping) <<<
./capturar.sh fim

# ... repita para os outros ataques ...

./capturar.sh relatorio                          # gera os relatórios
```

Descubra a rede da app e o IP do alvo:
```bash
BKC=$(docker ps --format '{{.Names}}' | grep backend | head -1)
REDE=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$BKC")
ALVO=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$BKC")
echo "rede=$REDE  alvo(backend)=$ALVO"
```

> **Importante:** para a contagem isolar sua campanha, seu ataque tem que sair do **mesmo
> `ATTACKER_IP`**. Com o `Dockerfile.lab` isso é fácil (`--ip`). Se usar sua própria ferramenta,
> garanta que a origem seja esse IP (ou deixe `ATTACKER_IP` vazio para contar todos os alertas — sem isolamento).

## Saída

Em `resultados/$CAMP/consolidados/`:
- `execucoes.csv` — uma linha por janela (alertas de cada IDS)
- `metricas.csv` — TP/FP/TN/FN + precisão, recall, especificidade, F1, FPR, FNR, acurácia balanceada
- `relatorio.md` — legível; destaca **FN** (ataques perdidos) e **FP** (alarmes falsos)

## Rodar EM PARALELO (vários testadores)

Cada pessoa usa um **`ATTACKER_IP` diferente** (`.241`, `.242`, …) e um **`CAMP` diferente**.
Os IDS são compartilhados, mas cada campanha só conta os alertas do **seu IP** → sem contaminação.

## Variáveis

| Var | Default | Para quê |
|---|---|---|
| `CAMP` | `campanha-<usuário>` | nome/pasta da campanha |
| `ATTACKER_IP` | (vazio) | filtra e isola por IP; **defina o seu** para paralelo |
| `SETTLE` | 8 | segundos de espera no `fim` (margem de escrita em disco) |
| `PCAP` | 0 | `PCAP=1` captura também o PCAP da janela (precisa do `Dockerfile.lab`) |
| `FLUSH` | 1 | rajada que força o flush do buffer (precisa do `Dockerfile.lab`); `FLUSH=0` desliga |

## Como as métricas são calculadas

Unidade = **janela rotulada**. Um IDS "detectou" a janela se contou ≥1 alerta (do seu IP).

|          | IDS alertou | IDS não alertou |
|----------|-------------|-----------------|
| **Maliciosa** | TP (acerto) | **FN** (ataque perdido) |
| **Benigna**   | **FP** (alarme falso) | TN (acerto) |

- **Recall/Sensibilidade** = TP/(TP+FN) · **FNR** = FN/(TP+FN) · **FPR** = FP/(FP+TN)
- **Precisão** = TP/(TP+FP) · **Especificidade** = TN/(TN+FP) · **F1** · **Acurácia balanceada** = (Recall+Especif.)/2
- Por IDS **e** para a **orquestração** (qualquer IDS alertou).

## Notas importantes

- **Nunca** use `docker restart` nos IDS (host-network): eles param de capturar sem erro.
  Se precisar, recrie: `docker compose up -d --force-recreate zeek suricata_ids snort_ids`.
- Ataques com `nmap -sS`/`nping` precisam de `--cap-add=NET_RAW --cap-add=NET_ADMIN`.
