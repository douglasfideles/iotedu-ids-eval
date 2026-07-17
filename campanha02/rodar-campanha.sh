#!/usr/bin/env bash
# =============================================================================
# rodar-campanha.sh — orquestrador da CAMPANHA 02 (avaliação de IDS por interface).
#
# Sobe uma rede docker dedicada (ids-eval-net) com ALVOS leves (http/ssh), faz os
# 3 IDS (Suricata/Snort/Zeek) FAREJAREM a bridge dessa rede, e roda janelas
# ISOLADAS de tráfego malicioso (10 ataques do sbcup2026) e benigno, salvando por
# janela: fatia dos alertas de cada IDS, PCAP, stdout do gerador e manifesto.
# No fim, dispara o pipeline de análise (classificar -> metricas -> estatistica ->
# relatorio).
#
# Subcomandos:
#   preparar   cria a rede, sobe alvos e IDS (force-recreate), congela hashes
#   pilancar / piloto   roda 1 rep por cenário (malicioso e benigno) — validação
#   completa   roda REPS (default 15) por cenário + benigno (~2h), ordem aleatória
#   analisar   (re)processa as janelas já capturadas e gera os relatórios
#   parar      remove alvos, rede e para os IDS
#
# Regras de ouro (NÃO violar):
#   - NUNCA 'docker restart' nos IDS (host-net) — sempre 'up -d --force-recreate'.
#   - Atacantes/benignos SEMPRE na mesma rede farejada, com --cap-add NET_RAW/NET_ADMIN.
#   - Uma janela por vez, sem tráfego concorrente (isolamento p/ contagem correta).
# =============================================================================
set -u

# ---------------- Configuração (override por env) ----------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MVP="${MVP:-/mnt/d/PROJETOS/react/Git/mvpv1-snapshot}"
SBCUP="${SBCUP:-/mnt/d/PROJETOS/react/Git/sbcup2026-ataques}"
NET="${NET:-ids-eval-net}"
SUBNET="${SUBNET:-172.30.0.0/24}"
GW="${GW:-172.30.0.1}"
HTTP_IP="${HTTP_IP:-172.30.0.5}"
SSH_IP="${SSH_IP:-172.30.0.6}"
ATT_IP="${ATT_IP:-172.30.0.10}"
BEN_IP="${BEN_IP:-172.30.0.20}"
FLUSH_IP="${FLUSH_IP:-172.30.0.250}"
LAB="${LAB:-iotedu-lab:latest}"
REPS="${REPS:-15}"
SETTLE="${SETTLE:-8}"          # espera p/ flush do buffer dos IDS
ATTACK_MAX="${ATTACK_MAX:-240}" # teto padrão de duração de um ataque (s)
FLOOD_DUR="${FLOOD_DUR:-12}"    # duração dos floods infinitos (hping3/scapy --flood)
SNAP="${SNAP:-128}"             # snaplen do pcap (headers; contagem de pacotes preservada)
BENIGN_DUR="${BENIGN_DUR:-60}"  # duração de uma janela benigna (s)
CLEANUP="${CLEANUP:-5}"         # intervalo entre janelas (s)
FLUSH="${FLUSH:-1}"
PCAP="${PCAP:-1}"

OUT="$HERE"                     # saídas ficam em campanha02/
EXE="$OUT/execucoes"; CONS="$OUT/consolidados"; REGRAS="$OUT/regras"
WIN_CSV="$CONS/windows.csv"
SURI="$MVP/ids/logs/logs_suricata/eve.json"
SNORT="$MVP/ids/logs/logs_snort/alert_fast.txt"
ZEEK="$MVP/ids/logs/logs_zeek/notice.log"
mkdir -p "$EXE" "$CONS" "$REGRAS"

# cenario -> "IMAGE|ARGS"  (ARGS já expandido com os IPs)
declare -A ATAQUE=(
  [icmp-flood]="sbcup26-ataque-icmp-flood|$HTTP_IP"
  [syn-flood]="sbcup26-ataque-syn-flood|$HTTP_IP 80"
  [udp-flood]="sbcup26-ataque-udp-flood|$HTTP_IP 80"
  [dos-http-simple]="sbcup26-ataque-dos-http-simple|$HTTP_IP 80"
  [sql-injection]="sbcup26-ataque-sql-injection|$HTTP_IP 80"
  [xss-scanner]="sbcup26-ataque-xss-scanner|$HTTP_IP 80"
  [idor-path-traversal]="sbcup26-ataque-idor-path-traversal|$HTTP_IP 80"
  [port-scanner-tcp]="sbcup26-ataque-port-scanner-tcp|$HTTP_IP"
  [ssh-bruteforce]="sbcup26-ataque-ssh-bruteforce|$SSH_IP 22"
  [dns-tunneling]="sbcup26-ataque-dns-tunneling|"
)
# cenario -> teto de tempo (s). Floods são infinitos -> FLOOD_DUR curto; os que
# terminam sozinhos (sqlmap/hydra/nmap/ffuf/dig) recebem teto mais folgado.
declare -A TMO=(
  [icmp-flood]="$FLOOD_DUR" [syn-flood]="$FLOOD_DUR" [udp-flood]="$FLOOD_DUR"
  [dos-http-simple]=90 [sql-injection]=240 [xss-scanner]=180
  [idor-path-traversal]=120 [port-scanner-tcp]=180 [ssh-bruteforce]=120 [dns-tunneling]=90
)
# cenario malicioso -> familia intencionada (deve casar com mapa-assinaturas.yaml)
declare -A FAMILIA=(
  [icmp-flood]=flood-icmp [syn-flood]=flood-syn [udp-flood]=flood-udp
  [dos-http-simple]=dos-http [sql-injection]=sqli [xss-scanner]=xss
  [idor-path-traversal]=path-traversal [port-scanner-tcp]=scan
  [ssh-bruteforce]=ssh-brute [dns-tunneling]=dns-tunneling
)
# cenario benigno -> familia do benigno.sh
declare -A BENIGNO=(
  [benigno-icmp]=icmp [benigno-http]=http [benigno-dns]=dns
  [benigno-ssh]=ssh [benigno-scan]=scan [benigno-mix]=mix
)
ORDEM_ATAQUES=(icmp-flood syn-flood udp-flood dos-http-simple sql-injection \
               xss-scanner idor-path-traversal port-scanner-tcp ssh-bruteforce dns-tunneling)
ORDEM_BENIGNOS=(benigno-icmp benigno-http benigno-dns benigno-ssh benigno-scan benigno-mix)

now_utc(){ date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

# ---------------- infra ----------------
ensure_net(){
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    log "criando rede $NET ($SUBNET)"
    docker network create --subnet "$SUBNET" --gateway "$GW" "$NET" >/dev/null
  else log "rede $NET já existe"; fi
}
start_targets(){
  docker rm -f c02-http c02-ssh >/dev/null 2>&1
  log "subindo alvos (http=$HTTP_IP:80, ssh=$SSH_IP:22)"
  docker run -d --rm --name c02-http --network "$NET" --ip "$HTTP_IP" sbcup26-servidor-http-server:latest >/dev/null
  docker run -d --rm --name c02-ssh  --network "$NET" --ip "$SSH_IP"  sbcup26-servidor-ssh-server:latest  >/dev/null
  sleep 3
  docker ps --format '{{.Names}}' | grep -qx c02-http && docker ps --format '{{.Names}}' | grep -qx c02-ssh \
    && log "alvos OK" || { log "ERRO: alvos não subiram"; return 1; }
}
trunc_logs(){
  # baseline limpo: zera os logs dos IDS (offsets ~0, sem backlog de campanhas
  # anteriores contaminando as janelas). Feito com IDS parados/ao recriar.
  log "truncando logs dos IDS (baseline limpo)"
  : > "$SURI" 2>/dev/null; : > "$SNORT" 2>/dev/null; : > "$ZEEK" 2>/dev/null
  : > "$MVP/ids/logs/logs_suricata/fast.log" 2>/dev/null
  : > "$MVP/ids/logs/logs_snort/alert_full.txt" 2>/dev/null
}
start_ids(){
  local NETID IFACE
  NETID=$(docker network inspect "$NET" -f '{{.Id}}')
  IFACE="br-${NETID:0:12}"
  log "subindo IDS farejando $IFACE (force-recreate; NUNCA restart)"
  # para os IDS antes de truncar (evita arquivo esparso) e recria FRESCOS
  docker compose -f "$MVP/docker-compose.yml" --project-directory "$MVP" stop zeek suricata_ids snort_ids >/dev/null 2>&1
  trunc_logs
  IDS_INTERFACE="$IFACE" docker compose -f "$MVP/docker-compose.yml" --project-directory "$MVP" \
    up -d --force-recreate zeek suricata_ids snort_ids
  sleep 8
  echo "$IFACE" > "$CONS/.iface"
}
health(){
  local ok=1
  for c in suricata snort zeek; do
    docker ps --format '{{.Names}}' | grep -qi "$c" || { log "IDS $c NÃO está rodando"; ok=0; }
  done
  for fpath in "$SURI" "$SNORT" "$ZEEK"; do
    [ -e "$fpath" ] || log "AVISO: log ainda não existe: $fpath (será criado no 1º alerta)"
  done
  [ "$ok" = 1 ] && log "health: IDS ativos ✅" || log "health: PROBLEMA nos IDS ❌"
  return $((1-ok))
}
freeze(){
  log "congelando hashes (regras/imagens/scripts)"
  { echo "# hashes.txt — campanha02 — $(now_utc)"
    echo "## regras snort"; find "$MVP/ids/rules/rules_snort" -type f | sort | xargs sha256sum 2>/dev/null
    echo "## regras suricata"; find "$MVP/ids/rules/rules_suricata" -type f | sort | xargs sha256sum 2>/dev/null
    echo "## imagens"; for i in mvpv1-snapshot-suricata_ids mvpv1-snapshot-snort_ids mvpv1-snapshot-zeek \
        sbcup26-servidor-http-server sbcup26-servidor-ssh-server "${ATAQUE[@]%%|*}" "$LAB"; do
        docker image inspect "$i" -f '{{.RepoTags}} {{.Id}}' 2>/dev/null; done
    echo "## scripts campanha02"; find "$HERE" -maxdepth 1 -type f \( -name '*.sh' -o -name '*.py' -o -name '*.yaml' \) | sort | xargs sha256sum 2>/dev/null
  } > "$REGRAS/hashes.txt"
}

# ---------------- captura de janela ----------------
# args: id, cenario, classe, familia, attacker_ip, cname, comando-que-lança-DETACHED...
# O gerador é lançado DETACHED com nome $cname; a janela espera terminar até TMO
# segundos e então força a parada (docker kill). NÃO usar 'timeout docker run' —
# neste setup WSL/Docker Desktop o SIGTERM não para o container (fica órfão).
janela(){
  local id="$1" cen="$2" classe="$3" fam="$4" aip="$5" cname="$6"; shift 6
  local dir="$EXE/$id"; mkdir -p "$dir"
  local off_s off_n off_z t0 t1 rc=0 pkts=0 NETID IFACE tmo waited=0
  tmo="${TMO_THIS:-$ATTACK_MAX}"
  NETID=$(docker network inspect "$NET" -f '{{.Id}}'); IFACE="br-${NETID:0:12}"
  off_s=$(stat -c%s "$SURI" 2>/dev/null || echo 0)
  off_n=$(stat -c%s "$SNORT" 2>/dev/null || echo 0)
  off_z=$(stat -c%s "$ZEEK" 2>/dev/null || echo 0)
  t0=$(now_utc)
  # pcap da janela (na bridge, filtrando o IP do gerador). Anel de ~100MB por
  # segurança; a CONTAGEM vem do sumário do tcpdump (não relê o arquivo).
  if [ "$PCAP" = 1 ]; then
    docker rm -f "cap_$id" >/dev/null 2>&1
    # captura tudo na janela EXCETO a rajada de flush (o filtro por IP do atacante
    # perderia floods com origem SPOOFADA, ex.: syn-flood -> contagem irreal).
    docker run -d --name "cap_$id" --network host --privileged -v "$dir:/cap" "$LAB" \
      tcpdump -i "$IFACE" -n -s "$SNAP" -U -C 100 -W 1 not host "$FLUSH_IP" -w /cap/trafego.pcap >/dev/null 2>&1
    sleep 1
  fi
  # lança o gerador DETACHED e espera terminar até 'tmo' segundos
  log "  janela $id ($classe/$cen) gerando (teto ${tmo}s)..."
  docker rm -f "$cname" >/dev/null 2>&1
  "$@" >/dev/null 2>&1
  while [ "$waited" -lt "$tmo" ]; do
    docker ps --format '{{.Names}}' | grep -qx "$cname" || break
    sleep 3; waited=$((waited+3))
  done
  docker logs "$cname" > "$dir/gerador.stdout" 2>&1 || :
  rc=$(docker inspect -f '{{.State.ExitCode}}' "$cname" 2>/dev/null || echo 124)
  if docker ps --format '{{.Names}}' | grep -qx "$cname"; then rc=124; docker kill "$cname" >/dev/null 2>&1; fi
  docker rm -f "$cname" >/dev/null 2>&1
  # flush do buffer dos IDS (rajada de IP descartável — excluída na análise)
  if [ "$FLUSH" = 1 ]; then
    docker run --rm --network "$NET" --ip "$FLUSH_IP" --cap-add=NET_RAW --cap-add=NET_ADMIN \
      "$LAB" sh -c "nping --icmp -c 800 --rate 800 $HTTP_IP >/dev/null 2>&1" >/dev/null 2>&1
  fi
  sleep "$SETTLE"
  t1=$(now_utc)
  # fatias dos alertas novos (byte offset -> só a parte nova, eficiente em eve.json grande)
  tail -c +$((off_s+1)) "$SURI"  2>/dev/null | grep '"event_type":"alert"' > "$dir/suricata.jsonl" 2>/dev/null || : > "$dir/suricata.jsonl"
  tail -c +$((off_n+1)) "$SNORT" 2>/dev/null > "$dir/snort.txt"   || : > "$dir/snort.txt"
  tail -c +$((off_z+1)) "$ZEEK"  2>/dev/null > "$dir/zeek.txt"    || : > "$dir/zeek.txt"
  # encerra pcap; contagem via sumário do tcpdump (packets received by filter)
  if [ "$PCAP" = 1 ]; then
    docker stop -t 3 "cap_$id" >/dev/null 2>&1
    pkts=$(docker logs "cap_$id" 2>&1 | grep -oE '[0-9]+ packets received by filter' | grep -oE '^[0-9]+' | tail -1)
    [ -z "$pkts" ] && pkts=0
    docker rm -f "cap_$id" >/dev/null 2>&1
  fi
  # manifesto + linha no windows.csv
  cat > "$dir/manifesto.yaml" <<EOF
execucao_id: $id
cenario: $cen
classe: $classe
familia_intencionada: $fam
attacker_ip: $aip
flush_ip: $FLUSH_IP
interface: $IFACE
t_start: $t0
t_end: $t1
gerador_rc: $rc
pcap_pacotes: $pkts
EOF
  [ -f "$WIN_CSV" ] || echo "execucao_id,cenario,familia_intencionada,classe,attacker_ip,flush_ip,t_start,t_end,gerador_rc,pcap_pacotes" > "$WIN_CSV"
  echo "$id,$cen,$fam,$classe,$aip,$FLUSH_IP,$t0,$t1,$rc,$pkts" >> "$WIN_CSV"
  local a_s a_n a_z
  a_s=$(grep -c . "$dir/suricata.jsonl" 2>/dev/null); a_n=$(grep -c . "$dir/snort.txt" 2>/dev/null); a_z=$(grep -c . "$dir/zeek.txt" 2>/dev/null)
  log "  janela $id fim: rc=$rc pcap=$pkts alertas(suri=$a_s snort=$a_n zeek=$a_z)"
  sleep "$CLEANUP"
}

rodar_ataque(){ # id, cenario, rep
  local cen="$1" rep="$2" spec img args
  spec="${ATAQUE[$cen]}"; img="${spec%%|*}"; args="${spec#*|}"
  local id; id=$(printf 'campanha02-%s-malicioso-r%02d' "$cen" "$rep")
  local TMO_THIS="${TMO[$cen]:-$ATTACK_MAX}"
  # gerador DETACHED com nome fixo c02-atk (a janela controla o tempo e a parada)
  # shellcheck disable=SC2086
  janela "$id" "$cen" "malicioso" "${FAMILIA[$cen]}" "$ATT_IP" c02-atk \
    docker run -d --name c02-atk --network "$NET" --ip "$ATT_IP" \
      --cap-add=NET_RAW --cap-add=NET_ADMIN "$img" $args
}
rodar_benigno(){ # cenario(benigno-*), rep
  local cen="$1" rep="$2" famb="${BENIGNO[$1]}"
  local id; id=$(printf 'campanha02-%s-benigno-r%02d' "$cen" "$rep")
  local TMO_THIS=$((BENIGN_DUR + 60))
  local script; script="$(bash "$HERE/benigno.sh" "$famb" "$HTTP_IP" "$SSH_IP" "$BENIGN_DUR")"
  janela "$id" "$cen" "benigno" "$famb" "$BEN_IP" c02-ben \
    docker run -d --name c02-ben --network "$NET" --ip "$BEN_IP" \
      --cap-add=NET_RAW --cap-add=NET_ADMIN "$LAB" sh -c "$script"
}

analisar(){
  log "analisando ($WIN_CSV)"
  python3 "$HERE/classificar.py" "$WIN_CSV" "$EXE" "$HERE/mapa-assinaturas.yaml" "$CONS" || return 1
  python3 "$HERE/../ferramenta_captura/metricas.py" "$CONS/execucoes.csv" "$CONS"
  python3 "$HERE/estatistica.py" "$CONS/classificacao_detalhe.csv" "$CONS/execucoes.csv" "$CONS"
  python3 "$HERE/graficos.py" "$CONS" "$OUT/graficos" 2>/dev/null || log "graficos.py falhou (matplotlib?)"
  python3 "$HERE/gera_relatorio.py" "$WIN_CSV" "$CONS" "$OUT/RELATORIO.md"
  log "relatórios em $CONS/, figuras em $OUT/graficos/ e $OUT/RELATORIO.md"
}

preparar(){ ensure_net && start_targets && start_ids && health; freeze; }

executar(){ # $1 = reps
  local reps="$1" seq=() cen rep
  for rep in $(seq 1 "$reps"); do
    for cen in "${ORDEM_ATAQUES[@]}"; do seq+=("atk:$cen:$rep"); done
    for cen in "${ORDEM_BENIGNOS[@]}"; do seq+=("ben:$cen:$rep"); done
  done
  # embaralha a ordem (não rodar repetições do mesmo cenário em sequência)
  mapfile -t seq < <(printf '%s\n' "${seq[@]}" | shuf)
  log "total de janelas: ${#seq[@]} (reps=$reps)"
  local i=0
  for item in "${seq[@]}"; do
    i=$((i+1))
    local tipo="${item%%:*}"; local resto="${item#*:}"
    local cen="${resto%:*}"; local rep="${resto##*:}"
    log "[$i/${#seq[@]}] $tipo $cen r$rep"
    if [ "$tipo" = atk ]; then rodar_ataque "$cen" "$rep"; else rodar_benigno "$cen" "$rep"; fi
  done
  analisar
}

continuar(){ # retoma: religa a infra e roda SÓ as janelas (cenario,rep) que faltam no windows.csv
  preparar || return 1
  local faltantes=() cen rep id
  for rep in $(seq 1 "$REPS"); do
    for cen in "${ORDEM_ATAQUES[@]}"; do
      id=$(printf 'campanha02-%s-malicioso-r%02d' "$cen" "$rep")
      grep -q "^$id," "$WIN_CSV" 2>/dev/null || faltantes+=("atk:$cen:$rep")
    done
    for cen in "${ORDEM_BENIGNOS[@]}"; do
      id=$(printf 'campanha02-%s-benigno-r%02d' "$cen" "$rep")
      grep -q "^$id," "$WIN_CSV" 2>/dev/null || faltantes+=("ben:$cen:$rep")
    done
  done
  if [ "${#faltantes[@]}" -eq 0 ]; then log "nada a fazer: 240 janelas já capturadas"; analisar; return; fi
  mapfile -t faltantes < <(printf '%s\n' "${faltantes[@]}" | shuf)
  local ja=$(( $(grep -c . "$WIN_CSV" 2>/dev/null || echo 1) - 1 ))
  log "retomando: ${ja} janelas já existem; faltam ${#faltantes[@]} (alvo 240)"
  local i=0
  for item in "${faltantes[@]}"; do
    i=$((i+1))
    local tipo="${item%%:*}"; local resto="${item#*:}"
    local cen="${resto%:*}"; local rep="${resto##*:}"
    log "[$i/${#faltantes[@]} | total $((ja+i))/240] $tipo $cen r$rep"
    if [ "$tipo" = atk ]; then rodar_ataque "$cen" "$rep"; else rodar_benigno "$cen" "$rep"; fi
  done
  analisar
}

parar(){
  log "parando alvos e rede; IDS podem continuar (use compose down se quiser)"
  docker rm -f c02-http c02-ssh c02-atk >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1 || log "rede em uso ou já removida"
}

case "${1:-}" in
  preparar) preparar ;;
  piloto|pilancar) preparar && REPS=1 executar 1 ;;
  completa) preparar && executar "$REPS" ;;
  continuar) continuar ;;
  executar) executar "${2:-$REPS}" ;;
  analisar) analisar ;;
  parar) parar ;;
  *) echo "uso: $0 {preparar|piloto|completa|continuar|executar [N]|analisar|parar}"
     echo "  env úteis: REPS=$REPS BENIGN_DUR=$BENIGN_DUR SETTLE=$SETTLE ATTACK_MAX=$ATTACK_MAX PCAP=$PCAP"
     exit 2;;
esac
