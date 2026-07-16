#!/bin/bash
# =============================================================================
# capturar.sh — CAPTURA dos alertas dos IDS sob ataque + RELATÓRIOS (FP/FN/eficácia)
#
# NÃO gera ataques. Você roda o ataque por fora; este script apenas
# delimita a janela, conta os alertas de Suricata/Snort/Zeek e, no fim, gera os
# CSVs e o relatório de eficácia. Ideal para vários testadores em PARALELO.
#
# Fluxo:
#   ./capturar.sh inicio <cenario> <classe>     # marca inicio da janela (classe=malicioso|benigno)
#        ... rode SEU ataque agora (ou gere o tráfego benigno) ...
#   ./capturar.sh fim                            # fecha a janela, conta alertas, grava no CSV
#   (repita inicio/fim para cada cenario e classe)
#   ./capturar.sh relatorio                      # gera metricas.csv + relatorio.md (FP/FN/eficácia)
#
# Variáveis de ambiente:
#   CAMP         id da campanha (default: campanha-<usuario>)  -> pasta de saída
#   ATTACKER_IP  (opcional, recomendado p/ paralelo) conta só alertas com este IP.
#                Se vazio, conta TODOS os alertas novos na janela.
#   SETTLE       segundos de espera no 'fim' p/ flush do Snort/Suricata (default 20)
#   PCAP=1       (opcional) captura tambem o PCAP da janela (host-net, na bridge)
#   MVP          raiz do repositório mvpv1-snapshot
# =============================================================================
set -u
CMD="${1:-}"
# Portável: raiz do repo derivada da localização deste script (…/<repo>/ferramenta_captura/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MVP="${MVP:-$(dirname "$SCRIPT_DIR")}"
# Rede docker da app: auto-detectada pelo container do backend (nome varia com o diretório do clone)
BKC="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'backend' | head -1)"
NET="${NET:-$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$BKC" 2>/dev/null)}"
NET="${NET:-mvpv1-snapshot_default}"
BK="${BK:-$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$BKC" 2>/dev/null)}"
CAMP="${CAMP:-campanha-$(id -un 2>/dev/null || echo user)}"
ATTACKER_IP="${ATTACKER_IP:-}"
SETTLE="${SETTLE:-8}"
PCAP="${PCAP:-0}"
LAB="${LAB:-iotedu-lab:latest}"   # imagem do toolbox (Dockerfile.lab) — usada p/ flush e PCAP
# FLUSH: Snort/Suricata bufferizam os alertas (~8KB); ataques de volume moderado nao
# descarregam a tempo. No 'fim' geramos uma rajada de um IP descartavel (FLUSH_IP, NAO
# contado) que enche o buffer e forca a escrita dos alertas reais. FLUSH=0 desliga.
FLUSH="${FLUSH:-1}"
FLUSH_IP="${FLUSH_IP:-172.18.0.250}"

# Diretórios de log dos IDS — detectados pelos MOUNTS dos containers (funciona com esta
# ferramenta em QUALQUER pasta, inclusive fora do repo). Fallback: $MVP/ids/logs/<dir>.
mount_src(){ docker inspect "$1" -f "{{range .Mounts}}{{if eq .Destination \"$2\"}}{{.Source}}{{end}}{{end}}" 2>/dev/null; }
SC="$(docker ps --format '{{.Names}}' 2>/dev/null|grep -i suricata|head -1)"
NC="$(docker ps --format '{{.Names}}' 2>/dev/null|grep -i snort|head -1)"
ZC="$(docker ps --format '{{.Names}}' 2>/dev/null|grep -i zeek|head -1)"
D_SURI="$(mount_src "$SC" /var/log/suricata)";            D_SURI="${D_SURI:-$MVP/ids/logs/logs_suricata}"
D_SNORT="$(mount_src "$NC" /opt/snort3/logs)";            D_SNORT="${D_SNORT:-$MVP/ids/logs/logs_snort}"
D_ZEEK="$(mount_src "$ZC" /usr/local/zeek/spool/zeek)";   D_ZEEK="${D_ZEEK:-$MVP/ids/logs/logs_zeek}"
SURI_EVE="$D_SURI/eve.json"
SNORT_FAST="$D_SNORT/alert_fast.txt"
ZEEK_NOTICE="$D_ZEEK/notice.log"

OUT="$MVP/resultados/$CAMP"; CONS="$OUT/consolidados"; EXE="$OUT/execucoes"
STATE="$OUT/.janela_aberta"
CSV="$CONS/execucoes.csv"
mkdir -p "$CONS" "$EXE"

now_utc(){ date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
lc(){ [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
# conta linhas novas (desde offset $2) no arquivo $1, filtrando por ATTACKER_IP se definido
count_new(){ local file="$1" off="$2" only_alert="${3:-}"
  [ -f "$file" ] || { echo 0; return; }
  local t; t=$(tail -n +$((off+1)) "$file" 2>/dev/null)
  [ -n "$only_alert" ] && t=$(printf '%s\n' "$t" | grep '"event_type":"alert"')
  if [ -n "$ATTACKER_IP" ]; then t=$(printf '%s\n' "$t" | grep -F "$ATTACKER_IP"); fi
  printf '%s\n' "$t" | grep -c .
}

case "$CMD" in
  inicio)
    cen="${2:?uso: inicio <cenario> <classe>}"; classe="${3:?uso: inicio <cenario> <classe>}"
    [ -f "$STATE" ] && { echo "ERRO: ja existe uma janela aberta ($(cat "$STATE" | head -1)). Rode 'fim' antes."; exit 1; }
    NETID=$(docker network inspect "$NET" -f '{{.Id}}' 2>/dev/null); IFACE="br-${NETID:0:12}"
    {
      echo "cenario=$cen"; echo "classe=$classe"; echo "t_start=$(now_utc)"
      echo "off_suri=$(lc "$SURI_EVE")"; echo "off_snort=$(lc "$SNORT_FAST")"; echo "off_zeek=$(lc "$ZEEK_NOTICE")"
      echo "iface=$IFACE"; echo "attacker_ip=$ATTACKER_IP"
    } > "$STATE"
    if [ "$PCAP" = "1" ]; then
      id="${CAMP}-${cen}-${classe}"; mkdir -p "$EXE/$id"
      filt=""; [ -n "$ATTACKER_IP" ] && filt="host $ATTACKER_IP"
      docker rm -f "cap_$id" >/dev/null 2>&1
      docker run -d --name "cap_$id" --network host --privileged -v "$EXE/$id:/cap" iotedu-lab:latest \
        tcpdump -i "$IFACE" -n -s0 -U $filt -w /cap/trafego.pcap >/dev/null 2>&1
      echo "pcap_id=$id" >> "$STATE"
    fi
    echo "[inicio] janela ABERTA: cenario=$cen classe=$classe  (rode seu ataque agora; depois: ./capturar.sh fim)"
    ;;

  fim)
    [ -f "$STATE" ] || { echo "ERRO: nenhuma janela aberta. Rode 'inicio' primeiro."; exit 1; }
    . <(sed 's/^/local_/' "$STATE" 2>/dev/null) 2>/dev/null
    cen=$(grep '^cenario=' "$STATE"|cut -d= -f2); classe=$(grep '^classe=' "$STATE"|cut -d= -f2)
    t_start=$(grep '^t_start=' "$STATE"|cut -d= -f2); ofs=$(grep '^off_suri=' "$STATE"|cut -d= -f2)
    ofn=$(grep '^off_snort=' "$STATE"|cut -d= -f2); ofz=$(grep '^off_zeek=' "$STATE"|cut -d= -f2)
    pcap_id=$(grep '^pcap_id=' "$STATE"|cut -d= -f2)
    t_end=$(now_utc)
    if [ "$FLUSH" = "1" ] && [ "$FLUSH_IP" != "$ATTACKER_IP" ] && [ -n "$BK" ]; then
      if docker image inspect "$LAB" >/dev/null 2>&1; then
        echo "[fim] forcando flush do buffer dos IDS (rajada de $FLUSH_IP, nao contada)..."
        docker run --rm --network "$NET" --ip "$FLUSH_IP" --cap-add=NET_RAW --cap-add=NET_ADMIN \
          "$LAB" sh -c "nping --icmp -c 800 --rate 800 $BK >/dev/null 2>&1; ab -n 4000 -c 100 http://$BK:8000/ >/dev/null 2>&1" >/dev/null 2>&1
      else
        echo "[fim] AVISO: imagem '$LAB' nao encontrada -> flush PULADO. Construa o Dockerfile.lab"
        echo "       ou defina FLUSH=0. Sem flush, ataques de baixo volume podem ser subcontados."
      fi
    fi
    echo "[fim] fechando janela ($cen/$classe) — aguardando escrita ${SETTLE}s..."
    sleep "$SETTLE"
    d_suri=$(count_new "$SURI_EVE" "$ofs" alert)
    d_snort=$(count_new "$SNORT_FAST" "$ofn")
    d_zeek=$(count_new "$ZEEK_NOTICE" "$ofz")
    pkts=0
    if [ -n "$pcap_id" ]; then
      docker stop "cap_$pcap_id" >/dev/null 2>&1; docker rm -f "cap_$pcap_id" >/dev/null 2>&1
      pkts=$(docker run --rm -v "$EXE/$pcap_id:/cap" iotedu-lab:latest sh -c 'tcpdump -r /cap/trafego.pcap 2>/dev/null|wc -l' 2>/dev/null|tr -d ' '); [ -z "$pkts" ] && pkts=0
    fi
    [ -f "$CSV" ] || echo "execucao_id,cenario,classe,attacker_ip,t_start,t_end,suricata,snort,zeek,pcap_pacotes" > "$CSV"
    echo "${CAMP}-${cen}-${classe},$cen,$classe,${ATTACKER_IP:-todos},$t_start,$t_end,$d_suri,$d_snort,$d_zeek,$pkts" >> "$CSV"
    rm -f "$STATE"
    echo "[fim] gravado: suricata=$d_suri snort=$d_snort zeek=$d_zeek pcap=$pkts"
    ;;

  relatorio)
    [ -f "$CSV" ] || { echo "ERRO: sem $CSV. Capture janelas antes."; exit 1; }
    python3 "$(dirname "$0")/metricas.py" "$CSV" "$CONS"
    echo ""; echo "Relatorios: $CONS/metricas.csv  e  $CONS/relatorio.md"
    ;;

  *)
    echo "uso: $0 inicio <cenario> <classe(malicioso|benigno)>  |  fim  |  relatorio"
    echo "   ex: CAMP=amigo ATTACKER_IP=172.18.0.241 $0 inicio port-scan malicioso"
    exit 2;;
esac
