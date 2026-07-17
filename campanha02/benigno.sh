#!/usr/bin/env bash
# =============================================================================
# benigno.sh — gera TRÁFEGO BENIGNO (uso legítimo / ferramentas do ambiente) numa
# janela, a partir de um container na MESMA rede farejada pelos IDS. Serve para a
# avaliação de FALSOS POSITIVOS: é tráfego normal que NÃO deve gerar alerta.
#
# Cada família benigna espelha uma família de ataque, mas em VOLUME/RITMO normais
# (baixa taxa, domínios/reais, poucas conexões) — o oposto do flood/scan/brute.
#
# Uso:  benigno.sh <familia> <http_ip> <ssh_ip> <duracao_s> [benign_ip] [net] [lab_img]
#   familia: http | dns | icmp | ssh | scan | mix
# Executa um container iotedu-lab na rede <net> com IP <benign_ip> e roda o tráfego.
# Retorna o rc do container.
# =============================================================================
set -u
FAM="${1:?familia}"; HTTP="${2:?http_ip}"; SSH="${3:?ssh_ip}"; DUR="${4:-60}"
BIP="${5:-172.30.0.20}"; NET="${6:-ids-eval-net}"; LAB="${7:-iotedu-lab:latest}"

# comandos legítimos por família (baixa taxa; loop até ~DUR segundos)
case "$FAM" in
  http)  CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           curl -s -o /dev/null "http://'"$HTTP"'/"; curl -s -o /dev/null "http://'"$HTTP"'/index.html";
           sleep 2; done' ;;
  dns)   CMD='end=$(( $(date +%s) + '"$DUR"' )); for d in example.com google.com wikipedia.org github.com debian.org; do :; done;
           while [ $(date +%s) -lt $end ]; do
           for d in example.com google.com wikipedia.org github.com; do dig +short "$d" >/dev/null 2>&1; sleep 3; done; done' ;;
  icmp)  CMD='nping --icmp -c '"$DUR"' --rate 1 '"$HTTP"' >/dev/null 2>&1 || ping -c '"$DUR"' -i 1 '"$HTTP"' >/dev/null 2>&1' ;;
  ssh)   CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           nping --tcp -p 22 -c 1 --flags syn '"$SSH"' >/dev/null 2>&1; sleep 5; done' ;;
  scan)  CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           curl -s -o /dev/null "http://'"$HTTP"'/"; nping --tcp -p 22 -c 1 --flags syn '"$SSH"' >/dev/null 2>&1; sleep 6; done' ;;
  mix|*) CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           curl -s -o /dev/null "http://'"$HTTP"'/"; dig +short example.com >/dev/null 2>&1;
           nping --icmp -c 2 --rate 1 '"$HTTP"' >/dev/null 2>&1;
           nping --tcp -p 22 -c 1 --flags syn '"$SSH"' >/dev/null 2>&1; sleep 4; done' ;;
esac

exec docker run --rm --network "$NET" --ip "$BIP" --cap-add=NET_RAW --cap-add=NET_ADMIN \
     --name "c02-benigno-$FAM" "$LAB" sh -c "$CMD"
