#!/usr/bin/env bash
# =============================================================================
# benigno.sh — IMPRIME (stdout) o script de shell de TRÁFEGO BENIGNO de uma
# família, para o orquestrador rodá-lo dentro de um container iotedu-lab na
# rede farejada pelos IDS. Serve à avaliação de FALSOS POSITIVOS: é uso legítimo,
# em volume/ritmo normais (baixa taxa, domínios reais, poucas conexões) — o
# oposto do flood/scan/brute — e NÃO deve gerar alerta.
#
# Uso:  benigno.sh <familia> <http_ip> <ssh_ip> <duracao_s>
#   familia: http | dns | icmp | ssh | scan | mix
# Saída: uma linha de comando compatível com `sh -c`.
# =============================================================================
set -u
FAM="${1:?familia}"; HTTP="${2:?http_ip}"; SSH="${3:?ssh_ip}"; DUR="${4:-60}"

case "$FAM" in
  http)  CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           curl -s -o /dev/null "http://'"$HTTP"'/"; curl -s -o /dev/null "http://'"$HTTP"'/index.html";
           sleep 2; done' ;;
  dns)   CMD='end=$(( $(date +%s) + '"$DUR"' )); while [ $(date +%s) -lt $end ]; do
           for d in example.com google.com wikipedia.org github.com debian.org; do
             dig +short "$d" >/dev/null 2>&1; sleep 3; done; done' ;;
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
printf '%s\n' "$CMD"
