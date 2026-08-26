#!/usr/bin/env bash
# Le a lista de IPs bloqueados (escrita pelo poll-db.sh num volume
# compartilhado) e aplica regras DROP no INPUT do proprio namespace de rede
# do Cowrie, pras portas 2222/2223 -- este container roda com
# network_mode: service:cowrie, entao "INPUT" aqui e o INPUT do Cowrie.
#
# Isso existe porque DOCKER-USER/FORWARD nao ve trafego que chega via NAT
# hairpin de porta publicada em localhost (o caminho que toda simulacao de
# ataque local usa) -- bloquear dentro do proprio namespace do container
# evita esse problema, porque o pacote passa pelo INPUT dele de qualquer jeito
# antes de chegar no processo que esta escutando a porta.
set -euo pipefail

CHAIN="SOC-SIEM-IP-BLOCKLIST"
POLL_SECONDS="${POLL_SECONDS:-5}"
FILE="/shared/blocked_ips.txt"

ensure_chain() {
  iptables -N "$CHAIN" 2>/dev/null || true
  iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
}

sync_once() {
  iptables -F "$CHAIN"
  [ -f "$FILE" ] || return 0

  local ip
  while read -r ip; do
    [ -n "$ip" ] || continue
    iptables -A "$CHAIN" -s "$ip" -p tcp --dport 2222 -j DROP
    iptables -A "$CHAIN" -s "$ip" -p tcp --dport 2223 -j DROP
  done < "$FILE"
}

ensure_chain

while true; do
  sync_once
  sleep "$POLL_SECONDS"
done
