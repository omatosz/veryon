#!/usr/bin/env bash
# Le a tabela blocked_ips do Postgres a cada poucos segundos e escreve a
# lista de IPs ativos num arquivo num volume compartilhado. Quem realmente
# aplica o bloqueio e o enforce-netns.sh (roda no namespace de rede do
# Cowrie) -- esse script aqui so tem acesso a rede "core" (onde fica o db),
# nunca ao namespace do honeypot.
set -euo pipefail

POLL_SECONDS="${POLL_SECONDS:-5}"
OUT="/shared/blocked_ips.txt"

# A condicao aqui e a mesma de app/core/blocklist.py:active_blocks(). Se as
# duas divergirem, um bloqueio some da API e continua preso no iptables, ou o
# contrario. Mexeu numa, mexe na outra.
while true; do
  psql "$DATABASE_URL" -t -A -c \
    "SELECT DISTINCT ip FROM blocked_ips
      WHERE unblocked_at IS NULL
        AND (expires_at IS NULL OR expires_at > now())" \
    > "${OUT}.tmp" 2>/dev/null && mv "${OUT}.tmp" "$OUT"
  sleep "$POLL_SECONDS"
done
