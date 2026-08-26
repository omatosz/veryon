#!/usr/bin/env bash
# Bloqueia conexoes de saida (NEW) das redes isoladas (honeypot, alvo vulneravel)
# para qualquer destino, evitando que esses containers sejam usados como pivo
# caso alguem escape do sandbox/exploite a vulnerabilidade de verdade. Trafego
# de ENTRADA (portas publicadas, ou conexoes do scanner) nao e afetado, pois
# so bloqueamos conexoes NOVAS originadas nessas subnets.
set -euo pipefail

SUBNETS=(
  "172.28.0.0/24"  # honeypot_net (Cowrie)
  "172.29.0.0/24"  # target_net (Juice Shop)
)

for subnet in "${SUBNETS[@]}"; do
  if ! sudo iptables -C DOCKER-USER -s "$subnet" -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
    sudo iptables -I DOCKER-USER -s "$subnet" -m conntrack --ctstate NEW -j DROP
    echo "regra de egress-block aplicada para $subnet"
  else
    echo "regra de egress-block ja presente para $subnet"
  fi
done
