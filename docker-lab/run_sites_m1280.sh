#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
net_ip() { docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1; }
docker compose up -d pqc-server >/dev/null
sleep 2
LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server); export LAB_SERVER_IP
LOSS=0 DELAY=0ms MTU=1280 docker compose up -d --force-recreate --no-deps netem-router >/dev/null
sleep 1.5
ROUTER_IP=$(net_ip labnet-a lab-netem-router)
# health check
docker compose run --rm -e TARGET="$ROUTER_IP" pqc-client bash -c 'echo Q | timeout 6 /usr/local/ssl/bin/openssl s_client -connect $TARGET:4433 -tls1_3 -groups X25519 -brief 2>&1' > /tmp/probe.out 2>&1 || true
grep -q "CONNECTION ESTABLISHED" /tmp/probe.out || { echo HEALTH_FAIL; exit 5; }
for G in X25519 X25519MLKEM768; do
  docker compose exec -d netem-router tcpdump -U -i any -s 160 -w "/lab/results/pcap_sites_M1280_${G}.pcapng" 'tcp port 4433'
  sleep 0.5
  docker compose run --rm -e TARGET="$ROUTER_IP" pqc-client /usr/local/bin/sites_loop.sh "M1280_${G}" 30 "$G" >/dev/null 2>&1
  docker compose exec -T netem-router pkill -INT tcpdump >/dev/null 2>&1 || true
  sleep 1
done
echo SITES_M1280_DONE
