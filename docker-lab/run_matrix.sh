#!/usr/bin/env bash
# run_matrix.sh — orchestrator ma trận thí nghiệm T1 (chạy trên HOST, trong thư mục docker-lab/)
# Ma trận RQ1: 2 nhóm KEM × loss{0,1,3%} × delay{0,50ms} × MTU{1500,1280} + MTU576 đặc biệt, 30 lần/cấu hình
# Dataset RQ2/3: 2 nhóm × 6 site × 30 flow, mạng sạch.
# Lưu ý: DNS Docker môi trường này không đáng tin → truyền IP qua env (LAB_SERVER_IP / TARGET).
set -euo pipefail
cd "$(dirname "$0")"
# sandbox map container-root sang host-uid khác → thư mục kết quả phải mở quyền
chmod 0777 results 2>/dev/null || true
N_HS="${N_HS:-30}"

net_ip() {  # net_ip <tên mạng> <tên container>
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}

resolve_server_ip() {
  LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)
  if [ -z "$LAB_SERVER_IP" ]; then echo "KHÔNG tìm thấy IP server trên labnet-b"; exit 4; fi
  export LAB_SERVER_IP
  echo "[matrix] SERVER_IP=$LAB_SERVER_IP"
}

health_check() {  # probe 1 handshake trước khi capture; restart server nếu bị kẹt
  local ROUTER_IP="$1"
  for try in 1 2 3; do
    # ghi ra file rồi grep (tránh SIGPIPE/pipefail khi grep thoát sớm)
    docker compose run --rm -e TARGET="$ROUTER_IP" pqc-client bash -c \
      'echo Q | timeout 6 /usr/local/ssl/bin/openssl s_client -connect $TARGET:4433 -tls1_3 -groups X25519 -brief 2>&1' \
      > /tmp/probe_$$.out 2>&1 || true
    if grep -q "CONNECTION ESTABLISHED" /tmp/probe_$$.out 2>/dev/null; then
      rm -f /tmp/probe_$$.out
      return 0
    fi
    rm -f /tmp/probe_$$.out
    echo "  [health] probe fail (lần $try) → restart server"
    docker compose restart pqc-server >/dev/null 2>&1
    sleep 3
  done
  echo "  [health] server vẫn hỏng sau 3 lần restart — bỏ cấu hình này"; return 1
}

run_hs_config() {
  local GROUP="$1" LOSS="$2" DELAY="$3" MTU="$4" TAG="$5"
  echo "=== [$TAG] loss=${LOSS}% delay=${DELAY}ms mtu=${MTU} group=${GROUP} ==="
  LOSS="$LOSS" DELAY="$DELAY" MTU="$MTU" docker compose up -d --force-recreate --no-deps netem-router >/dev/null
  sleep 1.2
  local ROUTER_IP; ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  if [ -z "$ROUTER_IP" ]; then echo "  !! router chưa có IP — bỏ cấu hình này"; return 1; fi
  health_check "$ROUTER_IP" || return 1
  docker compose exec -d netem-router tcpdump -U -i any -s 160 -w "/lab/results/pcap_${TAG}.pcapng" 'tcp port 4433'
  sleep 0.4
  docker compose run --rm -e TARGET="$ROUTER_IP" -e GROUP="$GROUP" \
    pqc-client /usr/local/bin/hs_loop.sh "$TAG" "$N_HS" "$GROUP" >/dev/null 2>&1
  docker compose exec -T netem-router pkill -INT tcpdump >/dev/null 2>&1 || true
  sleep 1
}

docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d pqc-server >/dev/null
sleep 2
resolve_server_ip

for G in X25519 X25519MLKEM768; do
  for LOSS in 0 1 3; do
    for DELAY in 0ms 50ms; do
      for MTU in 1500 1280; do
        DELAY_MS="${DELAY%ms}"
        run_hs_config "$G" "$LOSS" "$DELAY" "$MTU" "${G}_L${LOSS}_D${DELAY_MS}_M${MTU}" || echo "  [matrix] cấu hình bị bỏ qua"
      done
    done
  done
  run_hs_config "$G" 0 0 576 "${G}_L0_D0_M576" || echo "  [matrix] cấu hình MTU576 bị bỏ qua"
done

# ---- Dataset phân loại (mạng sạch) ----
for G in X25519 X25519MLKEM768; do
  echo "=== [sites:$G] ==="
  LOSS=0 DELAY=0ms MTU=1500 docker compose up -d --force-recreate --no-deps netem-router >/dev/null
  sleep 1.2
  ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  health_check "$ROUTER_IP" || continue
  docker compose exec -d netem-router tcpdump -U -i any -s 160 -w "/lab/results/pcap_sites_${G}.pcapng" 'tcp port 4433'
  sleep 0.4
  docker compose run --rm -e TARGET="$ROUTER_IP" -e GROUP="$G" \
    pqc-client /usr/local/bin/sites_loop.sh "${G}" 30 "$G" >/dev/null 2>&1
  docker compose exec -T netem-router pkill -INT tcpdump >/dev/null 2>&1 || true
  sleep 1
done

echo "ALL_DONE"
