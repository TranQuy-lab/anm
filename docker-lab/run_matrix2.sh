#!/usr/bin/env bash
# run_matrix2.sh — ma trận RQ1 phiên bản 2 (thiết kế XEN KẼ + MTU có hiệu lực thật).
#
# Khác biệt so với run_matrix.sh (bản 1):
#   (1) Hai nhóm KEM chạy LUÂN PHIÊN trong cùng cấu hình (hs_loop2.sh) → ghép cặp theo `rep`
#       là hợp lệ, loại bỏ nhiễu trôi hệ thống của thiết kế khối tuần tự.
#   (2) role.sh tắt GSO/TSO/GRO trên NIC ảo của router → MTU mô phỏng có hiệu lực thật
#       (bản 1 bị GSO che: gói 1847 B vẫn đi qua link MTU 576).
#
# Ma trận: 13 cấu hình × 30 cặp = 780 bắt tay; + dataset 6-site ở MTU 1500 và 1280.
# Biến môi trường: N_HS (mặc định 30), QUICK=1 (chạy 1 cấu hình test), CONFIGS (ghi đè danh sách)
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
N_HS="${N_HS:-30}"

net_ip() {
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}

resolve_server_ip() {
  LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)
  if [ -z "$LAB_SERVER_IP" ]; then echo "KHÔNG tìm thấy IP server trên labnet-b"; exit 4; fi
  export LAB_SERVER_IP
  echo "[matrix2] SERVER_IP=$LAB_SERVER_IP"
}

health_check() {
  local ROUTER_IP="$1"
  for try in 1 2 3; do
    docker compose run --rm -e TARGET="$ROUTER_IP" pqc-client bash -c \
      'echo Q | timeout 6 /usr/local/ssl/bin/openssl s_client -connect $TARGET:4433 -tls1_3 -groups X25519 -brief 2>&1' \
      > /tmp/probe_$$.out 2>&1 || true
    if grep -q "CONNECTION ESTABLISHED" /tmp/probe_$$.out 2>/dev/null; then
      rm -f /tmp/probe_$$.out; return 0
    fi
    rm -f /tmp/probe_$$.out
    echo "  [health] probe fail (lần $try) → restart server"
    docker compose restart pqc-server >/dev/null 2>&1
    sleep 3
  done
  echo "  [health] server vẫn hỏng sau 3 lần restart — bỏ cấu hình này"; return 1
}

set_router() {  # set_router <loss> <delay_ms> <mtu> [clamp] [drop_icmp]
  # BẮT BUỘC gắn đơn vị: `tc netem delay 50` (số trần) bị hiểu là 50 MICRO giây, không phải ms
  LOSS="$1" DELAY="$2ms" MTU="$3" CLAMP="${4:-on}" DROP_ICMP_FRAG="${5:-0}" \
    docker compose up -d --force-recreate --no-deps netem-router >/dev/null
  sleep 1.2
}

run_hs_pair() {  # run_hs_pair <loss> <delay_ms> <mtu>
  local LOSS="$1" DELAY="$2" MTU="$3"
  local TAG="L${LOSS}_D${DELAY}_M${MTU}"
  echo "=== [$TAG] XEN KẼ loss=${LOSS}% delay=${DELAY}ms mtu=${MTU} group=ABAB ==="
  set_router "$LOSS" "$DELAY" "$MTU" on 0
  local ROUTER_IP; ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  if [ -z "$ROUTER_IP" ]; then echo "  !! router chưa có IP — bỏ cấu hình này"; return 1; fi
  # kiểm tra offload đã tắt chưa (độ trung thực MTU)
  docker compose exec -T netem-router sh -c 'ethtool -k $(ip -o -4 addr show | awk "\$4 ~ /^172\.30\.10\./ {print \$2}" | cut -d@ -f1 | head -1) 2>/dev/null | grep -E "^tcp-segmentation-offload|^generic-segmentation-offload"' || true
  health_check "$ROUTER_IP" || return 1
  # capture trong container RIÊNG chia sẻ netns với router (ổn định hơn `exec -d`)
  local CAP="cap2_${TAG}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run -d --name "$CAP" --net=container:lab-netem-router \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
    bash /lab/scripts/capture.sh "/lab/results/pcap2_${TAG}.pcapng" 160 "tcp port 4433" >/dev/null
  sleep 0.6
  docker compose run --rm -e TARGET="$ROUTER_IP" \
    pqc-client /usr/local/bin/hs_loop2.sh "$TAG" "$N_HS" >/dev/null 2>&1
  sleep 2   # chờ tcpdump ghi hết phần đệm còn lại
  docker kill -s INT "$CAP" >/dev/null 2>&1 || true
  sleep 0.8
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  echo "  [xong $TAG] $(wc -l < results/hs2_${TAG}_X25519.csv) + $(wc -l < results/hs2_${TAG}_X25519MLKEM768.csv) dòng CSV, $(capinfos -c results/pcap2_${TAG}.pcapng 2>/dev/null | sed -n 's/Number of packets: *//p') gói"
}

run_sites() {  # run_sites <mtu>
  local MTU="$1"
  echo "=== [sites MTU $MTU] XEN KẼ 6 site x $N_HS rep x 2 nhóm ==="
  set_router 0 0 "$MTU" on 0
  local ROUTER_IP; ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  health_check "$ROUTER_IP" || return 1
  local CAP="cap2_sites_M${MTU}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run -d --name "$CAP" --net=container:lab-netem-router \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
    bash /lab/scripts/capture.sh "/lab/results/pcap2_sites_M${MTU}.pcapng" 160 "tcp port 4433" >/dev/null
  sleep 0.6
  docker compose run --rm -e TARGET="$ROUTER_IP" \
    pqc-client /usr/local/bin/sites_loop2.sh "$N_HS" >/dev/null 2>&1
  sleep 2
  docker kill -s INT "$CAP" >/dev/null 2>&1 || true
  sleep 0.8
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  mv results/sites2.csv "results/sites2_M${MTU}.csv"
  echo "  [xong sites M$MTU] $(wc -l < results/sites2_M${MTU}.csv) dòng, $(capinfos -c results/pcap2_sites_M${MTU}.pcapng 2>/dev/null | sed -n 's/Number of packets: *//p') gói"
}

docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d pqc-server >/dev/null
sleep 2
resolve_server_ip

if [ "${QUICK:-0}" = "1" ]; then
  CONFIG_LIST="${CONFIGS:-0 0 1500}"
else
  CONFIG_LIST="${CONFIGS:-}"
fi

if [ -n "$CONFIG_LIST" ]; then
  # CONFIGS là danh sách phẳng "loss delay mtu loss delay mtu ..." → nhóm thành bộ 3
  set -- $CONFIG_LIST
  while [ $# -ge 3 ]; do
    run_hs_pair "$1" "$2" "$3" || echo "  [matrix2] cấu hình bị bỏ qua"
    shift 3
  done
else
  for LOSS in 0 1 3; do
    for DELAY in 0 50; do
      for MTU in 1500 1280; do
        run_hs_pair "$LOSS" "$DELAY" "$MTU" || echo "  [matrix2] cấu hình bị bỏ qua"
      done
    done
  done
  run_hs_pair 0 0 576 || echo "  [matrix2] cấu hình MTU576 bị bỏ qua"
  run_sites 1500 || echo "  [matrix2] sites 1500 bị bỏ qua"
  run_sites 1280 || echo "  [matrix2] sites 1280 bị bỏ qua"
fi

echo "ALL_DONE_2"
