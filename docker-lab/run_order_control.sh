#!/usr/bin/env bash
# run_order_control.sh — ĐỐI CHỨNG loại trừ HIỆU ỨNG THỨ TỰ.
#
# Vấn đề: trong ma trận chính, X25519 luôn chạy TRƯỚC nhóm lai trong mỗi cặp. Nếu bản thân
# "chạy thứ hai" đã chậm hơn (hoặc nhanh hơn) một cách hệ thống, kết luận "nhóm lai chậm hơn"
# sẽ bị nhiễu. Ở đây thứ tự được ĐẢO NGẪU NHIÊN cho từng cặp (ORDER=random); nếu độ lệch RTT
# vẫn giữ nguyên độ lớn và hướng thì hiệu ứng thứ tự bị loại trừ.
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
N="${N_HS:-30}"
net_ip() {
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}
docker compose up -d pqc-server >/dev/null; sleep 2
export LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)
for MTU in 1500 1280; do
  echo "=== [order-control] MTU $MTU, $N cặp, thứ tự ngẫu nhiên ==="
  LOSS=0 DELAY=0ms MTU="$MTU" CLAMP=on DROP_ICMP_FRAG=0 \
    docker compose up -d --force-recreate --no-deps netem-router >/dev/null
  sleep 1.5
  ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  CAP="cap_ord_${MTU}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run -d --name "$CAP" --net=container:lab-netem-router \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
    bash /lab/scripts/capture.sh "/lab/results/pcap_order_M${MTU}.pcapng" 160 "tcp port 4433" >/dev/null
  sleep 0.6
  docker compose run --rm -e TARGET="$ROUTER_IP" -e ORDER=random \
    pqc-client /usr/local/bin/hs_loop2.sh "ORD${MTU}" "$N" >/dev/null 2>&1
  sleep 2
  docker kill -s INT "$CAP" >/dev/null 2>&1 || true
  sleep 0.8
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  echo "  [xong] pcap_order_M${MTU}.pcapng: $(capinfos -c results/pcap_order_M${MTU}.pcapng 2>/dev/null | sed -n 's/Number of packets: *//p') gói"
done
echo "ORDER_CONTROL_DONE"
