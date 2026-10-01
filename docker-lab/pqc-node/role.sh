#!/usr/bin/env bash
# role.sh — vai trò của node trong lab: server | client | router
set -euo pipefail

ROLE="${1:-idle}"
OUT=/lab/results
mkdir -p "$OUT"

gen_cert() {
  # Chứng chỉ tự ký EC P-256 nhỏ (như nhau giữa các nhóm so sánh → paired design hợp lệ).
  # -config trỏ sang cnf hệ thống vì make install_sw không cài openssl.cnf của source build.
  openssl req -config /etc/ssl/openssl.cnf -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /tmp/k.pem -out /tmp/c.pem -days 2 -subj "/CN=lab-server" >/dev/null 2>&1
}

case "$ROLE" in
  server)
    gen_cert
    # server hỗ trợ CẢ HAI nhóm — client quyết định nhóm qua -groups
    GROUPS_LIST="X25519MLKEM768:X25519"
    echo "[server] TLS 1.3 -WWW mode, groups=$GROUPS_LIST, /lab/www (6 site)"
    cd /lab/www
    # giữ stdin mở (EOF trên stdin làm s_server thoát ở chế độ detached)
    tail -f /dev/null | /usr/local/ssl/bin/openssl s_server -accept 4433 -tls1_3 \
      -groups "$GROUPS_LIST" -cert /tmp/c.pem -key /tmp/k.pem -WWW -quiet
    ;;
  client)
    echo "[client] chế độ tương tác — dùng các script trong /lab/scripts/"
    exec bash
    ;;
  router)
    echo "[router] ip_forward + netem 2 chiều + DNAT 4433 -> server. Biến: LOSS DELAY MTU SERVER_IP"
    # dò interface theo SUBNET (tên ethX không đáng tin trong môi trường Docker này)
    IF_A=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.10\./ {print $2}' | cut -d@ -f1 | head -1)
    IF_B=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.20\./ {print $2}' | cut -d@ -f1 | head -1)
    if [ -z "${IF_A:-}" ] || [ -z "${IF_B:-}" ]; then echo "[router] không dò được iface labnet (IF_A=$IF_A IF_B=$IF_B) — abort"; exit 3; fi
    SERVER_IP="${SERVER_IP:-$(getent hosts lab-pqc-server 2>/dev/null | awk '{print $1}' | head -1 || true)}"
    if [ -z "${SERVER_IP}" ]; then echo "[router] THIẾU SERVER_IP (DNS môi trường không hoạt động) — abort"; exit 3; fi
    iptables -t nat -A PREROUTING -i "$IF_A" -p tcp --dport 4433 -j DNAT --to-destination "${SERVER_IP}:4433"
    iptables -t nat -A POSTROUTING -o "$IF_B" -p tcp -d "$SERVER_IP" --dport 4433 -j MASQUERADE
    # MSS clamp: mô phỏng PMTUD hoạt động đúng (endpoint không bao giờ vượt MTU đường truyền).
    # Không có clamp, ICMP frag-needed bị môi trường sandbox chặn → blackhole (bản thân nó
    # là một hiện tượng thật của PQC handshake, được ghi nhận riêng trong báo cáo).
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
      || echo "[router] CẢNH BÁO: TCPMSS không khả dụng — kịch bản MTU sẽ là blackhole PMTUD"
    for IF in "$IF_A" "$IF_B"; do
      ip link set "$IF" mtu "${MTU:-1500}"
      tc qdisc replace dev "$IF" root netem delay "${DELAY:-0ms}" loss "${LOSS:-0%}"
    done
    echo "[router] sẵn sàng: $IF_A (client-side) <-> $IF_B (server-side -> $SERVER_IP), loss=${LOSS:-0} delay=${DELAY:-0} mtu=${MTU:-1500}"
    tail -f /dev/null | sleep infinity & wait
    ;;
  *) echo "dùng: role.sh server|client|router"; exit 1 ;;
esac
