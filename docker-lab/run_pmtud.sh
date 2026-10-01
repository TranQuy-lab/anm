#!/usr/bin/env bash
# run_pmtud.sh — THÍ NGHIỆM CÓ KIỂM SOÁT: PMTUD blackhole với bắt tay PQC.
#
# Câu hỏi: khi đường truyền có PMTU nhỏ hơn kích thước bắt tay hybrid VÀ ICMP
# "fragmentation needed" bị lọc, bắt tay hybrid có treo thật không? Cổ điển có treo không?
#
# Thiết kế nhân tố: nhóm KEM {X25519, X25519MLKEM768} × PMTU {1500, 1280, 576}
#                   × ICMP frag-needed {cho qua, chặn} × MSS clamp {off, on}
#   - CLAMP=off: endpoint không biết PMTU → router phải phát ICMP frag-needed (PMTUD động).
#   - CLAMP=on : mô phỏng mạng/endpoint đã xử lý đúng (đối chứng dương).
#   - DROP_ICMP_FRAG=1: iptables OUTPUT/FORWARD chặn ICMP type 3 code 4 (middlebox lọc ICMP).
#
# Đo: tỉ lệ bắt tay hoàn tất, thời gian, số ICMP frag-needed quan sát trên đường truyền.
# Capture full snaplen, filter gồm cả icmp → bằng chứng gốc, không suy diễn.
#
# Biến: N_TRIAL (mặc định 6)
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
N_TRIAL="${N_TRIAL:-6}"
OUT="results/pmtud_trials.csv"
echo "cell,group,mtu,clamp,icmp_policy,trial,rc,elapsed_s,established" > "$OUT"

net_ip() {
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}

set_router() {
  # MTU_A (phía client) giữ 1500 để gói lớn TỚI ĐƯỢC router; MTU_B (phía server) nhỏ
  # ⇒ router là điểm nghẽn thật và là nơi phát ICMP frag-needed (đối tượng can thiệp).
  LOSS=0 DELAY=0ms MTU="$1" MTU_A=1500 MTU_B="$1" CLAMP="$2" DROP_ICMP_FRAG="$3" \
    docker compose up -d --force-recreate --no-deps netem-router >/dev/null
  sleep 1.2
}

wait_server() {
  docker compose restart pqc-server >/dev/null 2>&1
  sleep 2.5
}

probe() {  # probe <group> -> in ra "rc elapsed established"
  local G="$1" ROUTER_IP="$2"
  local T0 T1 RC
  T0=$(date +%s.%N)
  set +e
  docker compose run --rm -e TARGET="$ROUTER_IP" -e GROUP="$G" pqc-client bash -c \
    'echo "GET /site1.bin HTTP/1.0" | timeout 8 /usr/local/ssl/bin/openssl s_client \
       -connect "$TARGET":4433 -tls1_3 -groups "$GROUP" -brief 2>&1' > /tmp/pmtud_probe.out 2>&1
  RC=$?
  set -e
  T1=$(date +%s.%N)
  local EST=0
  grep -q "CONNECTION ESTABLISHED" /tmp/pmtud_probe.out && EST=1
  echo "$RC $(echo "$T1 - $T0" | bc) $EST"
}

docker compose up -d pqc-server >/dev/null
sleep 2
export LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)
echo "[pmtud] SERVER_IP=$LAB_SERVER_IP"

run_cell() {  # run_cell <id> <group> <mtu> <clamp> <icmp:allow|drop>
  local ID="$1" G="$2" MTU="$3" CLAMP="$4" ICMP="$5"
  local DROP=0; [ "$ICMP" = "drop" ] && DROP=1
  echo "=== [cell $ID] group=$G mtu=$MTU clamp=$CLAMP icmp=$ICMP n=$N_TRIAL ==="
  set_router "$MTU" "$CLAMP" "$DROP"
  local ROUTER_IP; ROUTER_IP=$(net_ip labnet-a lab-netem-router)
  local CAP="cap_pmtud_${ID}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run -d --name "$CAP" --net=container:lab-netem-router \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
    bash /lab/scripts/capture.sh "/lab/results/pcap_pmtud_${ID}.pcapng" 0 "tcp port 4433 or icmp" >/dev/null
  sleep 0.6
  wait_server
  local t
  for t in $(seq 1 "$N_TRIAL"); do
    read -r RC ELAPSED EST < <(probe "$G" "$ROUTER_IP")
    echo "${ID},${G},${MTU},${CLAMP},${ICMP},${t},${RC},${ELAPSED},${EST}" >> "$OUT"
    printf "   trial %s: rc=%s t=%ss established=%s\n" "$t" "$RC" "$ELAPSED" "$EST"
    # s_server đơn luồng: chỉ cần restart khi lần trước KHÔNG hoàn tất
    [ "$EST" = "1" ] || wait_server
  done
  sleep 2
  docker kill -s INT "$CAP" >/dev/null 2>&1 || true
  sleep 0.8
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  local n_icmp=0
  n_icmp=$(tshark -r "results/pcap_pmtud_${ID}.pcapng" -Y 'icmp.type==3 && icmp.code==4' 2>/dev/null | wc -l)
  echo "  [cell $ID] ICMP frag-needed quan sát được: $n_icmp"
}

# --- Các ô thí nghiệm ---
# PMTU 1280: ClientHello hybrid 1393 B > 1228 B MSS ⇒ cần PMTUD
run_cell c1_hyb_1280_drop  X25519MLKEM768 1280 off drop
run_cell c2_hyb_1280_allow X25519MLKEM768 1280 off allow
run_cell c3_x25519_1280_drop  X25519 1280 off drop
run_cell c4_x25519_1280_allow X25519 1280 off allow
run_cell c5_hyb_1280_clampon_drop X25519MLKEM768 1280 on drop
# PMTU 1500: mọi gói vừa ⇒ đối chứng "không liên quan MTU"
run_cell c6_hyb_1500_drop   X25519MLKEM768 1500 off drop
run_cell c7_x25519_1500_drop X25519 1500 off drop
# PMTU 576: cả cổ điển cũng vượt (server flight 769 B > 536 B) ⇒ kiểm tra tính đặc thù PQC
run_cell c8_hyb_576_drop    X25519MLKEM768 576 off drop
run_cell c9_x25519_576_drop X25519 576 off drop

echo "PMTUD_DONE"
