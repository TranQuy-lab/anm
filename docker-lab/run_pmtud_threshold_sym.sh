#!/usr/bin/env bash
# run_pmtud_threshold_sym.sh — QUÉT NGƯỠNG trên ĐƯỜNG ĐỐI XỨNG (MTU_A = MTU_B).
#
# Câu hỏi: tuyên bố "PQC dịch ngưỡng an toàn từ ~820 B lên ~1450 B" có đo được không?
# Thiết kế: giữ MTU_A=1500 (để router là điểm nghẽn cho chiều client→server, xem run_pmtud.sh),
# quét MTU_B ∈ {900, 1200, 1400, 1440, 1448} × {X25519, X25519MLKEM768}, CLAMP=off,
# DROP_ICMP_FRAG=1, 3 lần thử mỗi ô. ClientHello hybrid là 1393 B ⇒ cần MTU_B ≥ 1393+52 = 1445;
# ClientHello X25519 là 217 B ⇒ sống ở mọi mức quét.
#
# Lưu ý: capture phải được khởi động LẠI sau mỗi lần tạo router, vì container capture chia sẻ
# netns với router (router bị recreate ⇒ netns cũ biến mất).
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
N_TRIAL="${N_TRIAL:-3}"
MTUS="${MTUS:-820 1200 1400 1445 1460 1500 1520}"
OUT="results/pmtud_threshold_sym.csv"
# ghi NỐI TIẾP: giữ header nếu file đã có (cho phép quét bổ sung ở dải MTU khác)
[ -f "$OUT" ] || echo "cell,group,mtu_b,clamp,icmp_policy,trial,rc,established" > "$OUT"

net_ip() {
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}
docker compose up -d pqc-server >/dev/null; sleep 2
export LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)

for MTU_B in $MTUS; do
  for G in X25519 X25519MLKEM768; do
    CELL="thr_${MTU_B}_${G}"
    echo "=== [ngưỡng] MTU_B=$MTU_B group=$G ==="
    LOSS=0 DELAY=0ms MTU="$MTU_B" MTU_A="$MTU_B" MTU_B="$MTU_B" CLAMP=off DROP_ICMP_FRAG=1 \
      docker compose up -d --force-recreate --no-deps netem-router >/dev/null
    sleep 1.2
    ROUTER_IP=$(net_ip labnet-a lab-netem-router)
    CAP="cap_${CELL}"
    docker rm -f "$CAP" >/dev/null 2>&1 || true
    docker run -d --name "$CAP" --net=container:lab-netem-router \
      --cap-add=NET_RAW --cap-add=NET_ADMIN \
      -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
      bash /lab/scripts/capture.sh "/lab/results/pcap_${CELL}.pcapng" 0 "tcp port 4433 or icmp" >/dev/null
    sleep 0.5
    docker compose restart pqc-server >/dev/null 2>&1; sleep 2.5
    for t in $(seq 1 "$N_TRIAL"); do
      set +e
      docker compose run --rm -e TARGET="$ROUTER_IP" -e GROUP="$G" pqc-client bash -c \
        'echo "GET /site1.bin HTTP/1.0" | timeout 8 /usr/local/ssl/bin/openssl s_client \
           -connect "$TARGET":4433 -tls1_3 -groups "$GROUP" -brief 2>&1' > /tmp/thr.out 2>&1
      RC=$?
      set -e
      EST=0; grep -q "CONNECTION ESTABLISHED" /tmp/thr.out && EST=1
      echo "${CELL},${G},${MTU_B},off,drop,${t},${RC},${EST}" >> "$OUT"
      printf "   trial %s: rc=%s established=%s\n" "$t" "$RC" "$EST"
      [ "$EST" = "1" ] || { docker compose restart pqc-server >/dev/null 2>&1; sleep 2.5; }
    done
    sleep 2
    docker kill -s INT "$CAP" >/dev/null 2>&1 || true; sleep 0.8
    docker rm -f "$CAP" >/dev/null 2>&1 || true
  done
done
echo "PMTUD_THRESHOLD_SYM_DONE"
