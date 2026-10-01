#!/usr/bin/env bash
# run_ch_budget.sh — capture SNAPLEN ĐẦY ĐỦ 3 bắt tay mỗi nhóm để bóc tách key_share
# (đối chiếu FIPS 203: ek 1184 B ở ClientHello, ct 1088 B ở ServerHello).
# Ma trận chính dùng -s 160 nên không đọc được nội dung extension.
set -euo pipefail
cd "$(dirname "$0")"
chmod 0777 results 2>/dev/null || true
net_ip() {
  docker network inspect "$1" --format '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
    | tr ' ' '\n' | sed 's|^/||' | grep "^$2=" | cut -d= -f2 | cut -d/ -f1 | head -1
}
docker compose up -d pqc-server >/dev/null; sleep 2
export LAB_SERVER_IP=$(net_ip labnet-b lab-pqc-server)
LOSS=0 DELAY=0ms MTU=1500 CLAMP=on DROP_ICMP_FRAG=0 \
  docker compose up -d --force-recreate --no-deps netem-router >/dev/null
sleep 1.5
ROUTER_IP=$(net_ip labnet-a lab-netem-router)
for G in X25519 X25519MLKEM768; do
  CAP="cap_full_${G}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run -d --name "$CAP" --net=container:lab-netem-router \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
    bash /lab/scripts/capture.sh "/lab/results/pcap_full_${G}.pcapng" 0 "tcp port 4433" >/dev/null
  sleep 0.6
  # -keylogfile đi KÈM mỗi lần chạy để keylog khớp đúng pcap (nếu không, keylog là file mồ côi
  # và không giải mã được EncryptedExtensions ⇒ không kiểm chứng được phần −10 B).
  rm -f "results/keys_${G}.log"
  docker compose run --rm -e TARGET="$ROUTER_IP" -e GROUP="$G" pqc-client bash -c \
    'for i in 1 2 3; do echo "GET /site1.bin HTTP/1.0" | timeout 10 /usr/local/ssl/bin/openssl s_client -connect "$TARGET":4433 -tls1_3 -groups "$GROUP" -keylogfile "/lab/results/keys_'"$G"'.log" -brief -quiet >/dev/null 2>&1 || true; sleep 0.2; done'
  sleep 2
  docker kill -s INT "$CAP" >/dev/null 2>&1 || true
  sleep 0.8
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  echo "[ch-budget] $G: $(capinfos -c results/pcap_full_${G}.pcapng 2>/dev/null | sed -n 's/Number of packets: *//p') gói"
done
echo "CH_BUDGET_DONE"
