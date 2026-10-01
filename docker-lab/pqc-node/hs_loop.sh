#!/usr/bin/env bash
# hs_loop.sh — vòng đo handshake: N lần s_client tới server, ghi mốc thời gian monotonic mỗi lần.
# Dùng: hs_loop.sh <label> <N> [group]
# Kết quả: /lab/results/hs_<label>.csv  (cột: idx, group, t_ns_wall, exit_code)
set -euo pipefail
LABEL="${1:?label}"; N="${2:-30}"; GROUP="${3:-${GROUP:-X25519MLKEM768}}"
OUT=/lab/results
mkdir -p "$OUT"
CSV="$OUT/hs_${LABEL}.csv"
echo "idx,group,t_ns_wall,exit_code" > "$CSV"

for i in $(seq 1 "$N"); do
  T0=$(date +%s%N)
  set +e
  echo "GET /site1.bin HTTP/1.0" | timeout 10 \
    /usr/local/ssl/bin/openssl s_client -connect ${TARGET:-netem-router}:4433 \
      -tls1_3 -groups "$GROUP" -brief -quiet >/dev/null 2>&1
  RC=$?
  set -e
  T1=$(date +%s%N)
  echo "$i,$GROUP,$T0,$RC" >> "$CSV"
  sleep 0.15
done
echo "[hs_loop] $LABEL xong: $N lần, group=$GROUP"
