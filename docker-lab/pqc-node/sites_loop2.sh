#!/usr/bin/env bash
# sites_loop2.sh — sinh dataset phân loại "6 site ứng dụng", cũng chạy XEN KẼ hai nhóm KEM.
# Dùng: sites_loop2.sh <N_PER_SITE>
# Kết quả: /lab/results/sites2.csv  (rep,site,group,t_ns_wall,exit_code)
set -euo pipefail
N="${1:-30}"
OUT=/lab/results
mkdir -p "$OUT"
CSV="$OUT/sites2.csv"
echo "rep,site,group,t_ns_wall,exit_code" > "$CSV"

KEM_GROUPS=(X25519 X25519MLKEM768)
for rep in $(seq 1 "$N"); do
  for site in site1 site2 site3 site4 site5 site6; do
    for G in "${KEM_GROUPS[@]}"; do
      T0=$(date +%s%N)
      set +e
      echo "GET /${site}.bin HTTP/1.0" | timeout 15 \
        /usr/local/ssl/bin/openssl s_client -connect "${TARGET:-netem-router}:4433" \
          -tls1_3 -groups "$G" -quiet >/dev/null 2>&1
      RC=$?
      set -e
      T1=$(date +%s%N)
      echo "$rep,$site,$G,$T0,$RC" >> "$CSV"
      sleep 0.03
    done
  done
done
echo "[sites_loop2] xong: 6 site x $N rep x 2 nhóm"
