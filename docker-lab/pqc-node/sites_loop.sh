#!/usr/bin/env bash
# sites_loop.sh — sinh dataset "6 site ứng dụng" (kích thước phản hồi khác nhau) cho RQ2/RQ3.
# Dùng: sites_loop.sh <label> <N_PER_SITE> [group]
# Mỗi flow: GET /siteK.bin → server trả file kích thước đặc trưng → flow metadata phân biệt site.
# Kết quả: /lab/results/sites_<label>.csv (cột: idx, site, group, t_ns_wall, bytes_req, exit_code)
set -euo pipefail
LABEL="${1:?label}"; N="${2:-30}"; GROUP="${3:-${GROUP:-X25519MLKEM768}}"
OUT=/lab/results
mkdir -p "$OUT"
CSV="$OUT/sites_${LABEL}.csv"
echo "idx,site,group,t_ns_wall,exit_code" > "$CSV"

for site in site1 site2 site3 site4 site5 site6; do
  for i in $(seq 1 "$N"); do
    T0=$(date +%s%N)
    set +e
    echo "GET /${site}.bin HTTP/1.0" | timeout 15 \
      /usr/local/ssl/bin/openssl s_client -connect ${TARGET:-netem-router}:4433 \
        -tls1_3 -groups "$GROUP" -quiet >/dev/null 2>&1
    RC=$?
    set -e
    T1=$(date +%s%N)
    echo "$i,$site,$GROUP,$T0,$RC" >> "$CSV"
    sleep 0.1
  done
done
echo "[sites_loop] $LABEL xong: 6 site x $N, group=$GROUP"
