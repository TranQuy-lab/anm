#!/usr/bin/env bash
# hs_loop2.sh — vòng đo handshake XEN KẼ (interleaved / ABAB) giữa hai nhóm KEM.
#
# Khác biệt so với hs_loop.sh: hai nhóm được chạy luân phiên trong CÙNG một phiên,
# cùng một cấu hình mạng, lặp lại N lần. Nhờ đó chỉ số lặp `rep` là khóa ghép cặp hợp lệ
# (paired design thật), loại bỏ nhiễu trôi hệ thống do chạy khối tuần tự.
#
# Dùng: hs_loop2.sh <TAG> <N>
#       ORDER=random  → đảo thứ tự hai nhóm ngẫu nhiên trong mỗi cặp (đối chứng loại trừ
#                       hiệu ứng thứ tự: mặc định X25519 luôn chạy trước nhóm lai).
# Kết quả: /lab/results/hs2_<TAG>_<GROUP>.csv  (rep,group,t_ns_wall,exit_code)
set -euo pipefail
TAG="${1:?tag}"; N="${2:-30}"
ORDER="${ORDER:-fixed}"
OUT=/lab/results
mkdir -p "$OUT"

KEM_GROUPS=(X25519 X25519MLKEM768)
for G in "${KEM_GROUPS[@]}"; do
  echo "rep,group,t_ns_wall,exit_code" > "$OUT/hs2_${TAG}_${G}.csv"
done

for rep in $(seq 1 "$N"); do
  ORDER_THIS=(X25519 X25519MLKEM768)
  if [ "$ORDER" = "random" ] && [ $((RANDOM % 2)) -eq 1 ]; then
    ORDER_THIS=(X25519MLKEM768 X25519)
  fi
  for G in "${ORDER_THIS[@]}"; do
    T0=$(date +%s%N)
    set +e
    echo "GET /site1.bin HTTP/1.0" | timeout 10 \
      /usr/local/ssl/bin/openssl s_client -connect "${TARGET:-netem-router}:4433" \
        -tls1_3 -groups "$G" -brief -quiet >/dev/null 2>&1
    RC=$?
    set -e
    T1=$(date +%s%N)
    echo "$rep,$G,$T0,$RC" >> "$OUT/hs2_${TAG}_${G}.csv"
    sleep 0.05
  done
  sleep 0.10
done
echo "[hs_loop2] $TAG xong: $N cặp (mỗi nhóm $N bắt tay)"
