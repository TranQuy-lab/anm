#!/usr/bin/env bash
# capture.sh — chạy TRONG container capture (chia sẻ netns với router).
#
# Vì sao không dùng `tcpdump -i any`: trong workload này capture SLL2 mất gói
# (đo được 1192 gói "received by filter" nhưng chỉ 892 gói được ghi) và file ghi trễ.
# Vì sao dumpcap: tcpdump 4.99.4 trong image chỉ nhận `-i` CUỐI CÙNG → mất hẳn một chiều.
#
# Dùng: capture.sh <out.pcapng> <snaplen> <bpf filter...>
set -euo pipefail
OUT="$1"; SNAP="$2"; shift 2
A=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.10\./ {print $2}' | cut -d@ -f1 | head -1)
B=$(ip -o -4 addr show | awk '$4 ~ /^172\.30\.20\./ {print $2}' | cut -d@ -f1 | head -1)
if [ -z "${A:-}" ] || [ -z "${B:-}" ]; then echo "[capture] KHÔNG dò được iface (A=$A B=$B)"; exit 3; fi
echo "[capture] iface A=$A B=$B snaplen=$SNAP out=$OUT filter=$*"

DP=0
finish() {  # dumpcap tạo file mode 600 (chủ root) → mở quyền cho host đọc được
  [ "$DP" != 0 ] && kill -INT "$DP" 2>/dev/null || true
  wait "$DP" 2>/dev/null || true
  chmod 644 "$OUT" 2>/dev/null || true
  exit 0
}
trap finish INT TERM
dumpcap -q -i "$A" -i "$B" -s "$SNAP" -w "$OUT" -f "$*" &
DP=$!
wait "$DP" || true
chmod 644 "$OUT" 2>/dev/null || true
