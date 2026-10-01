#!/usr/bin/env bash
# extract_metrics.sh — trích per-packet TCP data từ pcap → TSV (chạy trên host).
#
# Dùng:
#   bash extract_metrics.sh                 # dataset chính (pcap2_*), ra packets_all.tsv
#   bash extract_metrics.sh gso             # dataset lưu trữ bị GSO che, ra packets_all_gso.tsv
#
# Ghi chú: `tcp.len` đọc từ header IP nên KHÔNG phụ thuộc snaplen (-s 160 là đủ cho mọi
# tổng byte/segment; chỉ nội dung payload mới cần snaplen đầy đủ).
set -euo pipefail
cd "$(dirname "$0")"
LABDIR="../../docker-lab"

MODE="${1:-main}"
case "$MODE" in
  main) PATTERN="results/pcap2_.*\.pcapng"; OUT="packets_all.tsv" ;;
  gso)  PATTERN="archive_gso_capture/pcap_.*\.pcapng"; OUT="packets_all_gso.tsv" ;;
  *)    PATTERN="$MODE"; OUT="${2:-packets_all.tsv}" ;;
esac

echo -e "pcap\tstream\ttime\tsrc\tdst\ttcplen\tseq\tack\tretrans\tsyn\tfin\trst\tseqraw" > "$OUT"
shopt -s nullglob
FILES=()
for f in "$LABDIR"/results/*.pcapng "$LABDIR"/results/archive_gso_capture/*.pcapng; do
  [[ "$f" =~ $PATTERN ]] && FILES+=("$f")
done
if [ ${#FILES[@]} -eq 0 ]; then echo "KHÔNG tìm thấy pcap khớp: $PATTERN"; exit 2; fi

for f in "${FILES[@]}"; do
  name=$(basename "$f")
  echo "  - $name"
  tshark -r "$f" -Y 'tcp' -T fields \
    -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len -e tcp.seq -e tcp.ack \
    -e tcp.analysis.retransmission -e tcp.flags.syn -e tcp.flags.fin -e tcp.flags.reset \
    -e tcp.seq_raw \
    2>/dev/null | awk -v n="$name" -F'\t' 'NF>=11{OFS="\t"; print n,$0}' >> "$OUT"
done
echo "[extract] $OUT: $(wc -l < "$OUT") dòng (gồm header)"
