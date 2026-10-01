#!/usr/bin/env bash
# extract_metrics.sh — trích per-packet TCP data từ mọi pcap → packets_all.tsv (chạy trên host)
set -euo pipefail
cd "$(dirname "$0")"
LABDIR="../../docker-lab"
OUT="packets_all.tsv"
echo -e "pcap\tstream\ttime\tsrc\ttcplen\tseq\tack\tretrans\tsyn\tfin\trst" > "$OUT"
for f in "$LABDIR"/results/pcap_*.pcapng; do
  name=$(basename "$f")
  echo "  - $name"
  tshark -r "$f" -Y 'tcp' -T fields \
    -e tcp.stream -e frame.time_epoch -e ip.src -e tcp.len -e tcp.seq -e tcp.ack \
    -e tcp.analysis.retransmission -e tcp.flags.syn -e tcp.flags.fin -e tcp.flags.reset \
    2>/dev/null | awk -v n="$name" -F'\t' 'NF>=10{OFS="\t"; print n,$0}' >> "$OUT"
done
wc -l "$OUT"
