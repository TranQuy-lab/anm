#!/usr/bin/env python3
# pmtud_threshold.py — phân tích QUÉT NGƯỠNG PMTU, tách bạch HAI CHIỀU.
#
# Vì cảnh báo của vòng phản biện thứ ba: khi CLAMP=off, chiều server→client cũng bị chặn bởi
# MTU_B (server phân đoạn theo MSS 1460 mà nó học từ SYN của client), nên một ô "hỏng" chưa nói
# lên điều gì về ClientHello. Script này đọc TỪNG pcap của từng ô và trả lời:
#   - ClientHello có tới được server không?   (leg egress post-NAT có dữ liệu client→server)
#   - Flight server có tới được client không? (leg egress pre-NAT có dữ liệu router→client)
#   - Bắt tay có hoàn tất không?              (pmtud_threshold.csv)
import glob, json, os, re, subprocess
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(BASE, "..", "..", "docker-lab", "results"))

def fields(pcap, filt, flds):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", filt, "-T", "fields"]
                         + sum([["-e", f] for f in flds], []),
                         capture_output=True, text=True).stdout.strip().split("\n")
    return [l.split("\t") for l in out if l.strip()]

rows = []
for f in sorted(glob.glob(os.path.join(LAB, "pcap_thr_*.pcapng"))):
    m = re.match(r"pcap_thr_(\d+)_(X25519MLKEM768|X25519)\.pcapng$", os.path.basename(f))
    if not m:
        continue
    mtu, grp = int(m.group(1)), m.group(2)
    c2s = fields(f, "ip.src==172.30.20.3 && tcp.len>0", ["tcp.len"])           # client -> server
    s2c = fields(f, "ip.src==172.30.10.2 && tcp.len>0", ["tcp.len"])           # server -> client (egress)
    icmp = len(fields(f, "icmp.type==3 && icmp.code==4", ["frame.number"]))
    rows.append(dict(mtu_b=mtu, group=grp,
                     ch_crossed=len(c2s) > 0, ch_seg_max=max([int(r[0]) for r in c2s] or [0]),
                     srv_crossed=len(s2c) > 0, srv_seg_max=max([int(r[0]) for r in s2c] or [0]),
                     icmp=icmp))

T = pd.DataFrame(rows)
csv = os.path.join(LAB, "pmtud_threshold.csv")
res = {}
if os.path.exists(csv):
    D = pd.read_csv(csv)
    g = D.groupby(["mtu_b", "group"]).established.agg(n="size", ok="mean").reset_index()
    T = T.merge(g, on=["mtu_b", "group"], how="left")
    for _, r in T.sort_values(["mtu_b", "group"]).iterrows():
        res[f"M{int(r.mtu_b)}|{r.group}"] = dict(
            ch_crossed=bool(r.ch_crossed), ch_max_seg=int(r.ch_seg_max),
            srv_crossed=bool(r.srv_crossed), srv_max_seg=int(r.srv_seg_max),
            icmp=int(r.icmp), n=int(r.n) if pd.notna(r.n) else 0,
            completed=round(float(r.ok), 2) if pd.notna(r.ok) else None)
    print(f"{'MTU_B':>6} {'nhóm':<16} {'CH→server':>10} {'max':>5} {'server→client':>14} {'max':>5} {'ICMP':>5} {'hoàn tất':>9}")
    for k, v in res.items():
        print(f"{k.split('|')[0]:>6} {k.split('|')[1]:<16} {str(v['ch_crossed']):>10} {v['ch_max_seg']:>5} "
              f"{str(v['srv_crossed']):>14} {v['srv_max_seg']:>5} {v['icmp']:>5} {str(v['completed']):>9}")
    # ngưỡng suy ra
    thr = {}
    for grp in T.group.unique():
        s = T[T.group == grp].sort_values("mtu_b")
        ok = s[s.ok == 1.0]
        thr[grp] = int(ok.mtu_b.min()) if len(ok) else None
    res["threshold_completed"] = thr
json.dump(res, open(os.path.join(BASE, "tables", "pmtud_threshold.json"), "w"), indent=2, ensure_ascii=False)
print("\n[BẢNG] pmtud_threshold.json")
