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
# ÁNH XẠ TƯỜNG MINH: sweep đối xứng chạy sau đã ghi đè các pcap cùng tên của sweep bất đối
# xứng ở những MTU trùng nhau (lỗi vận hành đã ghi nhận). Vì vậy pcap chỉ được dùng cho đúng
# sweep mà nó thuộc về; còn TỈ LỆ HOÀN TẤT luôn lấy từ CSV kết quả tương ứng.
SWEEPS = [("asym", {900, 1440, 1448}, "pmtud_threshold.csv",
           "đường có NÚT THẮT GIỮA: MTU_A=1500, MTU_B=MTU"),
          ("sym", {820, 1200, 1400, 1445, 1460, 1500, 1520}, "pmtud_threshold_sym.csv",
           "đường ĐỐI XỨNG: MTU_A=MTU_B=MTU")]
for sweep, mtus, csvname, desc in SWEEPS:
  for f in sorted(glob.glob(os.path.join(LAB, "pcap_thr_*.pcapng"))):
    m = re.match(r"pcap_thr_(\d+)_(X25519MLKEM768|X25519)\.pcapng$", os.path.basename(f))
    if not m:
        continue
    mtu, grp = int(m.group(1)), m.group(2)
    if mtu not in mtus:
        continue
    c2s = fields(f, "ip.src==172.30.20.3 && tcp.len>0", ["tcp.len"])           # client -> server
    s2c = fields(f, "ip.src==172.30.10.2 && tcp.len>0", ["tcp.len"])           # server -> client (egress)
    icmp = len(fields(f, "icmp.type==3 && icmp.code==4", ["frame.number"]))
    rows.append(dict(sweep=sweep, mtu_b=mtu, group=grp, desc=desc,
                     ch_crossed=len(c2s) > 0, ch_seg_max=max([int(r[0]) for r in c2s] or [0]),
                     srv_crossed=len(s2c) > 0, srv_seg_max=max([int(r[0]) for r in s2c] or [0]),
                     icmp=icmp))

T = pd.DataFrame(rows)
res = {}
for sweep, mtus, csvname, desc in SWEEPS:
    csv = os.path.join(LAB, csvname)
    if not os.path.exists(csv):
        continue
    D = pd.read_csv(csv)
    g = D.groupby(["mtu_b", "group"]).established.agg(n="size", ok="mean").reset_index()
    dirs = T[T.sweep == sweep].set_index(["mtu_b", "group"])
    print(f"=== sweep: {sweep} — {desc} ({csvname}) ===")
    print(f"{'MTU':>6} {'nhóm':<16} {'CH→server':>10} {'max':>5} {'server→client':>14} {'ICMP':>5} {'hoàn tất':>9}")
    TS = g.copy()
    for _, r in g.sort_values(["mtu_b", "group"]).iterrows():
        key = (int(r.mtu_b), r.group)
        d = dirs.loc[key] if key in dirs.index else None
        ch = str(bool(d.ch_crossed)) if d is not None else "—"
        chmax = int(d.ch_seg_max) if d is not None else "—"
        ic = int(d.icmp) if d is not None else "—"
        print(f"{int(r.mtu_b):>6} {r.group:<16} {ch:>10} {str(chmax):>5} "
              f"{str(bool(d.srv_crossed)) if d is not None else '—':>14} {str(ic):>5} {r.ok:>9.2f}")
        res[f"{sweep}|M{int(r.mtu_b)}|{r.group}"] = dict(
            ch_crossed=bool(d.ch_crossed) if d is not None else None,
            ch_max_seg=int(d.ch_seg_max) if d is not None else None,
            srv_crossed=bool(d.srv_crossed) if d is not None else None,
            icmp=int(d.icmp) if d is not None else None,
            n=int(r.n), completed=round(float(r.ok), 2))
    # ngưỡng: MTU nhỏ nhất mà CẢ 3 lần đều hoàn tất
    thr = {}
    for grp in g.group.unique():
        ss = g[g.group == grp].sort_values("mtu_b")
        ok = ss[ss.ok >= 0.999]
        thr[grp] = int(ok.mtu_b.min()) if len(ok) else None
    res[f"threshold_completed_{sweep}"] = thr
    print("  ngưỡng (MTU nhỏ nhất đạt 3/3):", thr, "\n")
json.dump(res, open(os.path.join(BASE, "tables", "pmtud_threshold.json"), "w"), indent=2, ensure_ascii=False)
print("\n[BẢNG] pmtud_threshold.json")
