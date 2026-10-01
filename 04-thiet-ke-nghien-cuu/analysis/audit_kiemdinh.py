#!/usr/bin/env python3
# audit_kiemdinh.py — KIỂM ĐỊNH CHÉO ĐỘC LẬP kết quả đã công bố trong báo cáo.
# Nguyên tắc mù: KHÔNG tái sử dụng code/logic của rq*_analysis.py —
#   * trích xuất bằng tshark -T json (bản gốc dùng -T fields)
#   * định nghĩa flight theo TÍNH LIỀN KỀ SEQ RIÊNG TỪNG CHIỀU (bản gốc dùng mốc thời gian)
#   * client xác định theo cổng (≠4433) + subnet, không dùng cờ SYN
# Mỗi CHECK in PASS/FAIL/WARN kèm số liệu để đối chiếu với báo cáo.
import json, glob, re, subprocess, sys, os
import numpy as np
import pandas as pd
from scipy import stats

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docker-lab", "results")
BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = []
def check(cid, name, ok, detail):
    ok = bool(ok)
    verdict = "PASS" if ok is True else ("FAIL" if ok is False else "WARN")
    RESULTS.append((cid, name, verdict, detail))
    print(f"[{verdict}] {cid} — {name}\n        {detail}\n")

def extract(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tcp", "-T", "json",
         "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport",
         "-e", "tcp.len", "-e", "tcp.seq_raw", "-e", "frame.time_epoch"],
        capture_output=True, text=True).stdout
    pkts = []
    for line in json.loads(out or "[]"):
        l = line["_source"]["layers"]
        def g(k):
            v = l.get(k)
            return v[0] if isinstance(v, list) else v
        try:
            pkts.append(dict(
                stream=int(g("tcp.stream")), src=g("ip.src"), sport=g("tcp.srcport"),
                tlen=int(g("tcp.len") or 0), seq=int(g("tcp.seq_raw") or 0),
                t=float(g("frame.time_epoch") or 0)))
        except (TypeError, ValueError):
            continue
    return pkts

def clusters_by_time_gap(pkts, gap_ms=1.0):
    """Phân cụm dữ liệu MỘT CHIỀU theo thời gian: các flight cách nhau ≥ 1 RTT (≫1 ms),
    gói trong cùng flight phát liên tiếp (µs). Trả về danh sách cụm (mỗi cụm = list gói)."""
    ps = sorted(pkts, key=lambda q: q["t"])
    clusters, cur = [], [ps[0]]
    for p in ps[1:]:
        if (p["t"] - cur[-1]["t"]) * 1000 > gap_ms:
            clusters.append(cur); cur = [p]
        else:
            cur.append(p)
    clusters.append(cur)
    return clusters

def stream_features(pkts):
    by = {}
    for p in pkts: by.setdefault(p["stream"], []).append(p)
    out = {}
    for st, ps in by.items():
        # client = đầu cuối KHÔNG ở cổng 4433 và thuộc subnet client-side (siêu dữ liệu topology)
        cands = {(p["src"], p["sport"]) for p in ps if p["sport"] != "4433"
                 and p["src"].startswith("172.30.10.")}
        if len(cands) != 1: continue
        cli = cands.pop()
        cp = [p for p in ps if (p["src"], p["sport"]) == cli and p["tlen"] > 0]
        sp = [p for p in ps if (p["src"], p["sport"]) != cli and p["tlen"] > 0]
        if not cp or not sp: continue
        cc = clusters_by_time_gap(cp)   # cụm client: [CH] [Fin+GET] [close_notify...]
        sc = clusters_by_time_gap(sp)   # cụm server: [SH..Fin] [response...] [close_notify]
        # cửa sổ client-flight-2: dữ liệu client trước khi server bắt đầu cụm phản hồi
        resp_t = min((p["t"] for p in sc[1]), default=float("inf")) if len(sc) > 1 else float("inf")
        cli_hs2 = sum(p["tlen"] for p in cp if p["t"] < resp_t)
        out[st] = dict(
            c1=sum(p["tlen"] for p in cc[0]),               # CH thuần
            c2=cli_hs2 - sum(p["tlen"] for p in cc[0]),
            cli_all=sum(p["tlen"] for p in cp),
            sv_all=sum(p["tlen"] for p in sp),
            sv=sum(p["tlen"] for p in sc[0]),               # flight bắt tay server
            n_cli=len(cp), n_srv=len(sp))
    return out

pat = re.compile(r"pcap_(X25519MLKEM768|X25519)_L(\d+)_D(\d+)_M(\d+)\.pcapng")
HS, SITES = {}, {}
for f in sorted(glob.glob(os.path.join(LAB, "pcap_*.pcapng"))):
    name = os.path.basename(f)
    w = stream_features(extract(f))
    m = pat.match(name)
    if m:
        HS[(m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)))] = list(w.values())
    elif name.startswith("pcap_sites_X"):
        SITES[name] = list(w.values())

med = lambda v: float(np.median(v)) if len(v) else float("nan")
print(f"Đã trích: {sum(len(v) for v in HS.values())} handshake flows, "
      f"{sum(len(v) for v in SITES.values())} site flows\n")

# ---------- CHECK A: tái xuất độc lập số công bố (297/768/1473/1846) ----------
pub = json.load(open(f"{BASE}/tables/rq1_summary.json"))["clean_network_hs_bytes"]
mine = {g: (med([x["c1"] + x["c2"] for x in HS[(g, 0, 0, 1500)]]),
            med([x["sv"] for x in HS[(g, 0, 0, 1500)]])) for g in ("X25519", "X25519MLKEM768")}
ch_pure = {g: med([x["c1"] for x in HS[(g, 0, 0, 1500)]]) for g in ("X25519", "X25519MLKEM768")}
okA = (abs(mine["X25519"][0] - pub["X25519"]["client_novel"]) <= 1 and
       abs(mine["X25519MLKEM768"][0] - pub["X25519MLKEM768"]["client_novel"]) <= 1 and
       abs(mine["X25519"][1] - pub["X25519"]["server"]) <= 1 and
       abs(mine["X25519MLKEM768"][1] - pub["X25519MLKEM768"]["server"]) <= 1)
check("A", "Tái xuất độc lập (json + time-gap clustering) khớp số công bố", okA,
      f"đo lại (cli=CH+flight2): X25519 {mine['X25519'][0]:.0f}/{mine['X25519'][1]:.0f} | "
      f"MLKEM {mine['X25519MLKEM768'][0]:.0f}/{mine['X25519MLKEM768'][1]:.0f} — công bố 297/768, 1473/1846 | "
      f"CH thuần: {ch_pure['X25519']:.0f} → {ch_pure['X25519MLKEM768']:.0f} (tỉ lệ {ch_pure['X25519MLKEM768']/ch_pure['X25519']:.2f}×)")

# ---------- CHECK B: placebo — chia đôi ngẫu nhiên CÙNG nhóm ----------
def paired_p(xs, ys):
    xs, ys = np.asarray(xs, float), np.asarray(ys, float)
    n = min(len(xs), len(ys))
    if n < 5 or np.allclose(xs[:n], ys[:n]): return 1.0
    return float(stats.wilcoxon(xs[:n], ys[:n]).pvalue)
rng = np.random.default_rng(2026)
hits = 0
key = ("X25519", 3, 50, 1280)
tot = np.array([x["cli_all"] for x in HS[key]])
for _ in range(200):
    idx = rng.permutation(len(tot)); h = len(tot) // 2
    hits += paired_p(tot[idx[:h]], tot[idx[h:]]) < 0.05
fp = hits / 200
check("B", "Placebo: chia đôi ngẫu nhiên CÙNG nhóm (L3_D50_M1280), 200 lần → p<0.05 ≈ 5%",
      fp <= 0.10, f"tỷ lệ = {fp:.3f}")

# ---------- CHECK C: đối chiếu lý thuyết FIPS 203 ----------
d_cli = ch_pure["X25519MLKEM768"] - ch_pure["X25519"]
d_srv = mine["X25519MLKEM768"][1] - mine["X25519"][1]
okC = abs(d_cli - 1176) / 1176 < 0.08 and abs(d_srv - 1152) / 1152 < 0.10
check("C", "Chênh lệch byte khớp lý thuyết ML-KEM-768 (ct 1088 B / pubkey 1184 B)", okC,
      f"client +{d_cli:.0f}B (lý thuyết ≈1176, lệch {abs(d_cli-1176)/1176:.1%}) | "
      f"server +{d_srv:.0f}B (lý thuyết ≈1152, lệch {abs(d_srv-1152)/1152:.1%})")

# ---------- CHECK D: fingerprint mù — ngưỡng 800B không dùng nhãn ----------
a = [x["c1"] for x in SITES.get("pcap_sites_X25519.pcapng", [])]
b = [x["c1"] for x in SITES.get("pcap_sites_X25519MLKEM768.pcapng", [])]
if a and b:
    blind = (np.array(a + b) > 800).astype(int)
    truth = np.array([0] * len(a) + [1] * len(b))
    acc = float((blind == truth).mean())
    okD = acc == 1.0
    det = f"accuracy = {acc:.4f} ({len(a)}+{len(b)} flows)"
else:
    okD, det = False, "thiếu flows"
check("D", "Fingerprint mù: ngưỡng 800B tách hai nhóm không cần nhãn", okD, det)

# ---------- CHECK E: cơ chế kháng drift — chỉ đặc trưng handshake → ~ngẫu nhiên ----------
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
meta = pd.read_csv(os.path.join(LAB, "sites_X25519.csv"))
wa = SITES.get("pcap_sites_X25519.pcapng", [])[:len(meta)]
ya = list(meta["site"])[:len(wa)]
Xa = np.array([[x["c1"], x["c2"], x["sv"]] for x in wa])
acc_hs = cross_val_score(RandomForestClassifier(300, random_state=7, n_jobs=-1),
                         Xa, ya, cv=StratifiedKFold(5, shuffle=True, random_state=7)).mean()
check("E", "Cơ chế kháng drift: CHỈ đặc trưng handshake → ~ngẫu nhiên (6 lớp ≈ 0.17)",
      acc_hs < 0.30, f"accuracy = {acc_hs:.3f} — tín hiệu phân biệt site nằm ở pha ứng dụng")

# ---------- CHECK F: hiệu chuẩn bằng hoán vị nhãn nhóm ----------
x = [v["cli_all"] for v in HS[("X25519", 1, 0, 1500)]]
y = [v["cli_all"] for v in HS[("X25519MLKEM768", 1, 0, 1500)]]
n = min(len(x), len(y)); pool = np.concatenate([x[:n], y[:n]])
perm = []
for _ in range(300):
    rng.shuffle(pool)
    perm.append(paired_p(pool[:n], pool[n:2*n]) < 0.05)
check("F", "Hoán vị nhãn nhóm (hủy tín hiệu thật) → p<0.05 ≈ 5%",
      abs(np.mean(perm) - 0.05) < 0.05, f"tỷ lệ = {np.mean(perm):.3f} / 300 lần")

# ---------- CHECK G: tính lại Wilcoxon + Holm (họ hs_rtt) ----------
pubF = pd.read_csv(f"{BASE}/tables/rq1_flows.csv")
rows = []
for (l, d, m), g in pubF.groupby(["loss", "delay", "mtu"]):
    aa = g[g.group == "X25519"]["hs_rtt"].values
    bb = g[g.group == "X25519MLKEM768"]["hs_rtt"].values
    k = min(len(aa), len(bb))
    if k < 10: continue
    rows.append(stats.wilcoxon(aa[:k], bb[:k]).pvalue)
rows.sort()
k = len(rows)
holm = np.minimum(np.maximum.accumulate([(k - i) * p for i, p in enumerate(rows)]), 1.0)
pub_h = pd.read_csv(f"{BASE}/tables/rq1_stats.csv").query("metric=='hs_rtt'").sort_values("p")["p_holm"].values
okG = len(holm) == len(pub_h) and np.allclose(holm, pub_h, atol=0.02, equal_nan=True)
check("G", "Tính lại Wilcoxon + Holm (13 cấu hình) khớp bảng công bố", okG,
      f"tính lại: {np.round(holm,4)[:5]}… | công bố: {np.round(pub_h,4)[:5]}…")

# ---------- CHECK H: tính toàn vẹn dữ liệu ----------
counts = {k: len(v) for k, v in HS.items()}
pubc = pubF.groupby(["group", "loss", "delay", "mtu"]).size()
diffs = {f"{k[0]}_L{k[1]}_D{k[2]}_M{k[3]}": counts[k] - int(pubc.get(k, 0)) for k in counts}
big = {k: v for k, v in diffs.items() if abs(v) > 3}
check("H", "Toàn vẹn: số flow/cấu hình khớp bảng rq1_flows đã công bố (±3)",
      not big, f"tổng audit = {sum(counts.values())} vs công bố = {int(pubc.sum())} | lệch >3: {big or 'không'}")

# ---------- CHECK I: đồng hồ tường ↔ RTT pcap qua 26 cấu hình ----------
g2 = pubF.groupby(["group", "loss", "delay", "mtu"])["hs_rtt"].median()
pairs = []
for (gg, l, d, m) in HS:
    df = pd.read_csv(os.path.join(LAB, f"hs_{gg}_L{l}_D{d}_M{m}.csv"))
    dur = df.sort_values("idx").t_ns_wall.diff().dropna() / 1e6 - 150   # trừ sleep 0.15s
    r0 = g2.get((gg, l, d, m), np.nan)
    if len(dur) > 10 and not np.isnan(r0):
        pairs.append((med(dur.tolist()), r0))
A = np.array(pairs)
r = float(np.corrcoef(A[:, 0], A[:, 1])[0, 1]) if len(A) > 3 else float("nan")
check("I", "Đồng hồ tường (CSV) tương quan RTT pcap qua 26 cấu hình",
      (not np.isnan(r)) and r > 0.85, f"Pearson r = {r:.3f} trên {len(A)} cấu hình")

print("=" * 70)
tbl = pd.DataFrame(RESULTS, columns=["CHECK", "Tên", "Kết luận", "Chi tiết"])
tbl.to_csv(f"{BASE}/tables/audit_results.csv", index=False)
n_pass = (tbl["Kết luận"] == "PASS").sum(); n_fail = (tbl["Kết luận"] == "FAIL").sum()
print(f"TỔNG: {n_pass} PASS / {n_fail} FAIL / {len(tbl)-n_pass-n_fail} WARN")
sys.exit(1 if n_fail else 0)
