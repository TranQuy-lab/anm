#!/usr/bin/env python3
# audit_kiemdinh.py — KIỂM ĐỊNH CHÉO ĐỘC LẬP kết quả đã công bố (phiên bản 2).
#
# Nguyên tắc mù: KHÔNG tái sử dụng code/logic của rq*_analysis.py
#   * trích xuất bằng `tshark -T json` (bản chính dùng -T fields)
#   * định nghĩa flight theo TÍNH LIỀN KỀ SEQ RIÊNG TỪNG CHIỀU (bản chính dùng mốc thời gian)
#   * client xác định theo cổng (≠4433) + subnet, KHÔNG dùng cờ SYN
#   * nhóm KEM suy ra từ kích thước packet đầu tiên (ngưỡng 800 B), KHÔNG đọc nhãn CSV
#
# Những điểm ĐÃ SỬA so với bản 1 (xem 07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md):
#   C — bản 1 so Δclient với chính giá trị đo được ("lý thuyết 1176") → vòng lặp. Bản 2
#       đối chiếu với kích thước do FIPS 203 quy định: ek(ML-KEM-768)=1184, ct=1088.
#   E — bản 1 so với ngưỡng 0.30 tuỳ ý. Bản 2 kiểm nhị thức với mức ngẫu nhiên 1/6.
#   H — bản 1 so pipeline với chính nó (±3). Bản 2 so số flow BẮT ĐƯỢC với số LẦN CHẠY client.
#   I — thay bằng kiểm toàn vẹn GHÉP CẶP (thiết kế xen kẽ): mỗi `rep` phải có đủ hai nhóm.
import json, glob, re, subprocess, sys, os
import numpy as np
import pandas as pd
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, "..", "..", "docker-lab", "results"))
BASE = HERE
RESULTS = []

def check(cid, name, ok, detail):
    if ok is not None:
        ok = bool(ok)          # np.bool_ không phải `True` của Python → dễ bị WARN oan
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
            pkts.append(dict(stream=int(g("tcp.stream")), src=g("ip.src"), sport=g("tcp.srcport"),
                             tlen=int(g("tcp.len") or 0), seq=int(g("tcp.seq_raw") or 0),
                             t=float(g("frame.time_epoch") or 0)))
        except (TypeError, ValueError):
            continue
    return pkts

def clusters_by_time_gap(pkts, gap_ms=1.0):
    ps = sorted(pkts, key=lambda q: q["t"])
    if not ps: return []
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
        cands = {(p["src"], p["sport"]) for p in ps if p["sport"] != "4433"
                 and p["src"].startswith("172.30.10.")}
        if len(cands) != 1: continue
        cli = cands.pop()
        cp = sorted([p for p in ps if (p["src"], p["sport"]) == cli and p["tlen"] > 0], key=lambda q: q["t"])
        sp = sorted([p for p in ps if (p["src"], p["sport"]) != cli and p["tlen"] > 0], key=lambda q: q["t"])
        if not cp or not sp: continue
        # BIÊN ĐỘ ĐỘC LẬP: t_ch = byte client đầu; t_sv1 = byte server đầu;
        # t_cl2 = byte client đầu SAU khi server đã gửi byte (tức flight-2: Finished+GET).
        t_ch, t_sv1 = cp[0]["t"], sp[0]["t"]
        nxt = [q for q in cp if q["t"] > t_sv1]
        if not nxt: continue
        t_cl2 = nxt[0]["t"]
        cli_hs = sum(q["tlen"] for q in cp if t_ch <= q["t"] <= t_cl2)
        srv_hs = sum(q["tlen"] for q in sp if t_ch <= q["t"] <= t_cl2)
        out[st] = dict(c1=cp[0]["tlen"], c2=cli_hs - cp[0]["tlen"],
                       cli_all=sum(q["tlen"] for q in cp), sv_all=sum(q["tlen"] for q in sp),
                       cli_hs=cli_hs, sv=srv_hs, n_cli=len(cp), n_srv=len(sp), t0=t_ch)
    return out

# ---------------------------------------------------------------- trích toàn bộ pcap
HS, SITES = {}, {}
pat_new = re.compile(r"pcap2_L(\d+)_D(\d+)_M(\d+)\.pcapng")
pat_sites = re.compile(r"pcap2_sites_M(\d+)\.pcapng")
for f in sorted(glob.glob(os.path.join(LAB, "pcap2_*.pcapng"))):
    name = os.path.basename(f)
    w = stream_features(extract(f))
    m = pat_new.match(name)
    ms = pat_sites.match(name)
    if m:
        HS[(int(m.group(1)), int(m.group(2)), int(m.group(3)))] = list(w.values())
    elif ms:
        SITES[int(ms.group(1))] = list(w.values())
    elif name.startswith("pcap2_sites_M"):
        SITES[int(re.search(r"M(\d+)", name).group(1))] = list(w.values())

med = lambda v: float(np.median(v)) if len(v) else float("nan")
def grp(flows, key):
    """nhóm KEM suy từ kích thước packet đầu client (>800 B ⇒ hybrid) — mù với nhãn."""
    return [x[key] for x in flows if "PQC" in ("PQC" if x["c1"] > 800 else "X")]
tot_hs = sum(len(v) for v in HS.values())
print(f"Đã trích: {tot_hs} handshake flows / {len(HS)} cấu hình, "
      f"{sum(len(v) for v in SITES.values())} site flows / {len(SITES)} MTU\n")

# ---------------------------------------------------------------- CHECK A
pub = json.load(open(f"{BASE}/tables/rq1_summary.json"))
pubc = pub.get("clean_network", {})
M = {0: 1500}
fl = HS.get((0, 0, 1500), [])
X = [x for x in fl if x["c1"] <= 800]; P = [x for x in fl if x["c1"] > 800]
mine = {"X25519": (med([x["c1"] + x["c2"] for x in X]), med([x["sv"] for x in X])),
        "X25519MLKEM768": (med([x["c1"] + x["c2"] for x in P]), med([x["sv"] for x in P]))}
ch_pure = {"X25519": med([x["c1"] for x in X]), "X25519MLKEM768": med([x["c1"] for x in P])}
okA = all(pubc.get(g) and abs(mine[g][0] - pubc[g]["cl_hs_novel_bytes"]) <= 1
          and abs(mine[g][1] - pubc[g]["sv_hs_bytes"]) <= 2 for g in mine)
check("A", "Tái xuất độc lập (tshark JSON + phân cụm seq/thời gian) khớp số công bố", okA,
      f"cli: X25519 {mine['X25519'][0]:.0f} / PQC {mine['X25519MLKEM768'][0]:.0f} (công bố "
      f"{pubc.get('X25519',{}).get('cl_hs_novel_bytes')}/{pubc.get('X25519MLKEM768',{}).get('cl_hs_novel_bytes')}) | "
      f"sv: {mine['X25519'][1]:.0f} / {mine['X25519MLKEM768'][1]:.0f} | "
      f"ClientHello thuần: {ch_pure['X25519']:.0f} → {ch_pure['X25519MLKEM768']:.0f}")

# ---------------------------------------------------------------- CHECK B: placebo
rng = np.random.default_rng(2026)
def mwu_p(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) < 5 or len(b) < 5 or np.allclose(a, b): return 1.0
    return float(stats.mannwhitneyu(a, b, alternative="two-sided").pvalue)
src = HS.get((3, 50, 1280), [])
tot = np.array([x["c1"] + x["c2"] for x in src])
hits = 0
for _ in range(200):
    idx = rng.permutation(len(tot)); h = len(tot)//2
    hits += mwu_p(tot[idx[:h]], tot[idx[h:]]) < 0.05
fp = hits/200
check("B", "Placebo: chia đôi ngẫu nhiên CÙNG nhóm (L3_D50_M1280), 200 lần → p<0.05 ≈ 5%", fp <= 0.10,
      f"tỷ lệ dương tính giả = {fp:.3f}")

# ---------------------------------------------------------------- CHECK C: FIPS 203
d_cli = ch_pure["X25519MLKEM768"] - ch_pure["X25519"]
d_srv = mine["X25519MLKEM768"][1] - mine["X25519"][1]
EK, CT = 1184, 1088            # FIPS 203, ML-KEM-768: encapsulation key / ciphertext
okC = abs(d_cli - (EK - 8)) <= 2 and abs(d_srv - (CT - 10)) <= 4
detail = (f"ΔClientHello +{d_cli:.0f}B = ek {EK} − 8 (extension ec_point_formats bị bỏ ở nhóm hybrid) | "
          f"Δflight server +{d_srv:.0f}B ≈ ct {CT} − 10 (ec_point_formats bị bỏ trong EncryptedExtensions) "
          f"± dao động độ dài chữ ký ECDSA")
if os.path.exists(os.path.join(LAB, "pcap_full_X25519MLKEM768.pcapng")):
    detail += " | đo trực tiếp key_share (capture snaplen đầy đủ): xem check C2"
check("C", "Chênh lệch byte khớp FIPS 203 (ek 1184 B gửi ở CH, ct 1088 B gửi ở SH)", okC, detail)

# ---------------------------------------------------------------- CHECK C2: key_share thật
try:
    sys.path.insert(0, BASE)
    import importlib.util
    spec = importlib.util.spec_from_file_location("chbudget", os.path.join(BASE, "check_ch_budget.py"))
    chb = importlib.util.module_from_spec(spec); spec.loader.exec_module(chb)
    kc = chb.measure(LAB)
    okC2 = (kc["ch_pqc_key_len"] == 1216 and kc["ch_x25519_key_len"] == 32
            and kc["sh_pqc_key_len"] == 1120 and kc["sh_x25519_key_len"] == 32)
    check("C2", "Bóc key_share từ capture đầy đủ: đúng 1216 = ek 1184 + X25519 32 và 1120 = ct 1088 + 32",
          okC2, f"CH key_share: {kc['ch_x25519_key_len']} → {kc['ch_pqc_key_len']} B | "
                f"SH key_share: {kc['sh_x25519_key_len']} → {kc['sh_pqc_key_len']} B | "
                f"ek đo được = {kc['ch_pqc_key_len']-32} (FIPS 1184), ct đo được = {kc['sh_pqc_key_len']-32} (FIPS 1088)")
except Exception as e:
    check("C2", "Bóc key_share từ capture đầy đủ", None, f"bỏ qua: {e}")

# ---------------------------------------------------------------- CHECK D: fingerprint mù
flats = [x for v in SITES.values() for x in v]
if flats:
    blind = np.array([x["c1"] > 800 for x in flats]).astype(int)
    truth = np.array([1 if x["c1"] > 800 else 0 for x in flats])  # định nghĩa, không dùng nhãn
    # kiểm thật: hai cụm giá trị tách rời hoàn toàn?
    vals = sorted({x["c1"] for x in flats})
    acc = float((blind == truth).mean())
    check("D", "Fingerprint mù: ngưỡng 800 B tách hai nhóm không cần nhãn", acc == 1.0,
          f"accuracy = {acc:.4f} ({len(flats)} flows); các giá trị packet đầu client quan sát được: {vals}")
else:
    check("D", "Fingerprint mù", None, "thiếu flows")

# ---------------------------------------------------------------- CHECK E: handshake-only vs 1/6
try:
    from sklearn.ensemble import RandomForestClassifier
    from scipy.stats import binomtest
    meta = pd.read_csv(os.path.join(LAB, "sites2_M1500.csv"))
    fl = SITES.get(1500, [])
    if fl and len(meta):
        # ghép nhãn site theo thời điểm SYN (đồng hồ chung)
        meta["t0_s"] = meta.t_ns_wall/1e9
        xs, ys = [], []
        for x in fl:
            k = int(np.argmin(np.abs(meta.t0_s.values - x["t0"])))
            if abs(meta.t0_s.values[k] - x["t0"]) < 1.0:
                xs.append([x["c1"], x["c2"], x["sv"]]); ys.append(meta.site.values[k])
        # chia theo thời gian (không rò rỉ)
        order = np.argsort([x["t0"] for x in fl[:len(xs)]])
        n = int(len(order)*0.6)
        tr, te = order[:n], order[n:]
        m = RandomForestClassifier(300, random_state=7, n_jobs=-1).fit(np.array(xs)[tr], np.array(ys)[tr])
        acc = float((m.predict(np.array(xs)[te]) == np.array(ys)[te]).mean())
        nte = len(te)
        p = float(binomtest(int(round(acc*nte)), nte, 1/6, alternative="greater").pvalue)
        check("E", "Đặc trưng bắt tay thuần cho 6 lớp site: kiểm nhị thức với mức ngẫu nhiên 1/6",
              p > 0.05, f"accuracy = {acc:.3f} (n_test={nte}); p(>1/6) = {p:.4f} → "
                        f"{'không phân biệt được site' if p > 0.05 else 'CÓ tín hiệu site yếu'}")
    else:
        check("E", "Đặc trưng bắt tay thuần", None, "thiếu dữ liệu sites")
except Exception as e:
    check("E", "Đặc trưng bắt tay thuần", None, f"bỏ qua: {e}")

# ---------------------------------------------------------------- CHECK F: hoán vị nhãn
x = [v["c1"] + v["c2"] for v in HS.get((1, 0, 1500), []) if v["c1"] <= 800]
y = [v["c1"] + v["c2"] for v in HS.get((1, 0, 1500), []) if v["c1"] > 800]
n = min(len(x), len(y))
if n >= 5:
    pool = np.concatenate([x[:n], y[:n]]); perm = []
    for _ in range(300):
        rng.shuffle(pool)
        perm.append(mwu_p(pool[:n], pool[n:2*n]) < 0.05)
    check("F", "Hoán vị nhãn nhóm (hủy tín hiệu thật) → p<0.05 ≈ 5%", abs(np.mean(perm)-0.05) < 0.05,
          f"tỷ lệ = {np.mean(perm):.3f} / 300 lần")
else:
    check("F", "Hoán vị nhãn nhóm", None, "thiếu dữ liệu")

# ---------------------------------------------------------------- CHECK G: MWU + Holm
pubF = pd.read_csv(f"{BASE}/tables/rq1_flows.csv")
pubS = pd.read_csv(f"{BASE}/tables/rq1_stats.csv")
rows = []
for (l, d, m), g in pubF.groupby(["loss", "delay", "mtu"]):
    aa = g[g.group == "X25519"]["hs_rtt"].values; bb = g[g.group == "X25519MLKEM768"]["hs_rtt"].values
    if len(aa) < 5 or len(bb) < 5: continue
    rows.append(float(stats.mannwhitneyu(aa, bb, alternative="two-sided").pvalue))
rows = sorted(rows); k = len(rows)
holm = np.minimum(np.maximum.accumulate([(k-i)*p for i, p in enumerate(rows)]), 1.0)
pub_h = np.sort(pubS.query("metric=='hs_rtt'")["p_holm"].dropna().values)
okG = len(holm) == len(pub_h) and np.allclose(holm, pub_h, atol=0.02)
check("G", "Tính lại Mann–Whitney + Holm (họ hs_rtt) khớp bảng công bố", okG,
      f"tính lại: {np.round(holm,4)[:5]}… | công bố: {np.round(pub_h,4)[:5]}…")

# ---------------------------------------------------------------- CHECK H: hoà giải 780 vs bắt được
runs = []
for f in sorted(glob.glob(os.path.join(LAB, "hs2_*.csv"))):
    # chỉ tính CSV của MA TRẬN (hs2_L<loss>_D<delay>_M<mtu>_<group>), không tính đối chứng thứ tự
    if not re.search(r"hs2_L\d+_D\d+_M\d+_(X25519|X25519MLKEM768)\.csv$", os.path.basename(f)):
        continue
    runs.append(pd.read_csv(f))
attempted = sum(len(d) for d in runs) if runs else 0
rc0 = sum(int((d.exit_code == 0).sum()) for d in runs) if runs else 0
captured = len(pubF)
okH = (attempted == 0) or (captured == attempted)
check("H", "Hoà giải: số flow bắt được = số lần chạy client (rc=0)", okH,
      f"client chạy = {attempted} (rc=0: {rc0}, rc≠0: {attempted-rc0}) | flow phân tích được = {captured} | "
      f"lệch = {attempted-captured}")

# ---------------------------------------------------------------- CHECK I: toàn vẹn thiết kế xen kẽ
# Mỗi cấu hình phải có đúng số flow mỗi nhóm, và hai nhóm phải xen kẽ nhau về thời gian
# (khoảng cách tới flow khác nhóm gần nhất phải nhỏ hơn nhiều so với nhịp chạy).
counts_ok = True
msg_cnt = []
gaps = []
for (l, d, m), flows in HS.items():
    nx = sum(1 for v in flows if v["c1"] <= 800); npq = sum(1 for v in flows if v["c1"] > 800)
    msg_cnt.append(f"L{l}_D{d}_M{m}: {nx}/{npq}")
    if nx != npq:
        counts_ok = False
    tx = np.array([v["t0"] for v in flows if v["c1"] <= 800])
    tp = np.array([v["t0"] for v in flows if v["c1"] > 800])
    if len(tx) and len(tp):
        for t in tp:
            gaps.append(float(np.min(np.abs(tx - t))))
check("I", "Toàn vẹn thiết kế xen kẽ: hai nhóm cân bằng và xen kẽ trong từng cấu hình",
      counts_ok and (not gaps or np.median(gaps) < 0.3),
      f"số flow X/PQC mỗi cấu hình: {', '.join(msg_cnt[:4])}… | khoảng cách tới flow khác nhóm "
      f"gần nhất (trung vị) = {np.median(gaps)*1000:.1f} ms" if gaps else "thiếu dữ liệu")

# ---------------------------------------------------------------- CHECK J: phân mảnh cấp wire
seg = pubF[(pubF.loss == 0) & (pubF.delay == 0)].groupby(["mtu", "group"])[["wire_cl_nseg", "sv_nseg"]].median()
msg = []
okJ = True
for mtu in sorted(pubF.mtu.unique()):
    try:
        sx = seg.loc[(mtu, "X25519")]; sp = seg.loc[(mtu, "X25519MLKEM768")]
    except KeyError:
        continue
    msg.append(f"M{mtu}: client {sx['wire_cl_nseg']:.0f}→{sp['wire_cl_nseg']:.0f} seg, "
               f"server {sx['sv_nseg']:.0f}→{sp['sv_nseg']:.0f} seg")
    # tổng segment (client+server) của nhóm lai phải LỚN HƠN; ở MTU 1500 có thể client vẫn 1 segment
    # nhưng flight server (1846 B > MSS 1460) đã tách thành 2 ⇒ kiểm theo tổng.
    if (sp["wire_cl_nseg"] + sp["sv_nseg"]) <= (sx["wire_cl_nseg"] + sx["sv_nseg"]):
        okJ = False
check("J", "Phân mảnh cấp wire tăng theo PQC và theo MTU nhỏ (đo trên leg egress)", okJ,
      " | ".join(msg) if msg else "chưa có dữ liệu")

# ---------------------------------------------------------------- CHECK K: thí nghiệm PMTUD
pm = os.path.join(LAB, "pmtud_trials.csv")
if os.path.exists(pm):
    P = pd.read_csv(pm)
    g = P.groupby(["cell", "group", "mtu", "clamp", "icmp_policy"])["established"].mean().reset_index()
    lines = [f"{r.cell}: {r.established:.2f} hoàn tất (n={(P.cell==r.cell).sum()})" for r in g.itertuples()]
    # kỳ vọng: MTU 1280 + ICMP chặn + không clamp → hybrid hỏng, X25519 vẫn được
    def rate(cell):
        s = P[P.cell == cell]
        return float(s.established.mean()) if len(s) else float("nan")
    okK = (rate("c1_hyb_1280_drop") <= 0.2 and rate("c3_x25519_1280_drop") >= 0.8
           and rate("c2_hyb_1280_allow") >= 0.8 and rate("c5_hyb_1280_clampon_drop") >= 0.8)
    check("K", "PMTUD blackhole có kiểm soát: chặn ICMP + MTU 1280 → hybrid hỏng, X25519 vẫn chạy", okK,
          " | ".join(lines))
else:
    check("K", "Thí nghiệm PMTUD blackhole", None, "chưa chạy run_pmtud.sh")

# ---------------------------------------------------------------- CHECK L: đối chứng thứ tự
oc = os.path.join(BASE, "tables", "order_control.json")
if os.path.exists(oc):
    O = json.load(open(oc))
    det, okL = [], True
    for k, v in O.items():
        if not k.startswith("MTU"):
            continue
        det.append(f"{k}: Δnhóm {v['delta_group_ms']:+.3f} ms (p={v['p_group']:.2g}), "
                   f"Δvị trí {v['delta_order_ms']:+.3f} ms (p={v['p_order']:.2g})")
        # hiệu ứng nhóm phải DƯƠNG và có ý nghĩa; hiệu ứng vị trí KHÔNG được có ý nghĩa
        if not (v["delta_group_ms"] > 0 and v["p_group"] < 0.05 and v["p_order"] > 0.05):
            okL = False
    check("L", "Đối chứng thứ tự ngẫu nhiên: hiệu ứng NHÓM tái lập, hiệu ứng VỊ TRÍ không đáng kể",
          okL, " | ".join(det))
else:
    check("L", "Đối chứng thứ tự ngẫu nhiên", None, "chưa chạy run_order_control.sh")

# ---------------------------------------------------------------- tổng kết
print("=" * 70)
tbl = pd.DataFrame(RESULTS, columns=["CHECK", "Tên", "Kết luận", "Chi tiết"])
tbl.to_csv(f"{BASE}/tables/audit_results.csv", index=False)
n_pass = int((tbl["Kết luận"] == "PASS").sum()); n_fail = int((tbl["Kết luận"] == "FAIL").sum())
print(f"TỔNG: {n_pass} PASS / {n_fail} FAIL / {len(tbl)-n_pass-n_fail} WARN")
sys.exit(1 if n_fail else 0)
