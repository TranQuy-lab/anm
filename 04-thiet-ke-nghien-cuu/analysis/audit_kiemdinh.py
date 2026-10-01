#!/usr/bin/env python3
# audit_kiemdinh.py — KIỂM ĐỊNH CHÉO ĐỘC LẬP kết quả đã công bố (phiên bản 2).
#
# Nguyên tắc mù: KHÔNG tái sử dụng code/logic của rq*_analysis.py
#   * trích xuất bằng `tshark -T json` (bản chính dùng -T fields)
#   * định nghĩa flight theo BIÊN THỜI GIAN tường minh (t_ch → t_sv1 → t_cl2) trên từng chiều,
#     thay vì dùng cửa sổ sự kiện của bản chính
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
         "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport",
         "-e", "tcp.len", "-e", "tcp.seq_raw", "-e", "frame.time_epoch"],
        capture_output=True, text=True).stdout
    pkts = []
    for line in json.loads(out or "[]"):
        l = line["_source"]["layers"]
        def g(k):
            v = l.get(k)
            return v[0] if isinstance(v, list) else v
        try:
            pkts.append(dict(stream=int(g("tcp.stream")), src=g("ip.src"), dst=g("ip.dst"), sport=g("tcp.srcport"),
                             tlen=int(g("tcp.len") or 0), seq=int(g("tcp.seq_raw") or 0),
                             t=float(g("frame.time_epoch") or 0)))
        except (TypeError, ValueError):
            continue
    return pkts

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
# n=0 thì KHÔNG được PASS (bản trước trả 0.000 và PASS trên dữ liệu rỗng)
check("B", "Placebo: chia đôi ngẫu nhiên (trộn hai nhóm, L3_D50_M1280), 200 lần → p<0.05 ≈ 5%",
      (fp <= 0.10) if len(tot) >= 20 else None,
      (f"tỷ lệ dương tính giả = {fp:.3f} (n={len(tot)} flow)" if len(tot) else "KHÔNG có dữ liệu — không kết luận"))

# ---------------------------------------------------------------- CHECK C: FIPS 203
d_cli = ch_pure["X25519MLKEM768"] - ch_pure["X25519"]
d_srv = mine["X25519MLKEM768"][1] - mine["X25519"][1]
EK, CT = 1184, 1088            # FIPS 203, ML-KEM-768: encapsulation key / ciphertext
okC = abs(d_cli - (EK - 8)) <= 2 and abs(d_srv - (CT - 10)) <= 4
detail = (f"ΔClientHello +{d_cli:.0f}B = ek {EK} − 8 (extension ec_point_formats bị bỏ ở nhóm hybrid) | "
          f"Δflight server +{d_srv:.0f}B ≈ ct {CT} − 10 (supported_groups bị bỏ trong EncryptedExtensions) "
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

# ---------------------------------------------------------------- CHECK C3: giải mã EncryptedExtensions
# Phần −10 B của Δflight server được gán cho việc nhóm lai BỎ extension supported_groups (type 10)
# trong EncryptedExtensions. Kiểm chứng độc lập: giải mã bằng keylog, so độ dài EE **và đọc tên
# extension** để chắc chắn tên được nêu trong báo cáo là đúng.
def ee_len(pcap, keylog):
    """Độ dài EncryptedExtensions. Một frame có thể chứa NHIỀU handshake message nên phải
    căn theo chỉ số: tìm vị trí type==8 trong danh sách type rồi lấy length cùng chỉ số."""
    out = subprocess.run(["tshark", "-r", pcap, "-o", f"tls.keylog_file:{keylog}",
                          "-Y", "tls.handshake.type==8", "-T", "fields",
                          "-e", "tls.handshake.type", "-e", "tls.handshake.length"],
                         capture_output=True, text=True).stdout.strip().split("\n")
    for line in out:
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        types = [t.strip() for t in parts[0].split(",")]
        lens = [l.strip() for l in parts[1].split(",")]
        if "8" in types:
            i = types.index("8")
            if i < len(lens) and lens[i]:
                return int(lens[i])
    return None

def ee_ext_names(pcap, keylog):
    """Tên các extension trong EncryptedExtensions (để kiểm chứng TÊN mà báo cáo nêu ra).
    Một frame có thể chứa cả ServerHello lẫn EE nên phải cắt phần sau 'Encrypted Extensions'."""
    out = subprocess.run(["tshark", "-r", pcap, "-o", f"tls.keylog_file:{keylog}",
                          "-Y", "tls.handshake.type==8", "-V"],
                         capture_output=True, text=True).stdout
    if "Encrypted Extensions" not in out:
        return None
    tail = out.split("Encrypted Extensions", 1)[1]
    names = []
    for line in tail.splitlines():
        st = line.strip()
        if st.startswith("Handshake Protocol:") and "Encrypted Extensions" not in st:
            break
        if st.startswith("Extension: "):
            names.append(st.split("Extension: ", 1)[1].split(" ", 1)[0])
    return names

try:
    ee = {}
    for G in ("X25519", "X25519MLKEM768"):
        pc = os.path.join(LAB, f"pcap_full_{G}.pcapng")
        kl = os.path.join(LAB, f"keys_{G}.log")
        if not (os.path.exists(pc) and os.path.exists(kl)):
            raise FileNotFoundError(pc if not os.path.exists(pc) else kl)
        ee[G] = ee_len(pc, kl)
    names = {G: ee_ext_names(os.path.join(LAB, f"pcap_full_{G}.pcapng"), os.path.join(LAB, f"keys_{G}.log"))
             for G in ("X25519", "X25519MLKEM768")}
    okC3 = (ee.get("X25519") is not None and ee.get("X25519MLKEM768") is not None
            and ee["X25519"] - ee["X25519MLKEM768"] == 10
            and names["X25519"] == ["supported_groups"] and names["X25519MLKEM768"] == [])
    check("C3", "Giải mã EE bằng keylog: nhóm lai bỏ supported_groups ⇒ EE ngắn hơn đúng 10 B",
          okC3, f"EncryptedExtensions: X25519 {ee.get('X25519')} B chứa {names['X25519']} → "
                f"PQC {ee.get('X25519MLKEM768')} B chứa {names['X25519MLKEM768']} "
                f"(chênh {None if None in ee.values() else ee['X25519']-ee['X25519MLKEM768']} B)")
except Exception as e:
    check("C3", "Giải mã EncryptedExtensions bằng keylog", None, f"bỏ qua: {e}")

# ---------------------------------------------------------------- CHECK D: fingerprint mù (THẬT)
# Bản v1 của check này tự quy chiếu: "sự thật" được định nghĩa bằng chính ngưỡng đang kiểm
# (truth = c1 > 800) nên accuracy luôn = 1,0 và không bao giờ FAIL. Bản này kiểm ĐÚNG cách:
# luật ngưỡng 800 B (rút từ MTU 1500, không dùng nhãn) được đối chiếu với NHÃN NHÓM ĐỘC LẬP
# đọc từ CSV lần chạy (sites2_M1500.csv) — nhãn này do client tự khai khi chạy, không suy từ pcap.
d_ok, d_msg = None, "thiếu dữ liệu"
fl1500 = SITES.get(1500, [])
csv_sites = os.path.join(LAB, "sites2_M1500.csv")
if fl1500 and os.path.exists(csv_sites):
    meta = pd.read_csv(csv_sites); meta["t0_s"] = meta["t_ns_wall"] / 1e9
    pred, true = [], []
    for x in fl1500:
        k = int(np.argmin(np.abs(meta["t0_s"].values - x["t0"])))
        if abs(meta["t0_s"].values[k] - x["t0"]) > 1.0:
            continue
        pred.append(1 if x["c1"] > 800 else 0)
        true.append(1 if meta["group"].values[k] == "X25519MLKEM768" else 0)
    if pred:
        acc = float((np.array(pred) == np.array(true)).mean())
        # min-n được kiểm ở điều kiện d_ok bên dưới (không cho PASS trên vài dòng khớp được)
        vals = sorted({x["c1"] for x in fl1500})
        d_ok = (acc == 1.0) and (len(vals) == 2) and len(pred) >= 100
        d_msg = (f"accuracy = {acc:.4f} trên {len(pred)} flow (nhãn lấy từ CSV lần chạy, KHÔNG suy từ pcap) | "
                 f"packet đầu client chỉ nhận hai giá trị: {vals}")
check("D", "Fingerprint mù: luật ngưỡng 800 B đối chiếu với nhãn nhóm ĐỘC LẬP", d_ok, d_msg)

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
rc_bad = attempted - rc0
captured = len(pubF)
# KHÔNG được PASS khi thiếu dữ liệu (bản v1: attempted == 0 vẫn PASS), và mã thoát khác 0
# phải làm FAIL — bản v1 tính rc0 nhưng không dùng.
if attempted == 0:
    okH = None
elif rc_bad > 0:
    okH = False
else:
    okH = (captured == attempted)
check("H", "Hoà giải: số flow bắt được = số lần chạy client, mọi lần đều rc=0", okH,
      f"client chạy = {attempted} (rc=0: {rc0}, rc≠0: {rc_bad}) | flow phân tích được = {captured} | "
      f"lệch = {attempted-captured}")

# ---------------------------------------------------------------- CHECK I: toàn vẹn thiết kế xen kẽ
# Tiêu chí THEO TỪNG CẤU HÌNH (không dùng trung vị gộp — trung vị gộp bị lệch bởi thành phần
# delay-0/delay-50 và có thể PASS/FAIL tuỳ dữ liệu bị thiếu), cộng kiểm tra exit_code của client.
EXPECTED_CFG = {(l, d, m) for l in (0, 1, 3) for d in (0, 50) for m in (1500, 1280)} | {(0, 0, 576)}
runs_rc = {}
for f in sorted(glob.glob(os.path.join(LAB, "hs2_*.csv"))):
    mm = re.search(r"hs2_L(\d+)_D(\d+)_M(\d+)_(X25519|X25519MLKEM768)\.csv$", os.path.basename(f))
    if mm:
        d0 = pd.read_csv(f)
        runs_rc[(int(mm.group(1)), int(mm.group(2)), int(mm.group(3)))] = \
            runs_rc.get((int(mm.group(1)), int(mm.group(2)), int(mm.group(3))), 0) + int((d0.exit_code != 0).sum())
cfg_bad, gap_bad, rc_bad_cfg = [], [], []
gap_txt = []
for (l, d, m), flows in HS.items():
    nx = sum(1 for v in flows if v["c1"] <= 800); npq = sum(1 for v in flows if v["c1"] > 800)
    if nx != npq:
        cfg_bad.append(f"L{l}_D{d}_M{m}({nx}/{npq})")
    if runs_rc.get((l, d, m), 0) > 0:
        rc_bad_cfg.append(f"L{l}_D{d}_M{m}")
    tx = np.array([v["t0"] for v in flows if v["c1"] <= 800])
    tp = np.array([v["t0"] for v in flows if v["c1"] > 800])
    if len(tx) and len(tp):
        gg = float(np.median([np.min(np.abs(tx - t)) for t in tp]))
        gap_txt.append(f"L{l}_D{d}_M{m}={gg*1000:.0f}ms")
        # ngưỡng theo từng cấu hình: delay 50 ms làm khoảng cách cặp tăng ~0,2 s
        if gg > (0.3 if d == 0 else 1.0):
            gap_bad.append(f"L{l}_D{d}_M{m}({gg*1000:.0f}ms)")
missing_cfg = sorted(EXPECTED_CFG - set(HS.keys()))
okI = None
if HS:
    okI = (not cfg_bad) and (not gap_bad) and (not rc_bad_cfg) and (not missing_cfg)
check("I", "Toàn vẹn thiết kế xen kẽ THEO TỪNG CẤU HÌNH: đủ 13 cấu hình, hai nhóm cân bằng, mọi lần chạy rc=0, xen kẽ",
      okI,
      f"thiếu cấu hình: {missing_cfg or 'không'} | lệch số flow: {cfg_bad or 'không'} | "
      f"cấu hình có rc≠0: {rc_bad_cfg or 'không'} | khoảng cách cặp vượt ngưỡng: {gap_bad or 'không'} | "
      f"khoảng cách cặp (trung vị mỗi cấu hình): {', '.join(gap_txt[:5])}…")

# ---------------------------------------------------------------- CHECK J: phân mảnh cấp wire
# Bản v1 đọc thẳng bảng công bố (tables/rq1_flows.csv) → không độc lập. Bản này tính LẠI từ pcap:
# trên leg egress (router→server), đếm số segment của flight ClientHello và của flight server,
# đồng thời kiểm kích thước gói lớn nhất ≤ MTU − 52 (chứng minh MTU có hiệu lực thật).
def wire_segments(pcap):
    """Phân mảnh CẤP WIRE, tính lại từ pcap, chỉ dùng các leg EGRESS của router:
      - flight CLIENT: leg post-NAT (router 172.30.20.x -> server 172.30.20.y)
      - flight SERVER: leg pre-NAT  (router 172.30.10.2 -> client 172.30.10.3)
    Hai leg của cùng một kết nối được GHÉP theo mốc SYN (< 20 ms), như trong rq1_analysis.py."""
    by = {}
    for p in extract(pcap): by.setdefault(p["stream"], []).append(p)
    legs = []
    for st, ps in by.items():
        ps = sorted(ps, key=lambda q: q["t"])
        # seq gói ĐẦU của stream = SYN: số tuyệt đối (tcp.seq_raw), giữ nguyên qua DNAT
        legs.append(dict(g=ps, src0=ps[0]["src"], t0=ps[0]["t"], syn_seq=float(ps[0].get("seq") or 0)))
    res = []
    for L in legs:
        if not L["src0"].startswith("172.30.10.3"):
            continue                                    # chỉ xuất phát từ leg pre-NAT (client)
        def same_leg(m):
            if not m["src0"].startswith("172.30.20."):
                return False
            if not (np.isnan(L["syn_seq"]) or np.isnan(m["syn_seq"])):
                return L["syn_seq"] == m["syn_seq"]          # khoá chính: seq_raw (giữ qua DNAT)
            return abs(m["t0"] - L["t0"]) < 0.02             # dự phòng
        M = next((m for m in legs if m is not L and same_leg(m)), None)
        if M is None:
            continue
        c2s = sorted([p for p in M["g"] if p["src"] == M["src0"] and p["tlen"] > 0], key=lambda q: q["t"])
        s2c = sorted([p for p in L["g"] if p["src"] != L["src0"] and p["tlen"] > 0], key=lambda q: q["t"])
        if not c2s or not s2c:
            continue
        t_sv1 = s2c[0]["t"]                              # byte đầu tiên của server
        ch = [p for p in c2s if p["t"] <= t_sv1]         # flight ClientHello trên đường truyền
        nxt = [p for p in c2s if p["t"] > t_sv1]
        t_cl2 = nxt[0]["t"] if nxt else float("inf")
        sv = [p for p in s2c if t_sv1 <= p["t"] <= t_cl2]  # flight server trên đường truyền
        total = sum(p["tlen"] for p in ch)
        res.append(dict(group="X25519" if total < 800 else "PQC",
                        cl_seg=len(ch), cl_bytes=total, sv_seg=len(sv),
                        sv_bytes=sum(p["tlen"] for p in sv),
                        maxpkt=max([p["tlen"] for p in ch + sv] or [0])))
    return res

J = []
for f in sorted(glob.glob(os.path.join(LAB, "pcap2_L*.pcapng"))):
    mm = re.search(r"_M(\d+)\.pcapng$", f)
    if not mm:
        continue
    mtu = int(mm.group(1))
    for r in wire_segments(f):
        r["mtu"] = mtu; J.append(r)
JD = pd.DataFrame(J)
msg, okJ = [], None
if len(JD):
    okJ = True
    for mtu, sub in JD.groupby("mtu"):
        sx = sub[sub.group == "X25519"]; sp = sub[sub.group == "PQC"]
        if sx.empty or sp.empty:
            okJ = False; continue
        msg.append(f"M{mtu}: client {sx.cl_seg.median():.0f}→{sp.cl_seg.median():.0f} seg, "
                   f"server {sx.sv_seg.median():.0f}→{sp.sv_seg.median():.0f} seg "
                   f"(tổng {sx.cl_seg.median()+sx.sv_seg.median():.0f}→{sp.cl_seg.median()+sp.sv_seg.median():.0f}), "
                   f"gói egress lớn nhất {sub.maxpkt.max():.0f} ≤ MTU−52={mtu-52}")
        if (sp.cl_seg.median() + sp.sv_seg.median()) <= (sx.cl_seg.median() + sx.sv_seg.median()):
            okJ = False
        if sub.maxpkt.max() > mtu - 52:
            okJ = False
    if set(JD.mtu.unique()) != {1500, 1280, 576}:
        okJ = False
        msg.append(f"THIẾU MTU: chỉ có {sorted(JD.mtu.unique())}")
check("J", "Phân mảnh cấp wire tính LẠI từ pcap; MTU thực sự có hiệu lực trên leg egress", okJ,
      " | ".join(msg) if msg else "không dựng được từ pcap")

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

# ---------------------------------------------------------------- CHECK K2: cơ chế PMTUD trong pcap
# Không chỉ đếm "hoàn tất / không": kiểm tra CHUỖI NHÂN QUẢ trong chính pcap.
def ts_fields(pcap, filt, fields):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", filt, "-T", "fields"]
                         + sum([["-e", f] for f in fields], []),
                         capture_output=True, text=True).stdout.strip().split("\n")
    return [l.split("\t") for l in out if l.strip()]

def pmtud_mechanism(cid):
    pcap = os.path.join(LAB, f"pcap_pmtud_{cid}.pcapng")
    if not os.path.exists(pcap):
        return None
    icmp = len(ts_fields(pcap, "icmp.type==3 && icmp.code==4", ["frame.number"]))
    # chiều client->server trên leg egress (router 172.30.20.3 -> server)
    egr = [int(r[0] or 0) for r in ts_fields(pcap, "ip.src==172.30.20.3 && tcp.len>0", ["tcp.len"])]
    # chiều client->router (ingress): kích thước các gói lớn + số lần gửi lại
    ing = ts_fields(pcap, "ip.src==172.30.10.3 && tcp.len>1000",
                    ["tcp.len", "tcp.analysis.retransmission"])
    big = [int(r[0]) for r in ing]
    retr = sum(1 for r in ing if len(r) > 1 and r[1].strip() == "1")
    return dict(icmp=icmp, egr=sorted(set(egr)), big=sorted(set(big)), retr=retr)

m2 = pmtud_mechanism("c2_hyb_1280_allow")
m1 = pmtud_mechanism("c1_hyb_1280_drop")
m8 = pmtud_mechanism("c8_hyb_576_drop")
m9 = pmtud_mechanism("c9_x25519_576_drop")

def srv_seq_advance(cid):
    """Server có THỰC SỰ phát flight không: với TỪNG kết nối (tcp.stream), lấy hiệu số
    seq_raw lớn nhất − nhỏ nhất của các gói từ phía server (172.30.10.2), rồi lấy TRUNG VỊ.
    X25519 flight 767 B ⇒ tiến ~768 (767 dữ liệu + 1 cho SYN)."""
    f = os.path.join(LAB, f"pcap_pmtud_{cid}.pcapng")
    if not os.path.exists(f):
        return None
    per = {}
    for r in ts_fields(f, "ip.src==172.30.10.2", ["tcp.stream", "tcp.seq_raw"]):
        if len(r) >= 2 and str(r[1]).strip().isdigit():
            per.setdefault(r[0], []).append(int(r[1]))
    adv = [max(v) - min(v) for v in per.values() if len(v) >= 2]
    return int(np.median(adv)) if adv else None


def srv_to_client(cid):
    """Dữ liệu server→client có tới được client không (leg egress pre-NAT)."""
    f = os.path.join(LAB, f"pcap_pmtud_{cid}.pcapng")
    return len(ts_fields(f, "ip.src==172.30.10.2 && tcp.len>0", ["tcp.len"])) if os.path.exists(f) else None

okK2 = None
if m1 and m2 and m8 and m9:
    # c2 (cho qua): có ICMP và client TỰ CHIA LẠI ClientHello (egress có đoạn ≤ MSS 1228)
    # c1 (chặn):   0 ICMP, gửi lại nguyên 1393 B, không gì tới server  → blackhole PMTUD
    # c8 (hybrid@576): cùng dấu hiệu như c1 ⇒ cũng là blackhole PMTUD
    # c9 (X25519@576): 0 ICMP nhưng hỏng vì CHIỀU SERVER→CLIENT bị bỏ im lặng trước router
    okK2 = (m2["icmp"] >= 1 and m1["icmp"] == 0
            and 1393 in m2["big"] and len([x for x in m2["egr"] if x > 0]) >= 2
            and max(m2["egr"] or [0]) <= 1228
            and m1["big"] == [1393] and m1["retr"] >= 5 and not m1["egr"]
            and m8["icmp"] == 0 and m8["big"] == [1393] and m8["retr"] >= 5 and not m8["egr"]
            # c9: CH (217 B) PHẢI đã qua được tới server, nhưng KHÔNG có dữ liệu server→client nào
            # tới client ⇒ kết luận 'drop im lặng chiều về' mới có nội dung (nếu server không gửi gì
            # thì tiêu chí cũ vẫn PASS một cách rỗng).
            and m9["icmp"] == 0 and (217 in m9["egr"])
            and (srv_seq_advance("c9_x25519_576_drop") or 0) >= 700      # server ĐÃ phát flight 767 B
            and (srv_to_client("c9_x25519_576_drop") == 0))              # nhưng 0 byte tới client
    check("K2", "Cơ chế trong pcap: ICMP ⇒ tự chia lại CH; chặn ICMP ⇒ blackhole (c1, c8); c9 = drop im lặng chiều server→client",
          okK2,
          f"c2 (cho qua): {m2['icmp']} ICMP, egress nhận {m2['egr']} (≤ MSS 1228), ingress gửi {m2['big']} | "
          f"c1 (chặn): {m1['icmp']} ICMP, gửi lại {m1['retr']} lần nguyên {m1['big']}, egress rỗng | "
          f"c8 (hybrid@576): {m8['icmp']} ICMP, gửi lại {m8['retr']} lần nguyên {m8['big']}, egress rỗng | "
          f"c9 (X25519@576): {m9['icmp']} ICMP, seq server tiến {srv_seq_advance('c9_x25519_576_drop')} B "
          f"(đã phát flight), nhưng gói dữ liệu server→client tới client = {srv_to_client('c9_x25519_576_drop')}")
else:
    check("K2", "Cơ chế PMTUD trong pcap", None, "thiếu pcap c1/c2/c8/c9")

# ---------------------------------------------------------------- CHECK L: đối chứng thứ tự
oc = os.path.join(BASE, "tables", "order_control.json")
if os.path.exists(oc):
    O = json.load(open(oc))
    det, okL = [], True
    dec = O.get("decomposition_2x2", {})
    for k, v in O.items():
        if not k.startswith("MTU"):
            continue
        dd = dec.get(k, {})
        det.append(f"{k}: Δnhóm {v['delta_group_ms']:+.3f} ms (p={v['p_group']:.2g}) | "
                   f"Δvị trí TRONG nhóm: X {dd.get('pos_delta_X25519_ms', float('nan')):+.3f}, "
                   f"PQC {dd.get('pos_delta_X25519MLKEM768_ms', float('nan')):+.3f} ms")
        # (a) hiệu ứng nhóm phải DƯƠNG và có ý nghĩa;
        # (b) hiệu ứng vị trí phải được đánh giá TRONG TỪNG NHÓM (trung vị lề bị confound thành phần,
        #     vì hai vị trí có tỉ lệ nhóm khác nhau) — và phải nhỏ.
        if not (v["delta_group_ms"] > 0 and v["p_group"] < 0.05):
            okL = False
        for key in ("pos_delta_X25519_ms", "pos_delta_X25519MLKEM768_ms"):
            val = dd.get(key)
            if val is None or abs(val) > 0.10:
                okL = False
    check("L", "Đối chứng thứ tự ngẫu nhiên: hiệu ứng NHÓM tái lập; hiệu ứng VỊ TRÍ (trong từng nhóm) nhỏ",
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
