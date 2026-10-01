#!/usr/bin/env python3
# order_control.py — phân tích thí nghiệm ĐỐI CHỨNG THỨ TỰ (run_order_control.sh).
#
# Trả lời hai câu hỏi:
#   1. Khi thứ tự hai nhóm được đảo NGẪU NHIÊN, độ lệch RTT giữa X25519 và nhóm lai có còn
#      giữ nguyên độ lớn/hướng như trong ma trận chính không?
#   2. Bản thân vị trí "chạy thứ nhất" so với "chạy thứ hai" trong một cặp có tạo khác biệt
#      hệ thống không?  Nếu (2) ≈ 0 thì kết luận ở ma trận chính không bị nhiễu bởi thứ tự.
import json, os, subprocess, glob
import numpy as np
import pandas as pd
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, "..", "..", "docker-lab", "results"))

def extract(pcap):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", "tcp", "-T", "json",
                          "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport",
                          "-e", "tcp.len", "-e", "frame.time_epoch"],
                         capture_output=True, text=True).stdout
    pkts = []
    for line in json.loads(out or "[]"):
        l = line["_source"]["layers"]
        def g(k):
            v = l.get(k)
            return v[0] if isinstance(v, list) else v
        try:
            pkts.append(dict(stream=int(g("tcp.stream")), src=g("ip.src"), sport=g("tcp.srcport"),
                             tlen=int(g("tcp.len") or 0), t=float(g("frame.time_epoch") or 0)))
        except (TypeError, ValueError):
            continue
    return pkts

def flows(pkts):
    by = {}
    for p in pkts: by.setdefault(p["stream"], []).append(p)
    out = []
    for st, ps in by.items():
        cands = {(p["src"], p["sport"]) for p in ps if p["sport"] != "4433"
                 and p["src"].startswith("172.30.10.")}
        if len(cands) != 1: continue
        cli = cands.pop()
        cp = sorted([p for p in ps if (p["src"], p["sport"]) == cli and p["tlen"] > 0], key=lambda q: q["t"])
        sp = sorted([p for p in ps if (p["src"], p["sport"]) != cli and p["tlen"] > 0], key=lambda q: q["t"])
        if not cp or not sp: continue
        t_ch = cp[0]["t"]; t_sv1 = sp[0]["t"]
        nxt = [q for q in cp if q["t"] > t_sv1]
        if not nxt: continue
        out.append(dict(stream=st, ch=cp[0]["tlen"], rtt=nxt[0]["t"] - t_ch,
                        t_syn=min(p["t"] for p in ps)))
    return out

def mwu(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) < 5 or len(b) < 5: return np.nan
    return float(stats.mannwhitneyu(a, b, alternative="two-sided").pvalue)

def cliffs(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    gt = sum((x > b).sum() for x in a); lt = sum((x < b).sum() for x in a)
    return (gt - lt) / (len(a) * len(b))

rows = []
for pcap in sorted(glob.glob(os.path.join(LAB, "pcap_order_M*.pcapng"))):
    mtu = int(pcap.rsplit("M", 1)[1].split(".")[0])
    F = flows(extract(pcap))
    # NHÃN VỊ TRÍ CHÍNH XÁC từ CSV lần chạy (không dựa vào ghép cặp tham lam theo thời gian):
    # mỗi hàng CSV có rep + nhóm + mốc bắt đầu; trong một rep, hàng có t_ns_wall nhỏ hơn là
    # "chạy thứ nhất". Ghép flow trong pcap về hàng CSV gần nhất theo mốc SYN.
    meta = []
    for G in ("X25519", "X25519MLKEM768"):
        p = os.path.join(LAB, f"hs2_ORD{mtu}_{G}.csv")
        if not os.path.exists(p):
            print(f"  [cảnh báo] thiếu {p} — bỏ qua MTU {mtu}"); meta = None; break
        d = pd.read_csv(p); d["group"] = G; meta.append(d)
    if meta is None:
        continue
    M = pd.concat(meta, ignore_index=True)
    M["t0_s"] = M["t_ns_wall"] / 1e9
    first_of_rep = M.loc[M.groupby("rep")["t_ns_wall"].idxmin()].set_index("rep")["group"].to_dict()
    for f in F:
        k = int(np.argmin(np.abs(M["t0_s"].values - f["t_syn"])))
        if abs(M["t0_s"].values[k] - f["t_syn"]) > 1.0:
            continue
        rep = M["rep"].values[k]
        grp_csv = M["group"].values[k]
        f["group"] = grp_csv          # nhãn nhóm lấy từ CSV (khớp với kích thước CH đã kiểm)
        f["rep"] = rep
        f["pos"] = "first" if first_of_rep.get(rep) == grp_csv else "second"
        rows.append(dict(mtu=mtu, pos=f["pos"], group=f["group"], ch=f["ch"], rtt=f["rtt"]))
D = pd.DataFrame(rows)
print(f"Đã phân tích {len(D)} flow trong {D.mtu.nunique()} cấu hình "
      f"({(D.pos=='first').sum()} ở vị trí 1, {(D.pos=='second').sum()} ở vị trí 2)\n")

out = {"n_flows": int(len(D))}
for mtu, sub in D.groupby("mtu"):
    X = sub[sub.group == "X25519"]["rtt"].values * 1000
    P = sub[sub.group == "X25519MLKEM768"]["rtt"].values * 1000
    F1 = sub[sub.pos == "first"]["rtt"].values * 1000
    F2 = sub[sub.pos == "second"]["rtt"].values * 1000
    out[f"MTU{mtu}"] = dict(
        n_X=len(X), n_PQC=len(P),
        med_X_ms=round(float(np.median(X)), 3), med_PQC_ms=round(float(np.median(P)), 3),
        delta_group_ms=round(float(np.median(P) - np.median(X)), 3),
        p_group=mwu(X, P), cliffs_group=round(cliffs(P, X), 3),
        med_first_ms=round(float(np.median(F1)), 3), med_second_ms=round(float(np.median(F2)), 3),
        delta_order_ms=round(float(np.median(F2) - np.median(F1)), 3),
        p_order=mwu(F1, F2), cliffs_order=round(cliffs(F2, F1), 3))
    print(f"=== MTU {mtu} ===")
    print(f"  theo NHÓM  : X25519 {np.median(X):.3f} ms | PQC {np.median(P):.3f} ms | "
          f"Δ = {np.median(P)-np.median(X):+.3f} ms | p = {mwu(X,P):.4g} | Cliff δ = {cliffs(P,X):+.3f}")
    print(f"  theo VỊ TRÍ: thứ nhất {np.median(F1):.3f} ms | thứ hai {np.median(F2):.3f} ms | "
          f"Δ = {np.median(F2)-np.median(F1):+.3f} ms | p = {mwu(F1,F2):.4g} | Cliff δ = {cliffs(F2,F1):+.3f}\n")

json.dump(out, open(os.path.join(HERE, "tables", "order_control.json"), "w"), indent=2)

# ---- Phân rã 2×2 để TÁCH BẠCH hiệu ứng nhóm và hiệu ứng vị trí ----
# Nếu thứ tự được ngẫu nhiên hoá thật, hiệu ứng nhóm tính TRONG từng vị trí phải ổn định;
# còn hiệu ứng vị trí tính TRONG từng nhóm cho biết bản thân "chạy thứ hai" có chậm hơn không.
print("=== Phân rã 2×2: hiệu ứng nhóm TRONG từng vị trí, và hiệu ứng vị trí TRONG từng nhóm ===")
decomp = {}
for mtu, sub in D.groupby("mtu"):
    d = {}
    for pos in ("first", "second"):
        x = sub[(sub.pos == pos) & (sub.group == "X25519")]["rtt"].values * 1000
        p = sub[(sub.pos == pos) & (sub.group == "X25519MLKEM768")]["rtt"].values * 1000
        d[f"group_delta_{pos}_ms"] = round(float(np.median(p) - np.median(x)), 3) if len(x) and len(p) else None
        d[f"n_{pos}_X"] = int(len(x)); d[f"n_{pos}_PQC"] = int(len(p))
    for grp in ("X25519", "X25519MLKEM768"):
        f1 = sub[(sub.pos == "first") & (sub.group == grp)]["rtt"].values * 1000
        f2 = sub[(sub.pos == "second") & (sub.group == grp)]["rtt"].values * 1000
        d[f"pos_delta_{grp}_ms"] = round(float(np.median(f2) - np.median(f1)), 3) if len(f1) and len(f2) else None
    decomp[f"MTU{mtu}"] = d
    print(f"  MTU {mtu}: Δnhóm|vị trí1 = {d['group_delta_first_ms']:+.3f} ms "
          f"(n={d['n_first_X']}/{d['n_first_PQC']}), Δnhóm|vị trí2 = {d['group_delta_second_ms']:+.3f} ms "
          f"| Δvị trí|X25519 = {d['pos_delta_X25519_ms']:+.3f} ms, Δvị trí|PQC = {d['pos_delta_X25519MLKEM768_ms']:+.3f} ms")
out["decomposition_2x2"] = decomp
json.dump(out, open(os.path.join(HERE, "tables", "order_control.json"), "w"), indent=2)
print("\n[TABLE] order_control.json")
