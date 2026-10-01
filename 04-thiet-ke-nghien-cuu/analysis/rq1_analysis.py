#!/usr/bin/env python3
# rq1_analysis.py — RQ1: tác động mạng của ML-KEM hybrid vs X25519.
#
# PHIÊN BẢN 2 (sau kiểm chứng chéo). Khác biệt so với bản 1:
#   (1) THỐNG KÊ: hai nhóm là hai mẫu ĐỘC LẬP (chạy khối tuần tự ở bản 1) nên kiểm định
#       chính là Mann–Whitney U; bản 1 dùng Wilcoxon signed-rank (paired) trên các cặp
#       KHÔNG hề ghép — sai thiết kế và che mất một khác biệt thật ở cấu hình mạng sạch.
#       Bản 2 báo cáo: MWU (chính), permutation trên trung vị, Wilcoxon paired theo `rep`
#       (chỉ hợp lệ ở bản 2 vì hai nhóm chạy XEN KẼ), effect size Cliff's δ + Hedges' g,
#       bootstrap CI 95% cho hiệu trung vị, Holm trong từng họ metric.
#   (2) PHÂN MẢNH: đo số segment CẤP WIRE trên leg egress của router (sau khi tắt GSO/TSO)
#       thay vì chỉ suy luận từ tổng byte.
#   (3) HOÀ GIẢI: đối chiếu 780 lần chạy client (exit_code) với số flow bắt được.
import re, json, sys, glob, os
import numpy as np
import pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(BASE, "..", "..", "docker-lab"))
RNG = np.random.default_rng(20261001)
N_BOOT = 10000

def load_packets(path):
    df = pd.read_csv(path, sep="\t", header=None, skiprows=1)
    df.columns = ["pcap","stream","time","src","dst","tcplen","seq","ack","retrans","syn","fin","rst","seqraw"]
    for c in ("retrans","syn","fin","rst"):
        # tshark in boolean dưới HAI dạng tuỳ field: "True"/"False" (cờ TCP) và "1"/rỗng
        # (tcp.analysis.retransmission). Phải xử lý cả hai, nếu không retrans luôn = 0.
        df[c] = pd.to_numeric(df[c].replace({"True":1,"False":0,"true":1,"false":0}), errors="coerce") \
                  .fillna(0).astype(int)
    for c in ("time","tcplen","seq","ack","seqraw"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

PAT = re.compile(r"pcap2?_L(\d+)_D(\d+)_M(\d+)\.pcapng")
PAT_OLD = re.compile(r"pcap_(X25519MLKEM768|X25519)_L(\d+)_D(\d+)_M(\d+)\.pcapng")

def load_runs():
    """Bảng lần chạy client từ CSV (rep, group, t_ns_wall, exit_code) — dùng để ghép rep
    và để hoà giải số lần chạy với số flow bắt được."""
    rows = []
    for f in sorted(glob.glob(f"{LAB}/results/hs2_*.csv")):
        d = pd.read_csv(f)
        m = re.search(r"hs2_L(\d+)_D(\d+)_M(\d+)_(X25519MLKEM768|X25519)\.csv", os.path.basename(f))
        if not m:
            continue
        d["loss"], d["delay"], d["mtu"], d["group"] = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        rows.append(d)
    if not rows:
        return pd.DataFrame(columns=["rep","group","t_ns_wall","exit_code","loss","delay","mtu"])
    R = pd.concat(rows, ignore_index=True)
    R["t0_s"] = R["t_ns_wall"] / 1e9
    return R

def index_streams(g_all):
    """Lập chỉ mục mọi tcp.stream của MỘT pcap. Mỗi stream = một leg (một chiều, một chặng).
    Lab có DNAT nên một kết nối xuất hiện ở 3-4 leg:
      L1 client→router  (src=client 172.30.10.x)      — ingress
      L2 router→server  (src=router 172.30.20.3)      — EGRESS, phân mảnh cấp wire
      L3 server→router  (src=server 172.30.20.2)
      L4 router→client  (src=router 172.30.10.2)      — EGRESS, phân mảnh cấp wire
    """
    idx = []
    for (pc, st), g in g_all.groupby(["pcap", "stream"]):
        g = g.sort_values("time")
        synp = g[g["syn"] == 1]
        idx.append(dict(stream=st, g=g,
                        src0=str(g["src"].iloc[0]), dst0=str(g["dst"].iloc[0]),
                        syn_src=str(synp["src"].iloc[0]) if len(synp) else None,
                        # seq_raw là số TUYỆT ĐỐI và được giữ nguyên qua DNAT ⇒ khoá ghép leg
                        # chính xác, không phụ thuộc netem delay (ghép theo mốc thời gian đã
                        # làm mất 47% số đo wire ở các cấu hình delay 50 ms).
                        syn_seq=float(synp["seqraw"].iloc[0]) if len(synp) else np.nan,
                        t0=float(g["time"].min())))
    return idx

def connection_features(legs):
    """legs: danh sách tcp.stream của CÙNG một pcap. Mỗi tcp.stream là một kết nối HAI CHIỀU
    ở một chặng; DNAT tạo thêm một stream nữa cho chặng router↔server."""
    out = []
    for L in legs:
        if L["syn_src"] is None or not L["syn_src"].startswith("172.30.10."):
            continue
        cip = L["syn_src"]
        g = L["g"]
        cli = g[g["src"] == cip]          # client → router (ingress)
        srv = g[g["src"] != cip]          # router → client (egress, đã SNAT)
        dat = cli[cli["tcplen"] > 0]
        if dat.empty:
            continue
        sdat = srv[srv["tcplen"] > 0]
        if sdat.empty:
            continue
        t_ch = dat["time"].min()
        t_sv1 = sdat["time"].min()
        nxt = dat[dat["time"] > t_sv1]
        if nxt.empty:
            out.append({"ok": 0, "stream": L["stream"], "t_syn": float(g["time"].min())})
            continue
        t_cl2 = nxt["time"].min()
        wc = cli[(cli["time"] >= t_ch) & (cli["time"] <= t_cl2)]
        ws = srv[(srv["time"] >= t_ch) & (srv["time"] <= t_cl2)]
        ch_flight = dat[dat["time"] < t_sv1]

        # stream chặng router↔server (post-NAT) của CÙNG kết nối: khớp theo mốc SYN (<20 ms),
        # các kết nối trong pcap cách nhau ~60 ms nên không nhập nhằng.
        egr = egr_src = None
        for M in legs:
            if M is L or M["syn_src"] is None:
                continue
            same_syn = (not np.isnan(L["syn_seq"]) and not np.isnan(M["syn_seq"])
                        and L["syn_seq"] == M["syn_seq"])
            if M["src0"].startswith("172.30.20.") and (same_syn or abs(M["t0"] - L["t0"]) < 0.02):
                egr, egr_src = M["g"], M["src0"]; break
        wire_cl_nseg = wire_cl_bytes = wire_cl_first = np.nan
        if egr is not None:
            # chỉ gói router→server (đúng chiều client→server ở chặng sau NAT)
            e = egr[egr["src"] == egr_src]
            # chỉ tính flight ClientHello (trước khi server gửi byte dữ liệu đầu tiên)
            e = e[(e["tcplen"] > 0) & (e["time"] >= t_ch - 0.05) & (e["time"] < t_sv1)]
            wire_cl_nseg, wire_cl_bytes = int(len(e)), float(e["tcplen"].sum())
            # lấy segment ĐẦU của ClientHello theo seq_raw (gói gửi lại đuôi có seq lớn hơn,
            # nếu lấy .iloc[0] theo thời gian có thể nhầm một mảnh đuôi — đã gặp 1/780 ca)
            wire_cl_first = float(e.sort_values("seqraw")["tcplen"].iloc[0]) if len(e) else np.nan

        out.append({
            "ok": 1, "stream": L["stream"], "t_syn": float(g["time"].min()),
            "hs_rtt": float(t_cl2 - t_ch),
            # phân rã RTT để định vị chi phí: (1) CH→byte server đầu, (2) trải flight server,
            # (3) xử lý phía client đến flight-2
            "rtt_ch_to_sv1": float(t_sv1 - t_ch),
            "sv_spread": float(ws["time"].max() - t_sv1) if len(ws) else np.nan,
            "cl_proc": float(t_cl2 - ws["time"].max()) if len(ws) else np.nan,
            "cl_ch_bytes": float(ch_flight["tcplen"].iloc[0]) if len(ch_flight) else np.nan,
            "cl_ch_nseg": int(len(ch_flight)),
            "cl_ch_total": float(ch_flight["tcplen"].sum()),
            "cl_hs_bytes": float(wc["tcplen"].sum()),
            "cl_hs_novel_bytes": float(wc[wc["retrans"] != 1]["tcplen"].sum()),
            "sv_hs_bytes": float(ws["tcplen"].sum()),
            "sv_nseg": int((ws["tcplen"] > 0).sum()),
            # đếm retransmission của CẢ HAI chiều trong leg client (bản v1 cũng vậy; nếu chỉ đếm
            # phía client thì gần như luôn bằng 0 vì phần lớn mất gói rơi vào flight server)
            "retrans": int((g["retrans"] == 1).sum()),
            "flow_dur": float(cli["time"].max() - cli["time"].min()),
            "wire_cl_nseg": wire_cl_nseg, "wire_cl_bytes": wire_cl_bytes, "wire_cl_first": wire_cl_first,
            "wire_sv_nseg": int((ws["tcplen"] > 0).sum()),
            "cl_seg_max": float(ch_flight["tcplen"].max()) if len(ch_flight) else np.nan,
        })
    return out

def cliffs_delta(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    gt = sum((xi > y).sum() for xi in x); lt = sum((xi < y).sum() for xi in x)
    return float(gt - lt) / (len(x) * len(y))

def hedges_g(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    nx, ny = len(x), len(y)
    sp = np.sqrt(((nx-1)*x.var(ddof=1) + (ny-1)*y.var(ddof=1)) / (nx+ny-2))
    if sp == 0:
        return np.nan
    d = (x.mean() - y.mean()) / sp
    return float(d * (1 - 3/(4*(nx+ny)-9)))

def boot_ci(x, y, stat=np.median, B=N_BOOT, alpha=0.05):
    x, y = np.asarray(x, float), np.asarray(y, float)
    if len(x) == 0 or len(y) == 0:
        return (np.nan, np.nan)
    vals = np.empty(B)
    for b in range(B):
        vals[b] = stat(RNG.choice(x, len(x))) - stat(RNG.choice(y, len(y)))
    return tuple(np.percentile(vals, [100*alpha/2, 100*(1-alpha/2)]))

def perm_p(x, y, stat=np.median, B=5000):
    x, y = np.asarray(x, float), np.asarray(y, float)
    obs = stat(x) - stat(y)
    pool = np.concatenate([x, y]); n = len(x)
    cnt = 0
    for _ in range(B):
        RNG.shuffle(pool)
        if abs(stat(pool[:n]) - stat(pool[n:])) >= abs(obs) - 1e-15:
            cnt += 1
    return (cnt + 1) / (B + 1)

def holm(pvals):
    p = np.asarray(pvals, float); order = np.argsort(p); m = len(p)
    adj = np.empty(m); prev = 0.0
    for i, idx in enumerate(order):
        v = (m - i) * p[idx]
        prev = max(prev, v)
        adj[idx] = min(prev, 1.0)
    return adj

def main():
    pkt_path = f"{BASE}/packets_all.tsv"
    df = load_packets(pkt_path)
    runs = load_runs()
    interleaved = any(str(n).startswith("pcap2_") for n in df["pcap"].unique())

    rows, failed = [], []
    for name, gall in df.groupby("pcap"):
        m = PAT.search(name) or PAT_OLD.search(name)
        if not m:
            continue
        if PAT.search(name):
            loss, delay, mtu = int(m.group(1)), int(m.group(2)), int(m.group(3))
        else:
            loss, delay, mtu = int(m.group(2)), int(m.group(3)), int(m.group(4))
        legs = index_streams(gall)
        for f in connection_features(legs):
            rec = dict(loss=loss, delay=delay, mtu=mtu, pcap=name, **f)
            (rows if f.get("ok") else failed).append(rec)
    R = pd.DataFrame(rows)
    F = pd.DataFrame(failed)

    # --- gán nhóm + rep bằng ghép đồng hồ (chỉ khi có CSV lần chạy) ---
    if len(runs) and len(R):
        R["group"], R["rep"] = "?", np.nan
        for (loss, delay, mtu), sub in R.groupby(["loss","delay","mtu"]):
            cand = runs[(runs.loss==loss)&(runs.delay==delay)&(runs.mtu==mtu)]
            if cand.empty:
                # bản 1: tên pcap mang nhóm, không có ghép rep
                for i, r in sub.iterrows():
                    mm = PAT_OLD.search(r["pcap"])
                    R.loc[i, "group"] = mm.group(1) if mm else "?"
                continue
            t = cand["t0_s"].values; grp = cand["group"].values; rep = cand["rep"].values
            for i, ts in sub["t_syn"].items():
                k = int(np.argmin(np.abs(t - ts)))
                if abs(t[k] - ts) < 1.0:
                    R.loc[i, "group"] = grp[k]; R.loc[i, "rep"] = rep[k]
        R = R[R["group"] != "?"].copy()

    R.to_csv(f"{BASE}/tables/rq1_flows.csv", index=False)
    (F.groupby(["loss","delay","mtu"], as_index=False).size().rename(columns={"size":"n_failed"})
      if len(F) else pd.DataFrame(columns=["loss","delay","mtu","n_failed"])
     ).to_csv(f"{BASE}/tables/rq1_failures.csv", index=False)

    METRICS = ["hs_rtt","rtt_ch_to_sv1","sv_spread","cl_proc","cl_ch_bytes","cl_ch_nseg",
               "cl_hs_novel_bytes","sv_hs_bytes","sv_nseg","retrans","flow_dur","wire_cl_nseg"]
    stat_rows = []
    for (loss, delay, mtu), sub in R.groupby(["loss","delay","mtu"]):
        a = sub[sub.group=="X25519"]; b = sub[sub.group=="X25519MLKEM768"]
        for metric in METRICS:
            x = a[metric].dropna().values.astype(float)
            y = b[metric].dropna().values.astype(float)
            if len(x) == 0 or len(y) == 0:
                continue
            row = dict(loss=loss, delay=delay, mtu=mtu, metric=metric, n_a=len(x), n_b=len(y),
                       med_a=float(np.median(x)), med_b=float(np.median(y)),
                       mean_a=float(x.mean()), mean_b=float(y.mean()))
            degenerate = (len(x) == len(y) and np.allclose(x, y)) or \
                         (len(x) and len(y) and x.std() == 0 and y.std() == 0 and x[0] == y[0])
            if degenerate:
                row.update(U=np.nan, p_mwu=1.0, cliffs=0.0, hedges_g=0.0,
                           dmed_lo=0.0, dmed_hi=0.0, p_perm=1.0, p_wilcoxon_paired=np.nan)
            else:
                U, p = stats.mannwhitneyu(x, y, alternative="two-sided")
                lo, hi = boot_ci(x, y)
                row.update(U=float(U), p_mwu=float(p), cliffs=cliffs_delta(x, y),
                           hedges_g=hedges_g(x, y), dmed_lo=float(lo), dmed_hi=float(hi),
                           p_perm=float(perm_p(x, y)))
                if interleaved:
                    aa = a.dropna(subset=[metric]); bb = b.dropna(subset=[metric])
                    mg = pd.merge(aa[["rep",metric]], bb[["rep",metric]], on="rep", suffixes=("_a","_b"))
                    if len(mg) >= 6 and not np.allclose(mg[f"{metric}_a"], mg[f"{metric}_b"]):
                        _, pw = stats.wilcoxon(mg[f"{metric}_a"], mg[f"{metric}_b"])
                        row["p_wilcoxon_paired"] = float(pw)
                    else:
                        row["p_wilcoxon_paired"] = np.nan
                else:
                    row["p_wilcoxon_paired"] = np.nan
            stat_rows.append(row)
    S = pd.DataFrame(stat_rows)
    if not S.empty:
        S["p_holm"] = np.nan
        for metric in S.metric.unique():
            idx = S.metric == metric
            S.loc[idx, "p_holm"] = holm(S.loc[idx, "p_mwu"].fillna(1.0).values)
        S["p_holm_global"] = holm(S["p_mwu"].fillna(1.0).values)
        S = S.sort_values(["metric","loss","delay","mtu"])
    S.to_csv(f"{BASE}/tables/rq1_stats.csv", index=False)

    # --- hoà giải số lần chạy ---
    recon = {}
    if len(runs):
        recon = dict(attempted=int(len(runs)),
                     rc_zero=int((runs.exit_code == 0).sum()),
                     rc_nonzero=int((runs.exit_code != 0).sum()),
                     captured=int(len(R)), failed_no_flight=int(len(F)),
                     per_group_captured={g: int((R.group==g).sum()) for g in R.group.unique()})
    # --- byte budget mạng sạch ---
    clean = R[(R.loss==0)&(R.delay==0)&(R.mtu==1500)]
    def med(g, col):
        v = clean[clean.group==g][col].median()
        return None if pd.isna(v) else float(v)
    budget = {g: {c: med(g, c) for c in ("cl_ch_bytes","cl_hs_novel_bytes","sv_hs_bytes","cl_ch_nseg","wire_cl_nseg")}
              for g in ("X25519","X25519MLKEM768")}
    seg = {}
    if len(R):
        seg = (R[(R.loss==0)&(R.delay==0)]
               .groupby(["mtu","group"])[["cl_ch_nseg","wire_cl_nseg","sv_nseg"]]
               .median().round(3).to_dict(orient="index"))
        seg = {f"M{k[0]}|{k[1]}": v for k, v in seg.items()}

    summary = dict(interleaved_design=bool(interleaved), reconciliation=recon,
                   clean_network=budget, segmentation_median=seg,
                   n_flows=int(len(R)), n_configs=int(R.groupby(["loss","delay","mtu"]).ngroups) if len(R) else 0)
    json.dump(summary, open(f"{BASE}/tables/rq1_summary.json","w"), indent=2, default=str)
    print(json.dumps(summary, indent=2, default=str))
    print(f"\n[TABLES] rq1_flows.csv, rq1_stats.csv, rq1_failures.csv, rq1_summary.json  ({len(S)} dòng thống kê)")

    # ---------------- Biểu đồ ----------------
    if S.empty or len(R) == 0:
        print("[FIG] bỏ qua — thiếu dữ liệu so sánh")
        return
    C_A, C_B = "#0072B2", "#D55E00"
    plt.rcParams.update({"font.size": 10, "figure.dpi": 150})

    # Fig 1: RTT theo loss (delay 0)
    fig, ax = plt.subplots(figsize=(6.2,4))
    for mtu, style in [(1500,"o"),(1280,"s")]:
        for G, c, lab in [("X25519",C_A,"X25519"),("X25519MLKEM768",C_B,"X25519MLKEM768")]:
            sub = R[(R.group==G)&(R.loss.isin([0,1,3]))&(R.delay==0)&(R.mtu==mtu)]
            if sub.empty: continue
            q = sub.groupby("loss")["hs_rtt"].agg(med="median", q1=lambda s:s.quantile(.25), q3=lambda s:s.quantile(.75))
            ax.errorbar(q.index, q["med"], yerr=[q["med"]-q["q1"], q["q3"]-q["med"]],
                        marker=style, color=c, capsize=3, ls="-" if mtu==1500 else "--",
                        label=f"{lab}, MTU {mtu}")
    ax.set_xlabel("Mất gói (%)"); ax.set_ylabel("RTT bắt tay TLS (s)")
    ax.set_title("RQ1: RTT bắt tay theo mất gói (delay 0 ms)"); ax.legend(fontsize=8); ax.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig1_rtt_loss.png"); plt.close(fig)

    # Fig 2: byte bắt tay
    fig, ax = plt.subplots(figsize=(6.2,4))
    labels = ["ClientHello\n(packet đầu)", "Client\n(toàn flight)", "Server\n(toàn flight)"]
    x = np.arange(3); w = 0.36
    for i,(G,c) in enumerate([("X25519",C_A),("X25519MLKEM768",C_B)]):
        vals = [clean[clean.group==G]["cl_ch_bytes"].median(),
                clean[clean.group==G]["cl_hs_novel_bytes"].median(),
                clean[clean.group==G]["sv_hs_bytes"].median()]
        b = ax.bar(x+(i-.5)*w, vals, w, color=c, label=G)
        ax.bar_label(b, fmt="%.0f", fontsize=8)
    ax.set_xticks(x, labels); ax.set_ylabel("Byte (trung vị)")
    ax.set_title("Kích thước bắt handshake TLS 1.3 (MTU 1500, mạng sạch)"); ax.legend(); ax.grid(alpha=.3, axis="y")
    fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig2_handshake_bytes.png"); plt.close(fig)

    # Fig 3: retransmission theo loss
    fig, ax = plt.subplots(figsize=(6.2,4))
    for G, c, mk in [("X25519",C_A,"o"),("X25519MLKEM768",C_B,"s")]:
        sub = R[(R.group==G)&(R.loss.isin([0,1,3]))&(R.delay==0)&(R.mtu==1280)]
        if sub.empty: continue
        g = sub.groupby("loss")["retrans"].mean()
        ax.plot(g.index, g.values, marker=mk, color=c, label=G)
    ax.set_xlabel("Mất gói (%)"); ax.set_ylabel("TCP retransmission / handshake (TB)")
    ax.set_title("Retransmission theo mất gói (MTU 1280, delay 0)"); ax.legend(); ax.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig3_retrans_loss.png"); plt.close(fig)

    # Fig 5: phân mảnh cấp wire (số segment) theo MTU
    fig, ax = plt.subplots(figsize=(6.2,4))
    gg = R[(R.loss==0)&(R.delay==0)]
    if not gg.empty:
        mtus = sorted(gg["mtu"].unique())
        x = np.arange(len(mtus)); w = 0.36
        for i,(G,c) in enumerate([("X25519",C_A),("X25519MLKEM768",C_B)]):
            vals = [gg[(gg.group==G)&(gg.mtu==m)]["wire_cl_nseg"].median() for m in mtus]
            vals = [0 if pd.isna(v) else v for v in vals]
            b = ax.bar(x+(i-.5)*w, vals, w, color=c, label=G)
            ax.bar_label(b, fmt="%.0f", fontsize=8)
        ax.set_xticks(x, [f"M{int(m)}" for m in mtus])
        ax.set_xlabel("MTU đường truyền (byte)")
        ax.set_ylabel("Số segment cấp wire (trung vị)")
        ax.set_title("Phân mảnh cấp wire của flight client (đo trên leg egress)")
        ax.legend(fontsize=8); ax.grid(alpha=.3, axis="y")
    fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig5_wire_segments.png"); plt.close(fig)
    print("[FIGS] fig1_rtt_loss.png, fig2_handshake_bytes.png, fig3_retrans_loss.png, fig5_wire_segments.png")

if __name__ == "__main__":
    main()
