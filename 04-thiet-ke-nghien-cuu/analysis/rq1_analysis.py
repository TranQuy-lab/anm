#!/usr/bin/env python3
# rq1_analysis.py — RQ1: tác động mạng của ML-KEM hybrid vs X25519 (thống kê + biểu đồ)
# Thiết kế: paired theo thứ tự lặp (môi trường dừng), Wilcoxon signed-rank + Cohen's d paired,
# hiệu chỉnh Holm-Bonferroni (theo skill statistical-analysis: luôn kèm effect size).
import re, json
import numpy as np
import pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = __file__.rsplit("/", 1)[0]
df = pd.read_csv(f"{BASE}/packets_all.tsv", sep="\t")
df.columns = ["pcap","stream","time","src","tcplen","seq","ack","retrans","syn","fin","rst"]
BOOL_MAP = {"True":1,"False":0,"true":1,"false":0}
for c in ("retrans","syn","fin","rst"):
    df[c] = pd.to_numeric(df[c].replace(BOOL_MAP), errors="coerce").fillna(0).astype(int)
for c in ("time","tcplen","seq","ack"):
    df[c] = pd.to_numeric(df[c], errors="coerce")

pat_hs = re.compile(r"pcap_(X25519MLKEM768|X25519)_L(\d+)_D(\d+)_M(\d+)\.pcapng")

def stream_features(g: pd.DataFrame) -> dict | None:
    g = g.sort_values("time")
    client_ip = g.loc[g["syn"] == 1, "src"]
    if client_ip.empty:  # bắt đầu giữa chừng → bỏ stream
        return None
    client_ip = client_ip.iloc[0]
    if not str(client_ip).startswith("172.30.10."):
        return None  # leg post-NAT (router↔server) — chỉ phân tích leg client
    cli = g[g["src"] == client_ip]; srv = g[g["src"] != client_ip]
    dat = cli[cli["tcplen"] > 0]
    if dat.empty: return None
    t_ch = dat["time"].min()
    sdat = srv[srv["tcplen"] > 0]
    if sdat.empty: return None
    t_sv1 = sdat["time"].min()
    nxt = dat[dat["time"] > t_sv1]
    if nxt.empty:  # client chưa hoàn tất flight 2 trong capture → handshake thất bại/treo
        return {"ok": 0}
    t_cl2 = nxt["time"].min()
    win_c = cli[(cli["time"] >= t_ch) & (cli["time"] <= t_cl2)]
    win_s = srv[(srv["time"] >= t_ch) & (srv["time"] <= t_cl2)]
    novel_c = win_c[win_c["retrans"] != 1]["tcplen"].sum()
    return {
        "ok": 1, "hs_rtt": t_cl2 - t_ch,
        "cl_hs_bytes": float(win_c["tcplen"].sum()), "cl_hs_novel_bytes": float(novel_c),
        "sv_hs_bytes": float(win_s["tcplen"].sum()),
        "cl_nsegs": int((win_c["tcplen"] > 0).sum()),
        "sv_nsegs": int((win_s["tcplen"] > 0).sum()),
        "retrans": int((g["retrans"] == 1).sum()),
        "flow_dur": float(g["time"].max() - g["time"].min()),
        "flow_cli_bytes": float(cli["tcplen"].sum()),
        "flow_srv_bytes": float(srv["tcplen"].sum()),
    }

rows, failed = [], []
for name, g in df.groupby(["pcap","stream"]):
    m = pat_hs.search(name[0])
    if not m: continue
    f = stream_features(g)
    if f is None: continue
    grp = dict(group=m.group(1), loss=int(m.group(2)), delay=int(m.group(3)), mtu=int(m.group(4)), tag=m.group(0))
    (rows if f.get("ok") else failed).append({**grp, **f})

R = pd.DataFrame(rows)
F = pd.DataFrame(failed)
if F.empty:
    F = pd.DataFrame(columns=["group","loss","delay","mtu","n_failed"])
else:
    F = F.groupby(["group","loss","delay","mtu"], as_index=False).size().rename(columns={"size":"n_failed"})
R.to_csv(f"{BASE}/tables/rq1_flows.csv", index=False); F.to_csv(f"{BASE}/tables/rq1_failures.csv", index=False)

# ---- Thống kê paired theo cấu hình ----
def cohens_d_paired(x, y):
    d = np.asarray(x) - np.asarray(y)
    return d.mean() / d.std(ddof=1) if d.std(ddof=1) > 0 else np.nan

cfgs = sorted(set(zip(R.loss, R.delay, R.mtu)))
stat_rows = []
for loss, delay, mtu in cfgs:
    a = R[(R.group=="X25519") & (R.loss==loss) & (R.delay==delay) & (R.mtu==mtu)].sort_index()
    b = R[(R.group=="X25519MLKEM768") & (R.loss==loss) & (R.delay==delay) & (R.mtu==mtu)].sort_index()
    n = min(len(a), len(b))
    a, b = a.head(n), b.head(n)
    if n == 0: continue
    for metric in ("hs_rtt","cl_hs_novel_bytes","sv_hs_bytes","retrans","flow_dur"):
        x, y = a[metric].values, b[metric].values
        if np.allclose(x, y):
            p, W, d = 1.0, np.nan, 0.0
        else:
            W, p = stats.wilcoxon(x, y)
            d = cohens_d_paired(x, y)
        stat_rows.append(dict(loss=loss, delay=delay, mtu=mtu, metric=metric, n=n,
                              med_x=np.median(x), med_y=np.median(y),
                              mean_x=x.mean(), mean_y=y.mean(),
                              sd_x=x.std(ddof=1), sd_y=y.std(ddof=1),
                              W=W, p=p, cohen_d=d))
S = pd.DataFrame(stat_rows)
if S.empty:
    print("[rq1] dữ liệu chưa đủ (thiếu một phía so sánh) — chỉ xuất rq1_flows.csv")
    R.to_csv(f"{BASE}/tables/rq1_flows.csv", index=False)
    raise SystemExit(0)
# Holm–Bonferroni trong từng họ (mỗi metric một họ qua các cấu hình)
S["p_holm"] = np.nan
for metric in S.metric.unique():
    idx = S.metric == metric
    sub = S[idx].sort_values("p")
    m = len(sub)
    pvals = sub["p"].values
    madj = np.maximum.accumulate((m - np.arange(m)) * pvals)
    S.loc[sub.index, "p_holm"] = np.minimum(madj, 1.0)
S.to_csv(f"{BASE}/tables/rq1_stats.csv", index=False)

# ---- Biểu đồ ----
C_A, C_B = "#0072B2", "#D55E00"  # colorblind-safe (Okabe-Ito)
plt.rcParams.update({"font.size": 11, "figure.dpi": 150})

# Fig 1: RTT theo loss (delay=0, mtu=1500)
fig, ax = plt.subplots(figsize=(6,4))
for mtu, style in [(1500,"o"), (1280,"s")]:
    for G, c, lab in [("X25519", C_A, "X25519 (cổ điển)"), ("X25519MLKEM768", C_B, "X25519MLKEM768 (PQC hybrid)")]:
        sub = R[(R.group==G)&(R.loss.isin([0,1,3]))&(R.delay==0)&(R.mtu==mtu)]
        g = sub.groupby("loss")["hs_rtt"].agg(["median", lambda s: s.quantile(.25), lambda s: s.quantile(.75)])
        ax.errorbar(g.index, g["median"], yerr=[g["median"]-g["<lambda_0>"], g["<lambda_1>"]-g["median"]],
                    marker=style, color=c, label=f"{lab}, MTU {mtu}", capsize=3, ls="-" if mtu==1500 else "--")
ax.set_xlabel("Mất gói (%)"); ax.set_ylabel("Thời gian bắt tay TLS (s)")
ax.set_title("RQ1: RTT bắt tay theo mức mất gói (delay 0 ms)"); ax.legend(fontsize=8); ax.grid(alpha=.3)
fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig1_rtt_loss.png"); plt.close(fig)

# Fig 2: bytes bắt tay (mạng sạch)
fig, ax = plt.subplots(figsize=(6,4))
clean = R[(R.loss==0)&(R.delay==0)&(R.mtu==1500)]
labels = ["Client\n( novel bytes)", "Server"]
x = np.arange(2); w = 0.35
for i,(G,c) in enumerate([("X25519",C_A),("X25519MLKEM768",C_B)]):
    vals = [clean[clean.group==G]["cl_hs_novel_bytes"].median(), clean[clean.group==G]["sv_hs_bytes"].median()]
    ax.bar(x + (i-0.5)*w, vals, w, color=c, label=G)
ax.set_xticks(x, labels); ax.set_ylabel("Số byte bắt tay (median)")
ax.set_title("Kích thước dữ liệu bắt tay TLS 1.3: cổ điển vs PQC hybrid")
ax.legend(); ax.grid(alpha=.3, axis="y")
fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig2_handshake_bytes.png"); plt.close(fig)

# Fig 3: retransmission theo loss (mtu 1280)
fig, ax = plt.subplots(figsize=(6,4))
for G, c, mk in [("X25519",C_A,"o"),("X25519MLKEM768",C_B,"s")]:
    sub = R[(R.group==G)&(R.loss.isin([0,1,3]))&(R.delay==0)&(R.mtu==1280)]
    g = sub.groupby("loss")["retrans"].mean()
    ax.plot(g.index, g.values, marker=mk, color=c, label=G)
ax.set_xlabel("Mất gói (%)"); ax.set_ylabel("Số lần TCP retransmission / handshake (TB)")
ax.set_title("Tiếp xúc mất gói của bắt tay PQC (MTU 1280)"); ax.legend(); ax.grid(alpha=.3)
fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig3_retrans_loss.png"); plt.close(fig)

summary = {
    "n_flows_ok": int(len(R)), "n_flows_failed": int(len(F)),
    "by_config_ok": {f"{g}|L{l}_D{d}_M{m}": int(n) for (g,l,d,m), n in
                     R.groupby(["group","loss","delay","mtu"]).size().items()},
    "clean_network_hs_bytes": {
        "X25519": {"client_novel": float(R[(R.group=="X25519")&(R.loss==0)&(R.delay==0)&(R.mtu==1500)]["cl_hs_novel_bytes"].median()),
                    "server": float(R[(R.group=="X25519")&(R.loss==0)&(R.delay==0)&(R.mtu==1500)]["sv_hs_bytes"].median())},
        "X25519MLKEM768": {"client_novel": float(R[(R.group=="X25519MLKEM768")&(R.loss==0)&(R.delay==0)&(R.mtu==1500)]["cl_hs_novel_bytes"].median()),
                            "server": float(R[(R.group=="X25519MLKEM768")&(R.loss==0)&(R.delay==0)&(R.mtu==1500)]["sv_hs_bytes"].median())},
    },
}
json.dump(summary, open(f"{BASE}/tables/rq1_summary.json","w"), indent=2, default=str)
print(json.dumps(summary, indent=2, default=str))
print(f"\n[TABLES] rq1_flows.csv, rq1_stats.csv, rq1_failures.csv, rq1_summary.json")
print(f"[FIGS] fig1_rtt_loss.png, fig2_handshake_bytes.png, fig3_retrans_loss.png")
