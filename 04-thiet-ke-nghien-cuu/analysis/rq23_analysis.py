#!/usr/bin/env python3
# rq23_analysis.py — RQ2/RQ3: drift của classifier lưu lượng khi giao thức chuyển PQC + thích ứng.
# Trách nhiệm chống leakage: label gán theo thời điểm SYN (tệp sites_*.csv ghi t_ns_wall trong
# cùng đồng hồ kernel với pcap); không bao giờ trộn session giữa train/test trừ khi chủ ý (drift).
import re, json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = __file__.rsplit("/", 1)[0]
K = 20  # độ dài chuỗi kích thước packet (padded) mỗi chiều

def load_flows(pcap_name: str, csv_name: str) -> pd.DataFrame:
    df = pd.read_csv(f"{BASE}/packets_all.tsv", sep="\t")
    df.columns = ["pcap","stream","time","src","tcplen","seq","ack","retrans","syn","fin","rst"]
    BOOL_MAP = {"True":1,"False":0,"true":1,"false":0}
    for c in ("retrans","syn","fin","rst"):
        df[c] = pd.to_numeric(df[c].replace(BOOL_MAP), errors="coerce").fillna(0).astype(int)
    for c in ("time","tcplen","seq","ack"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    g = df[df.pcap == pcap_name]
    # meta: thời điểm bắt đầu từng flow từ CSV client (cùng đồng hồ kernel)
    meta = pd.read_csv(f"../../docker-lab/results/{csv_name}")
    meta["t0_s"] = meta["t_ns_wall"] / 1e9
    rows = []
    for (pcap, stream), s in g.groupby(["pcap","stream"]):
        s = s.sort_values("time")
        syn_src = s.loc[s["syn"] == 1, "src"]
        if syn_src.empty: continue
        cli_ip = syn_src.iloc[0]
        if not str(cli_ip).startswith("172.30.10."):
            continue  # bỏ leg post-NAT router↔server
        t_syn = s["time"].min()
        if meta.empty: continue
        i = (meta["t0_s"] - t_syn).abs().idxmin()
        if abs(meta.loc[i, "t0_s"] - t_syn) > 1.0:  # không khớp → bỏ
            continue
        site = meta.loc[i, "site"]
        cli = s[s["src"] == cli_ip]; srv = s[s["src"] != cli_ip]
        t_ch = cli[cli["tcplen"] > 0]["time"].min()
        t_sv1 = srv[srv["tcplen"] > 0]["time"].min()
        app_s = srv[srv["time"] > (t_sv1 + 0.001)]["tcplen"].values
        app_c = cli[cli["time"] > t_sv1]["tcplen"].values
        cli_sizes = cli["tcplen"].values
        def pad(a, k):
            a = np.asarray(a, dtype=float)[:k]
            return np.pad(a, (0, k - len(a)))
        iat_c = np.diff(cli[cli["tcplen"] > 0]["time"].values) if len(cli) > 1 else np.array([0.0])
        rows.append({
            "stream": stream, "site": site, "t_syn": t_syn,
            "cli_total": float(cli["tcplen"].sum()), "srv_total": float(srv["tcplen"].sum()),
            "app_srv_bytes": float(app_s.sum()) if len(app_s) else 0.0,
            "n_cli_pkts": int((cli["tcplen"] > 0).sum()), "n_srv_pkts": int((srv["tcplen"] > 0).sum()),
            "dur": float(s["time"].max() - s["time"].min()),
            "mean_iat_c": float(np.mean(iat_c)) if len(iat_c) else 0.0,
            **{f"cs_{j}": v for j, v in enumerate(pad(cli_sizes, K))},
            **{f"sv_{j}": v for j, v in enumerate(pad(srv[srv['tcplen']>0]['time'].values * 0 + srv[srv['tcplen']>0]['tcplen'].values, K))},
        })
    return pd.DataFrame(rows)

A = load_flows("pcap_sites_X25519.pcapng", "sites_X25519.csv")
B = load_flows("pcap_sites_X25519MLKEM768.pcapng", "sites_X25519MLKEM768.csv")
feat = [c for c in A.columns if c not in ("stream","site","t_syn")]
Xa, ya = A[feat].values, A["site"].values
Xb, yb = B[feat].values, B["site"].values

def fit_eval(Xtr, ytr, Xte, yte, seed=42):
    clf = RandomForestClassifier(n_estimators=300, random_state=seed, n_jobs=-1)
    clf.fit(Xtr, ytr)
    p = clf.predict(Xte)
    return accuracy_score(yte, p), f1_score(yte, p, average="macro")

# (1) Baseline: 5-fold CV trong X25519
cv = StratifiedKFold(5, shuffle=True, random_state=42)
cv_acc = cross_val_score(RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1), Xa, ya, cv=cv)
# (2) Drift: train X25519 → test MLKEM768
acc_drift, f1_drift = fit_eval(Xa, ya, Xb, yb)
# bootstrap CI cho drift
rng = np.random.default_rng(7)
boot = []
for _ in range(300):
    idx = rng.integers(0, len(Xb), len(Xb))
    acc, _ = fit_eval(Xa, ya, Xb[idx], yb[idx], seed=42)
    boot.append(acc)
ci = (np.percentile(boot, 2.5), np.percentile(boot, 97.5))

# (3) Thích ứng: thêm k flow MLKEM/site vào train
adapt = []
for k in (1, 3, 5, 10, 20):
    accs = []
    for draw in range(10):
        pick = []
        for site in np.unique(yb):
            idc = np.where(yb == site)[0]
            pick.extend(rng.choice(idc, size=min(k, len(idc)), replace=False))
        pick = np.array(pick)
        test_mask = np.ones(len(Xb), bool); test_mask[pick] = False
        acc, _ = fit_eval(np.vstack([Xa, Xb[pick]]), np.concatenate([ya, yb[pick]]), Xb[test_mask], yb[test_mask])
        accs.append(acc)
    adapt.append(dict(k=k, mean=float(np.mean(accs)), lo=float(np.percentile(accs,5)), hi=float(np.percentile(accs,95))))

out = {
    "n_flows_X25519": int(len(A)), "n_flows_MLKEM768": int(len(B)),
    "baseline_cv_acc_mean": float(cv_acc.mean()), "baseline_cv_acc_sd": float(cv_acc.std()),
    "drift_acc": float(acc_drift), "drift_macroF1": float(f1_drift),
    "drift_acc_CI95": [float(ci[0]), float(ci[1])],
    "adaptation_curve": adapt,
}
json.dump(out, open(f"{BASE}/tables/rq23_summary.json","w"), indent=2)
print(json.dumps(out, indent=2))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10,4))
ax1.bar(["Baseline\n(within X25519)", "Drift:\ntrain X25519\ntest MLKEM768"],
        [cv_acc.mean(), acc_drift],
        yerr=[[cv_acc.mean()-cv_acc.mean()-cv_acc.std() if False else 0, acc_drift-ci[0]],
              [0, ci[1]-acc_drift]],
        color=[ "#0072B2", "#D55E00"], capsize=4)
ax1.set_ylim(0,1.05); ax1.set_ylabel("Accuracy (6 lớp site)")
ax1.set_title("RQ2: Suy giảm classifier sau drift PQC"); ax1.grid(alpha=.3, axis="y")
ks = [d["k"] for d in adapt]; m = [d["mean"] for d in adapt]
lo = [d["mean"]-d["lo"] for d in adapt]; hi = [d["hi"]-d["mean"] for d in adapt]
ax2.errorbar(ks, m, yerr=[lo,hi], marker="o", color="#009E73", capsize=3)
ax2.axhline(acc_drift, ls="--", color="#D55E00", label="Không thích ứng")
ax2.axhline(cv_acc.mean(), ls=":", color="#0072B2", label="Baseline mức trần")
ax2.set_xlabel("Số flow MLKEM768/site thêm vào train"); ax2.set_xscale("log")
ax2.set_ylabel("Accuracy trên test MLKEM768"); ax2.set_title("RQ3: Thích ứng nhanh với ít dữ liệu mới")
ax2.legend(fontsize=8); ax2.grid(alpha=.3)
fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig4_drift_adaptation.png"); plt.close(fig)
print("[FIG] fig4_drift_adaptation.png ; [TABLE] rq23_summary.json")
