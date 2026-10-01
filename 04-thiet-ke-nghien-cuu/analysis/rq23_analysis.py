#!/usr/bin/env python3
# rq23_analysis.py — RQ2/RQ3: drift của classifier lưu lượng & chi phí thích ứng.
#
# PHIÊN BẢN 2 (sau kiểm chứng chéo). Sửa ba vấn đề của bản 1:
#   (1) RÒ RỈ: bản 1 dùng StratifiedKFold ngẫu nhiên trên 30 flow gần như trùng nhau cho mỗi
#       site → train/test chứa bản sao của nhau. Bản 2 dùng chia THEO THỜI GIAN (flow đầu train,
#       flow cuối test) — không bao giờ để flow cùng giai đoạn lọt cả hai phía.
#   (2) TÍNH TẦM THƯỜNG: 6 "site" có kích thước cố định nên chỉ 1 đặc trưng (tổng byte server)
#       đã phân loại hoàn hảo. Bản 2 báo cáo baseline 1-NN một-đặc-trưng như một PHÉP KIỂM
#       TÍNH TẦM THƯỜNG bắt buộc, thay vì trình bày accuracy 1.0 như thành tựu.
#   (3) CEILING: không thể đo "thích ứng" khi baseline đã 1.0. Bản 2 thêm một bài toán drift
#       THẬT và có ceiling thật: đổi MTU đường truyền (1500 ↔ 1280) làm thay đổi phân mảnh
#       pha ứng dụng → phân bố đặc trưng chuỗi gói dịch chuyển.
import re, json, os, glob
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.neighbors import KNeighborsClassifier
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(BASE, "..", "..", "docker-lab"))
K = 20
RNG = np.random.default_rng(20261002)

def load_packets(path):
    df = pd.read_csv(path, sep="\t", header=None, skiprows=1)
    df.columns = ["pcap","stream","time","src","dst","tcplen","seq","ack","retrans","syn","fin","rst","seqraw"]
    for c in ("retrans","syn","fin","rst"):
        df[c] = pd.to_numeric(df[c].replace({"True":1,"False":0,"true":1,"false":0}), errors="coerce") \
                  .fillna(0).astype(int)
    for c in ("time","tcplen","seq","ack"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

def site_flows(df, pcap, csv_path):
    meta = pd.read_csv(csv_path); meta["t0_s"] = meta["t_ns_wall"]/1e9
    g = df[df.pcap == pcap]
    rows = []
    for (pc, st), s in g.groupby(["pcap","stream"]):
        s = s.sort_values("time")
        syn = s.loc[s.syn == 1, "src"]
        if syn.empty: continue
        cip = syn.iloc[0]
        if not str(cip).startswith("172.30.10."): continue
        cli = s[s.src == cip]; srv = s[s.src != cip]
        dat = cli[cli.tcplen > 0]
        if dat.empty: continue
        t_ch = dat.time.min()
        sd = srv[srv.tcplen > 0]
        if sd.empty: continue
        t_sv1 = sd.time.min()
        nxt = dat[dat.time > t_sv1]
        if nxt.empty: continue
        t_cl2 = nxt.time.min()
        t_syn = float(s.time.min())
        k = int(np.argmin(np.abs(meta.t0_s.values - t_syn)))
        if abs(meta.t0_s.values[k] - t_syn) > 1.0: continue
        hs_c = cli[(cli.time >= t_ch) & (cli.time <= t_cl2)]
        hs_s = srv[(srv.time >= t_ch) & (srv.time <= t_cl2)]
        # PHA ỨNG DỤNG thuần: byte server SAU flight-2 của client (Finished+GET).
        # Nếu lấy cả kết nối thì số packet/byte sẽ chứa luôn packet bắt tay → rò rỉ nhãn KEM.
        app = sd[sd.time > t_cl2]
        cs = dat.tcplen.values; ss = app.tcplen.values
        def pad(a, k):
            a = np.asarray(a, float)[:k]; return np.pad(a, (0, k-len(a)))
        iat = np.diff(app.time.values) if len(app) > 1 else np.array([0.0])
        rows.append(dict(
            stream=st, site=meta.site.values[k], group=meta.group.values[k], t_syn=t_syn,
            # tổng byte cả kết nối (chứa bắt tay) — nhóm "kích thước, tầm thường"
            srv_total=float(srv.tcplen.sum()), cli_total=float(cli.tcplen.sum()),
            # pha ứng dụng thuần
            app_srv_bytes=float(app.tcplen.sum()),
            n_app_srv_pkts=int(len(app)),
            app_dur=float(app.time.max()-app.time.min()) if len(app) else 0.0,
            mean_iat_app=float(np.mean(iat)) if len(iat) else 0.0,
            **{f"as_{j}": v for j, v in enumerate(pad(ss, K))},
            # pha bắt tay
            cl_ch_bytes=float(dat.tcplen.iloc[0]),
            cl_hs_bytes=float(hs_c.tcplen.sum()), sv_hs_bytes=float(hs_s.tcplen.sum()),
            cl_ch_nseg=int(len(dat[dat.time < t_sv1])),
            n_srv_pkts=int((srv.tcplen > 0).sum()), n_cli_pkts=int((cli.tcplen > 0).sum()),
        ))
    return pd.DataFrame(rows)

SIZE_TOTAL = ["srv_total","cli_total","n_srv_pkts","n_cli_pkts"]
APP_TOTAL = ["app_srv_bytes","n_app_srv_pkts","app_dur","mean_iat_app"]
APP_SEQ = [f"as_{j}" for j in range(K)]
# Họ "bắt tay": CHỈ dùng tổng byte và số segment — KHÔNG dùng `cl_ch_bytes` (kích thước packet
# đầu ở leg ingress), vì GSO của client gộp nó thành một super-packet ở mọi MTU (artifact đã bị
# v3 của rq2b chỉ ra). Tổng byte và số segment không phụ thuộc cách gộp.
HS_FEAT = ["cl_hs_bytes","sv_hs_bytes","cl_ch_nseg"]

def time_split(D, frac=0.6, label="site"):
    """Chia theo THỜI GIAN trong từng lớp: flow sớm → train, flow muộn → test."""
    tr, te = [], []
    for cls, sub in D.groupby(label):
        sub = sub.sort_values("t_syn")
        n = max(1, int(len(sub)*frac))
        tr.append(sub.iloc[:n]); te.append(sub.iloc[n:])
    return pd.concat(tr), pd.concat(te)

def rf(seed=42):
    return RandomForestClassifier(n_estimators=300, random_state=seed, n_jobs=-1)

def ev(train, test, feats, label="site"):
    if train.empty or test.empty: return dict(acc=np.nan, f1=np.nan, n_tr=len(train), n_te=len(test))
    m = rf(); m.fit(train[feats].values, train[label].values)
    p = m.predict(test[feats].values)
    return dict(acc=float(accuracy_score(test[label].values, p)),
                f1=float(f1_score(test[label].values, p, average="macro")),
                n_tr=int(len(train)), n_te=int(len(test)))

def main():
    pkt = f"{BASE}/packets_all.tsv"
    df = load_packets(pkt)
    D = {}
    for mtu, pcap, csv in [(1500, "pcap2_sites_M1500.pcapng", f"{LAB}/results/sites2_M1500.csv"),
                           (1280, "pcap2_sites_M1280.pcapng", f"{LAB}/results/sites2_M1280.csv")]:
        if os.path.exists(csv) and pcap in set(df.pcap.unique()):
            D[mtu] = site_flows(df, pcap, csv)
            D[mtu]["mtu"] = mtu

    out = {"n_flows": {m: int(len(d)) for m, d in D.items()}, "K_seq": K}
    if 1500 not in D:
        json.dump(out, open(f"{BASE}/tables/rq23_summary.json","w"), indent=2)
        print("Chưa có dataset sites M1500 — chỉ ghi thông tin."); return

    A = D[1500]
    tr, te = time_split(A)
    # (0) PHÉP KIỂM TÍNH TẦM THƯỜNG: 1-NN trên MỘT đặc trưng (không cần ML)
    triv = {}
    for f in ["srv_total", "app_srv_bytes", "as_0"]:
        nn = KNeighborsClassifier(1).fit(tr[[f]].values, tr["site"].values)
        triv[f] = float(accuracy_score(te["site"].values, nn.predict(te[[f]].values)))
    out["triviality_1nn_M1500"] = triv

    # (1) baseline & drift KEM (cùng MTU)
    feats_all = SIZE_TOTAL + APP_TOTAL + APP_SEQ + HS_FEAT
    base = ev(tr, te, feats_all)
    xb = A[A.group == "X25519MLKEM768"]
    tr_b, te_b = time_split(xb)
    drift_kem = ev(tr[tr.group == "X25519"], te_b, feats_all)
    out["rq2_same_mtu"] = dict(baseline_within=base, drift_trainX_testH=drift_kem)

    # (2) DRIFT DO MTU — đổi phân mảnh pha ứng dụng giữa hai MTU
    if 1280 in D:
        B = D[1280]
        trB, teB = time_split(B)
        out["rq2_mtu_drift"] = {
            "train1500_test1280_all": ev(tr, teB, feats_all),
            "train1500_test1280_size_totals": ev(tr, teB, SIZE_TOTAL),
            "train1500_test1280_app_totals": ev(tr, teB, APP_TOTAL),
            "train1500_test1280_app_seq": ev(tr, teB, APP_SEQ),
            "train1500_test1280_handshake": ev(tr, teB, HS_FEAT),
            "within1280_all": ev(trB, teB, feats_all),
            "within1280_app_totals": ev(trB, teB, APP_TOTAL),
            "within1280_app_seq": ev(trB, teB, APP_SEQ),
            "within1280_handshake": ev(trB, teB, HS_FEAT),
        }
        # (3) THÍCH ỨNG: thêm k flow MTU 1280 / lớp vào tập train
        curve = []
        for k in (1, 3, 5, 10, 20):
            accs = {"all": [], "app_seq": [], "app_totals": []}
            for draw in range(10):
                pick = []
                for cls, sub in B.groupby("site"):
                    idx = sub.sort_values("t_syn").index.values
                    pick.extend(RNG.choice(idx, size=min(k, len(idx)), replace=False))
                add = B.loc[pick]
                rest = B.drop(index=pick)
                if rest.empty: continue
                _, te_rest = time_split(rest)
                if te_rest is None or te_rest.empty: continue
                for name, fl in (("all", feats_all), ("app_seq", APP_SEQ), ("app_totals", APP_TOTAL)):
                    m = rf(); m.fit(pd.concat([tr, add])[fl].values, pd.concat([tr, add])["site"].values)
                    accs[name].append(float(accuracy_score(te_rest["site"].values, m.predict(te_rest[fl].values))))
            curve.append(dict(k=k, **{n: (float(np.mean(v)) if v else np.nan) for n, v in accs.items()}))
        out["rq3_adaptation_mtu_drift"] = curve

    # (4) RANH GIỚI QUAN SÁT: họ đặc trưng nào nhìn thấy đổi giao thức KEM?
    # Nhãn = nhóm KEM; mỗi họ đặc trưng phân loại độc lập. Kỳ vọng: bắt tay → 1.0,
    # pha ứng dụng → ~0.5 (không thấy gì), tổng byte cả kết nối → ~0.5.
    G = pd.concat([d.drop(columns=["site"]) for d in D.values()])
    trp, tep = time_split(G, label="group")
    proto = {}
    for name, fl in (("handshake_only", HS_FEAT), ("app_totals_only", APP_TOTAL),
                     ("app_seq_only", APP_SEQ), ("size_totals_incl_hs", SIZE_TOTAL)):
        m = rf(); m.fit(trp[fl].values, trp["group"].values)
        proto[name] = float(accuracy_score(tep["group"].values, m.predict(tep[fl].values)))
    out["protocol_visibility_kem_group"] = proto

    json.dump(out, open(f"{BASE}/tables/rq23_summary.json","w"), indent=2)
    print(json.dumps(out, indent=2))

    # ---- Hình 4 ----
    fig, axes = plt.subplots(1, 2, figsize=(11,4))
    ax = axes[0]
    if "rq2_mtu_drift" in out:
        d = out["rq2_mtu_drift"]
        labels = ["trong MTU 1280\n(tất cả ĐT)", "1500→1280\n(tất cả ĐT)",
                  "…tổng byte", "…tổng pha ứng dụng", "…chuỗi gói ứng dụng", "…bắt tay"]
        vals = [d["within1280_all"]["acc"], d["train1500_test1280_all"]["acc"],
                d["train1500_test1280_size_totals"]["acc"], d["train1500_test1280_app_totals"]["acc"],
                d["train1500_test1280_app_seq"]["acc"], d["train1500_test1280_handshake"]["acc"]]
        ax.bar(range(len(vals)), vals, color=["#0072B2","#D55E00","#009E73","#56B4E9","#CC79A7","#999999"])
        ax.set_xticks(range(len(vals)), labels, fontsize=7, rotation=20, ha="right")
        ax.axhline(1/6, ls=":", color="k", lw=1); ax.text(0.02, 1/6+0.02, "ngẫu nhiên (1/6)", fontsize=7)
        ax.set_ylim(0,1.05); ax.set_ylabel("Accuracy (6 lớp site)")
        ax.set_title("RQ2: drift do ĐỔI MTU (1500→1280)"); ax.grid(alpha=.3, axis="y")
    ax = axes[1]
    if "rq3_adaptation_mtu_drift" in out:
        c = out["rq3_adaptation_mtu_drift"]
        ks = [d["k"] for d in c]
        for name, col, lab in (("all","#0072B2","tất cả đặc trưng"),("app_seq","#CC79A7","chuỗi gói ứng dụng"),("app_totals","#009E73","tổng pha ứng dụng")):
            ax.plot(ks, [d[name] for d in c], marker="o", color=col, label=lab)
        ax.set_xscale("log"); ax.set_xlabel("Số flow MTU 1280/lớp thêm vào train")
        ax.set_ylabel("Accuracy trên test MTU 1280"); ax.set_ylim(0,1.05)
        ax.set_title("RQ3: chi phí thích ứng khi đổi MTU"); ax.legend(fontsize=8); ax.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(f"{BASE}/figs/fig4_drift_adaptation.png"); plt.close(fig)
    print("[FIG] fig4_drift_adaptation.png ; [TABLE] rq23_summary.json")

if __name__ == "__main__":
    main()
