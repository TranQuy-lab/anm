#!/usr/bin/env python3
# rq2b_group_classifier.py — Mặt kia của drift: PQC tạo ra tín hiệu fingerprint TRỰC TIẾP.
# Câu hỏi: quan sát viên trên đường truyền có phân loại được "client có hỗ trợ hybrid PQC không"
#          chỉ từ metadata flow (không giải mã)? Đây là rủi ro riêng tư mới trong giai đoạn chuyển đổi.
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold

BASE = __file__.rsplit("/", 1)[0]
K = 20

df = pd.read_csv(f"{BASE}/packets_all.tsv", sep="\t")
df.columns = ["pcap","stream","time","src","tcplen","seq","ack","retrans","syn","fin","rst"]
BOOL_MAP = {"True":1,"False":0,"true":1,"false":0}
for c in ("retrans","syn","fin","rst"):
    df[c] = pd.to_numeric(df[c].replace(BOOL_MAP), errors="coerce").fillna(0).astype(int)
for c in ("time","tcplen","seq","ack"):
    df[c] = pd.to_numeric(df[c], errors="coerce")

def flows(pcap):
    out = []
    for (pc, st), s in df[df.pcap == pcap].groupby(["pcap","stream"]):
        s = s.sort_values("time")
        syn_src = s.loc[s["syn"] == 1, "src"]
        if syn_src.empty: continue
        cli_ip = syn_src.iloc[0]
        if not str(cli_ip).startswith("172.30.10."): continue
        cli = s[s["src"] == cli_ip]; srv = s[s["src"] != cli_ip]
        d = cli[cli["tcplen"] > 0]
        if d.empty: continue
        t_ch = d["time"].min()
        sd = srv[srv["tcplen"] > 0]
        t_sv1 = sd["time"].min() if len(sd) else np.nan
        d2 = d[d["time"] > t_sv1] if not np.isnan(t_sv1) else d.iloc[0:0]
        if d2.empty: continue
        t_cl2 = d2["time"].min()
        win_c = cli[(cli["time"] >= t_ch) & (cli["time"] <= t_cl2)]
        win_s = srv[(srv["time"] >= t_ch) & (srv["time"] <= t_cl2)]
        def pad(a, k):
            a = np.asarray(a, float)[:k]
            return np.pad(a, (0, k - len(a)))
        out.append({
            "first_client_pkt": float(d["tcplen"].iloc[0]),
            "first_server_pkt": float(sd["tcplen"].iloc[0]) if len(sd) else 0.0,
            "cl_hs_bytes": float(win_c["tcplen"].sum()),
            "sv_hs_bytes": float(win_s["tcplen"].sum()),
            **{f"cs_{j}": v for j, v in enumerate(pad(cli["tcplen"].values, 4))},
        })
    return pd.DataFrame(out)

A = flows("pcap_X25519_L0_D0_M1500.pcapng"); A["label"] = "X25519"
B = flows("pcap_X25519MLKEM768_L0_D0_M1500.pcapng"); B["label"] = "X25519MLKEM768"
D = pd.concat([A, B], ignore_index=True)
feat = [c for c in D.columns if c != "label"]

# (1) Chỉ dùng kích thước gói đầu tiên client gửi (siêu tối giản, không payload)
for fsel, name in [(["first_client_pkt"], "1 đặc trưng: kích thước packet đầu client"),
                   (["first_client_pkt","first_server_pkt","cl_hs_bytes","sv_hs_bytes"], "4 đặc trưng handshake"),
                   (feat, "toàn bộ đặc trưng flow")]:
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    cv = StratifiedKFold(5, shuffle=True, random_state=42)
    acc = cross_val_score(clf, D[fsel].values, D["label"].values, cv=cv)
    print(f"[{name}] accuracy = {acc.mean():.4f} ± {acc.std():.4f}")

out = {"n_flows": int(len(D)),
       "acc_1feat_first_pkt": float(cross_val_score(RandomForestClassifier(200, random_state=42, n_jobs=-1),
            D[["first_client_pkt"]].values, D["label"].values,
            cv=StratifiedKFold(5, shuffle=True, random_state=42)).mean())}
json.dump(out, open(f"{BASE}/tables/rq2b_summary.json", "w"), indent=2)
print("[TABLE] rq2b_summary.json")
