#!/usr/bin/env python3
# rq2b_group_classifier.py — quan sát viên thụ động có tách được client "PQC-capable" không?
#
# PHIÊN BẢN 3. Lịch sử sửa:
#   v1: ghi sai giá trị đặc trưng (297/1473 thay vì 217/1393) và trình bày "accuracy 100%" như
#       một phát hiện, dù đó là hệ quả định nghĩa của giao thức.
#   v2: tách hai mức quan sát (một packet / toàn flight), đo bền theo MTU.
#   v3 (bản này): sửa một ARTIFACT của chính v2 — "kích thước packet đầu" lấy từ leg INGRESS
#       (client→router) bị GSO của client gộp thành một super-packet 1393 B ở MỌI MTU, nên
#       tuyên bố "bất biến theo MTU" là sai. Trên đường truyền thật (leg egress của router),
#       ClientHello 1393 B bị cắt thành 1393 / 1228 / 524 B ở MTU 1500/1280/576.
#       Đại lượng THẬT SỰ bất biến theo MTU là TỔNG byte của flight, không phải packet đầu.
import json, os
import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
R = pd.read_csv(f"{BASE}/tables/rq1_flows.csv")

def acc_threshold(vals, groups, thr):
    pred = np.where(vals > thr, "X25519MLKEM768", "X25519")
    return float((pred == groups).mean())

out = {"n_flows": int(len(R)), "by_mtu": {}}
for mtu, sub in R.groupby("mtu"):
    a = sub[sub.group == "X25519"]; b = sub[sub.group == "X25519MLKEM768"]
    rec = {
        "n_X25519": int(len(a)), "n_MLKEM768": int(len(b)),
        # (1) leg INGRESS — bị GSO gộp, KHÔNG phản ánh đường truyền
        "ingress_first_pkt_X": float(a.cl_ch_bytes.median()),
        "ingress_first_pkt_PQC": float(b.cl_ch_bytes.median()),
        # (2) leg EGRESS — đường truyền thật
        "egress_first_pkt_X": float(a.wire_cl_first.median()),
        "egress_first_pkt_PQC": float(b.wire_cl_first.median()),
        # (3) tổng byte flight client — bất biến theo MTU
        "client_flight_bytes_X": float(a.cl_hs_novel_bytes.median()),
        "client_flight_bytes_PQC": float(b.cl_hs_novel_bytes.median()),
        "server_flight_bytes_X": float(a.sv_hs_bytes.median()),
        "server_flight_bytes_PQC": float(b.sv_hs_bytes.median()),
        "ch_segments_egress_X": float(a.wire_cl_nseg.median()),
        "ch_segments_egress_PQC": float(b.wire_cl_nseg.median()),
    }
    v, g = sub.wire_cl_first.values, sub.group.values
    rec["threshold_800_egress_first_pkt_acc"] = acc_threshold(v, g, 800)
    rec["threshold_800_client_flight_acc"] = acc_threshold(sub.cl_hs_novel_bytes.values, g, 800)
    out["by_mtu"][int(mtu)] = rec

fp_in = {m: r["ingress_first_pkt_PQC"] for m, r in out["by_mtu"].items()}
fp_eg = {m: r["egress_first_pkt_PQC"] for m, r in out["by_mtu"].items()}
ft = {m: r["client_flight_bytes_PQC"] for m, r in out["by_mtu"].items()}
out["mtu_invariance"] = {
    "ingress_first_packet_by_mtu": fp_in,
    "egress_first_packet_by_mtu": fp_eg,
    "client_flight_bytes_by_mtu": ft,
    "ingress_first_packet_looks_invariant": len(set(fp_in.values())) == 1,
    "egress_first_packet_invariant": len(set(fp_eg.values())) == 1,
    "client_flight_invariant": len(set(ft.values())) == 1,
    "note": ("`ingress_first_packet_looks_invariant = True` là ARTIFACT của GSO trên NIC ảo phía "
             "client (super-packet không bị cắt ở điểm capture), KHÔNG phải tính chất đường truyền. "
             "Đại lượng bất biến thật sự theo MTU là TỔNG byte flight client."),
}
out["prior_art_note"] = (
    "Khả năng quan sát thụ động phân biệt cổ điển vs hậu lượng tử ĐÃ được công bố: "
    "arXiv:2503.17830 (Mallick et al., 98-100% trên nhiều giao thức), IACR ePrint 2026/834 "
    "(đọc key_share ServerHello, 38 endpoint thật), arXiv:2608.22683. Đóng góp ở đây KHÔNG phải "
    "tính mới của khả năng fingerprint, mà là định lượng mức quan sát tối thiểu VÀ chỉ ra rằng "
    "nó phụ thuộc MTU ở mức packet nhưng bất biến ở mức tổng byte."
)
json.dump(out, open(f"{BASE}/tables/rq2b_summary.json", "w"), indent=2, ensure_ascii=False)
print(json.dumps(out, indent=2, ensure_ascii=False))
print("[TABLE] rq2b_summary.json")
