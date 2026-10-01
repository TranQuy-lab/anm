#!/usr/bin/env python3
# rq2b_group_classifier.py — quan sát viên thụ động có tách được client "PQC-capable" không?
#
# PHIÊN BẢN 2 (sau kiểm chứng chéo). Sửa ba vấn đề của bản 1:
#   (1) SỐ LIỆU SAI: bản 1 ghi đặc trưng "kích thước packet đầu client" là 297/1473, nhưng
#       giá trị thật là 217/1393 (297/1473 là TOÀN BỘ flight client). Bản 2 tách bạch hai
#       mức quan sát: (a) một packet, (b) tổng byte cả flight.
#   (2) TÍNH TẦM THƯỜNG: kích thước ClientHello do giao thức quy định (ML-KEM-768 ek = 1184 B),
#       nên "accuracy 100%" không phải phát hiện. Bản 2 trình bày nó như một ĐỊNH NGHĨA kèm
#       phép kiểm ngưỡng không cần ML, và định vị so với tiền lệ đã công bố.
#   (3) CHƯA KIỂM BỀN: bản 1 chỉ đo ở MTU 1500. Bản 2 đo ở MTU 1500/1280/576 để chỉ ra
#       đặc trưng "một packet" phụ thuộc MTU còn "tổng byte flow" thì bất biến.
import json, os
import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
R = pd.read_csv(f"{BASE}/tables/rq1_flows.csv")

def acc_threshold(vals, groups, thr, pos="X25519MLKEM768"):
    pred = np.where(vals > thr, pos, "X25519")
    return float((pred == groups).mean())

out = {"n_flows": int(len(R)), "by_mtu": {}}
for mtu, sub in R.groupby("mtu"):
    a = sub[sub.group == "X25519"]; b = sub[sub.group == "X25519MLKEM768"]
    rec = {
        "n_X25519": int(len(a)), "n_MLKEM768": int(len(b)),
        "first_pkt_median_X": float(a.cl_ch_bytes.median()),
        "first_pkt_median_PQC": float(b.cl_ch_bytes.median()),
        "client_flight_bytes_median_X": float(a.cl_hs_novel_bytes.median()),
        "client_flight_bytes_median_PQC": float(b.cl_hs_novel_bytes.median()),
        "server_flight_bytes_median_X": float(a.sv_hs_bytes.median()),
        "server_flight_bytes_median_PQC": float(b.sv_hs_bytes.median()),
        "ch_segments_median_X": float(a.wire_cl_nseg.median()),
        "ch_segments_median_PQC": float(b.wire_cl_nseg.median()),
    }
    # ngưỡng cố định 800 B học từ MTU 1500, áp cho mọi MTU (không dùng ML)
    v1 = sub.cl_ch_bytes.values; v2 = sub.cl_hs_novel_bytes.values; g = sub.group.values
    rec["threshold_800_first_pkt_acc"] = acc_threshold(v1, g, 800)
    rec["threshold_800_client_flight_acc"] = acc_threshold(v2, g, 800)
    out["by_mtu"][int(mtu)] = rec

# tính bất biến theo MTU của hai mức quan sát
if len(out["by_mtu"]):
    fp = {m: (r["first_pkt_median_X"], r["first_pkt_median_PQC"]) for m, r in out["by_mtu"].items()}
    ft = {m: (r["client_flight_bytes_median_X"], r["client_flight_bytes_median_PQC"]) for m, r in out["by_mtu"].items()}
    out["mtu_invariance"] = {
        "first_packet_sizes_by_mtu": fp,
        "client_flight_bytes_by_mtu": ft,
        "first_packet_invariant": len({v for v in fp.values()}) == 1,
        "client_flight_invariant": len({v for v in ft.values()}) == 1,
    }
out["prior_art_note"] = (
    "Việc quan sát thụ động phân biệt được cổ điển vs hậu lượng tử ĐÃ được công bố: "
    "arXiv:2503.17830 (Mallick et al., 2025/2026, 98-100% cho nhiều giao thức, có cả TLS/QUIC), "
    "IACR ePrint 2026/834 (đọc key_share ServerHello, 38 endpoint thật), "
    "arXiv:2608.22683 (đo drift trace khi bật X25519MLKEM768). "
    "Đóng góp ở đây KHÔNG phải tính mới của khả năng fingerprint, mà là: (i) định lượng đặc trưng "
    "tối thiểu cần thiết, (ii) kiểm bền theo MTU/phân mảnh."
)
json.dump(out, open(f"{BASE}/tables/rq2b_summary.json", "w"), indent=2, ensure_ascii=False)
print(json.dumps(out, indent=2, ensure_ascii=False))
print("[TABLE] rq2b_summary.json")
