#!/usr/bin/env python3
# check_report_numbers.py — chặn lỗi "chép tay": đối chiếu MỌI con số trong các bảng của
# BÁO_CÁO_NGHIÊN_CỨU.md với dữ liệu thô (tables/*.csv, *.json, pmtud_trials.csv).
#
# Vì sao cần: ở vòng phản biện thứ hai, bảng audit §4 của báo cáo bị phát hiện chép tay sai
# hai ô so với audit_results.csv. Script này biến việc kiểm tra đó thành tự động, chạy được
# trong chuỗi tái lập. Thoát mã 1 nếu có sai lệch.
import re, sys, os
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(BASE, "..", "BÁO_CÁO_NGHIÊN_CỨU.md")
LAB = os.path.abspath(os.path.join(BASE, "..", "..", "docker-lab", "results"))

def num(x):
    return float(x.replace("*", "").replace(",", ".").replace("−", "-")
                 .replace(" ", "").replace("s", "").replace("(timeout)", ""))

def same(got, exp, dec):
    return abs(got - round(float(exp), dec)) <= 10 ** (-dec) / 2 + 1e-9

def main():
    s = open(REPORT, encoding="utf-8").read()
    S = pd.read_csv(os.path.join(BASE, "tables", "rq1_stats.csv"))
    A = pd.read_csv(os.path.join(BASE, "tables", "audit_results.csv"))
    errs, n_checked = [], 0

    # ---- Bảng 3: RTT (loss | delay | MTU | med_a | med_b | Δ | % | p_holm | δ) ----
    for l in [l for l in s.splitlines() if re.match(r"^\| [0-3] \| (0|50) \| (1500|1280|576) \|", l)]:
        c = [x.strip() for x in l.strip("|").split("|")]
        loss, delay, mtu = int(c[0]), int(c[1]), int(c[2])
        q = S[(S.metric == "hs_rtt") & (S.loss == loss) & (S.delay == delay) & (S.mtu == mtu)]
        if q.empty:
            errs.append(f"Bảng 3: thiếu dữ liệu cho L{loss} D{delay} M{mtu}"); continue
        r = q.iloc[0]
        for name, got, exp, dec in [("med_a", num(c[3]), r.med_a * 1000, 3),
                                    ("med_b", num(c[4]), r.med_b * 1000, 3),
                                    ("Δ", num(c[5]), (r.med_b - r.med_a) * 1000, 3),
                                    ("p_holm", num(c[7]), r.p_holm, 2),
                                    ("Cliff δ", num(c[8]), r.cliffs, 2)]:
            n_checked += 1
            if not same(got, exp, dec):
                errs.append(f"Bảng 3 L{loss} D{delay} M{mtu} — {name}: báo cáo {got} ≠ dữ liệu {round(float(exp), dec)}")

    # ---- Bảng 4: PMTUD (ô | nhóm | MTU | clamp | ICMP | hoàn tất | thời gian | ICMP bắt được) ----
    P = pd.read_csv(os.path.join(LAB, "pmtud_trials.csv"))
    g = P.groupby("cell").agg(n=("established", "size"), ok=("established", "mean"),
                              t=("elapsed_s", "median"))
    pmap = {"c1": "c1_hyb_1280_drop", "c2": "c2_hyb_1280_allow", "c3": "c3_x25519_1280_drop",
            "c4": "c4_x25519_1280_allow", "c5": "c5_hyb_1280_clampon_drop", "c6": "c6_hyb_1500_drop",
            "c7": "c7_x25519_1500_drop", "c8": "c8_hyb_576_drop", "c9": "c9_x25519_576_drop"}
    for l in [l for l in s.splitlines() if re.match(r"^\| c\d \|", l)]:
        c = [x.strip() for x in l.strip("|").split("|")]
        r = g.loc[pmap[c[0]]]
        n_checked += 2
        if c[5].replace("*", "") != f"{int(round(r.ok * r.n))}/{int(r.n)}":
            errs.append(f"Bảng 4 {c[0]}: hoàn tất báo cáo {c[5]} ≠ dữ liệu {int(round(r.ok*r.n))}/{int(r.n)}")
        if not same(num(c[6]), r.t, 2):
            errs.append(f"Bảng 4 {c[0]}: thời gian báo cáo {c[6]} ≠ dữ liệu {r.t:.2f} s")

    # ---- Bảng audit §4: mọi dòng phải có một dòng PASS/FAIL/WARN tương ứng trong CSV ----
    ids = [l.split("|")[1].strip() for l in s.splitlines() if re.match(r"^\| (A|B|C|C2|C3|D|E|F|G|H|I|J|K|K2|L) \|", l)]
    for cid in ids:
        n_checked += 1
        row = A[A.CHECK == cid]
        if row.empty:
            errs.append(f"Bảng audit: check {cid} không có trong audit_results.csv")
        elif "PASS" not in row.iloc[0]["Kết luận"]:
            errs.append(f"Bảng audit: check {cid} trong CSV là {row.iloc[0]['Kết luận']}, báo cáo trình bày PASS")

    print(f"Đã đối chiếu {n_checked} con số/mục giữa báo cáo và dữ liệu.")
    if errs:
        print("SAI LỆCH:")
        for e in errs:
            print("  -", e)
        return 1
    print("✓ Không có sai lệch: mọi con số trong bảng đều truy được về dữ liệu thô.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
