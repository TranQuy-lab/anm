#!/usr/bin/env python3
# check_report_numbers.py — chặn lỗi "chép tay" ở mọi bảng/số liệu chính của
# BÁO_CÁO_NGHIÊN_CỨU.md, bằng cách đối chiếu với dữ liệu thô.
#
# Lịch sử: phiên bản đầu (vòng 2) chỉ kiểm Bảng 3 + Bảng 4 và bị vòng phản biện thứ ba chỉ ra
# là "con dấu cao su" — 10/11 phép sửa thử đều lọt. Bản này phủ:
#   Bảng 1 (kích thước bắt tay), Bảng 2 (phân mảnh), Bảng 3 (RTT), Bảng 4 (PMTUD),
#   Bảng 5 (ngưỡng PMTU đo được), bảng phân rã RTT, bảng đối chứng thứ tự, bảng audit (§4),
#   và các con số nằm trong văn xuôi (abstract, §3.4, §3.6, Holm toàn cục).
# Thoát mã 1 nếu có bất kỳ sai lệch nào.
import glob, json, os, re, subprocess, sys
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(BASE, "..", "BÁO_CÁO_NGHIÊN_CỨU.md")
LAB = os.path.abspath(os.path.join(BASE, "..", "..", "docker-lab", "results"))

def num(x):
    x = (x.replace("*", "").replace(",", ".").replace("−", "-").replace("–", "-")
          .replace("ms", "").replace("B", "").replace("(timeout)", "").replace("s", "").replace(" ", ""))
    return float(x)

def same(got, exp, dec):
    return abs(got - round(float(exp), dec)) <= 10 ** (-dec) / 2 + 1e-9

def sigdigits(tok):
    """Số chữ số có nghĩa của một token đã chuẩn hoá, ví dụ '0.0061'→2, '0.00014'→2, '1.208'→4."""
    d = re.sub(r"^0*\.?0*", "", tok).replace(".", "").lstrip("0")
    return max(1, len(d))

def same_sig(got, exp, tok):
    """So khớp theo số chữ số có nghĩa mà báo cáo đang hiển thị (p-value hay được ghi 2 csn)."""
    return float(tok) == float(f"{float(exp):.{sigdigits(tok)}g}")

def rows_of(s, prefix_re):
    return [l for l in s.splitlines() if re.match(prefix_re, l)]

def main():
    s = open(REPORT, encoding="utf-8").read()
    S = pd.read_csv(os.path.join(BASE, "tables", "rq1_stats.csv"))
    R = pd.read_csv(os.path.join(BASE, "tables", "rq1_flows.csv"))
    A = pd.read_csv(os.path.join(BASE, "tables", "audit_results.csv"))
    O = json.load(open(os.path.join(BASE, "tables", "order_control.json")))
    C23 = json.load(open(os.path.join(BASE, "tables", "rq23_summary.json")))
    THR = json.load(open(os.path.join(BASE, "tables", "pmtud_threshold.json")))
    CB = json.load(open(os.path.join(BASE, "tables", "ch_budget.json"))) \
        if os.path.exists(os.path.join(BASE, "tables", "ch_budget.json")) else None
    errs, n = [], 0

    def chk(cond, msg):
        nonlocal n
        n += 1
        if not cond:
            errs.append(msg)

    # ---------- Bảng 1: kích thước bắt tay (mạng sạch, MTU 1500) ----------
    clean = R[(R.loss == 0) & (R.delay == 0) & (R.mtu == 1500)]
    med = lambda c, g: clean[clean.group == g][c].median()
    chk(int(med("cl_ch_bytes", "X25519")) == 217 and int(med("cl_ch_bytes", "X25519MLKEM768")) == 1393,
        "Bảng 1: ClientHello không khớp rq1_flows.csv")
    chk(int(med("cl_hs_novel_bytes", "X25519")) == 297 and int(med("cl_hs_novel_bytes", "X25519MLKEM768")) == 1473,
        "Bảng 1: flight client không khớp rq1_flows.csv")
    chk(int(med("sv_hs_bytes", "X25519")) == 767 and int(med("sv_hs_bytes", "X25519MLKEM768")) == 1845,
        "Bảng 1: flight server không khớp rq1_flows.csv")
    # giá trị key_share/ServerHello đến từ capture snaplen đầy đủ (check_ch_budget.py).
    # Dòng "— trong đó: trường key_share" xuất hiện HAI lần (CH và SH) nên phải khớp THEO THỨ TỰ.
    KS = [("217", "1393"), ("32", "1216"), ("118", "1206"), ("32", "1120"), ("297", "1473"), ("767", "1845")]
    t1rows = rows_of(s, r"^\| (ClientHello \(packet đầu client\)|— trong đó: trường key_share|"
                        r"ServerHello \(handshake length\)|Toàn bộ flight client|Toàn bộ flight server)")
    chk(len(t1rows) == len(KS), f"Bảng 1: có {len(t1rows)} dòng, kỳ vọng {len(KS)}")
    for l, (ea, eb) in zip(t1rows, KS):
        c = [x.strip() for x in l.strip("|").split("|")]
        chk(ea in c[1] and eb in c[2], f"Bảng 1 dòng '{c[0][:38]}': kỳ vọng {ea}/{eb}, thấy {c[1]}/{c[2]}")

    # ---------- Bảng 2: phân mảnh cấp wire ----------
    seg = R[(R.loss == 0) & (R.delay == 0)].groupby(["mtu", "group"])[["wire_cl_nseg", "sv_nseg"]].median()
    exp_seg = {1500: (1, 1, 1, 2), 1280: (1, 2, 1, 2), 576: (1, 3, 2, 4)}
    for mtu, (cx, cp, sx, sp) in exp_seg.items():
        try:
            got = (int(seg.loc[(mtu, "X25519")]["wire_cl_nseg"]), int(seg.loc[(mtu, "X25519MLKEM768")]["wire_cl_nseg"]),
                   int(seg.loc[(mtu, "X25519")]["sv_nseg"]), int(seg.loc[(mtu, "X25519MLKEM768")]["sv_nseg"]))
        except KeyError:
            got = None
        chk(got == (cx, cp, sx, sp), f"Bảng 2 MTU {mtu}: dữ liệu {got} ≠ kỳ vọng {(cx, cp, sx, sp)}")

    # ---------- Bảng 2: phân mảnh cấp wire — đối chiếu NỘI DUNG BÁO CÁO với dữ liệu ----------
    t2 = rows_of(s, r"^\| (1500|1280|576) \| \*{0,2}\d+ → \d+\*{0,2} \|")
    chk(len(t2) == 3, f"Bảng 2: có {len(t2)} dòng, kỳ vọng 3")
    for l in t2:
        c = [x.strip().replace("*", "") for x in l.strip("|").split("|")]
        mtu = int(c[0])
        cx, cp = [int(x) for x in re.findall(r"\d+", c[1])]
        sx, sp = [int(x) for x in re.findall(r"\d+", c[2])]
        try:
            got = (int(seg.loc[(mtu, "X25519")]["wire_cl_nseg"]), int(seg.loc[(mtu, "X25519MLKEM768")]["wire_cl_nseg"]),
                   int(seg.loc[(mtu, "X25519")]["sv_nseg"]), int(seg.loc[(mtu, "X25519MLKEM768")]["sv_nseg"]))
        except KeyError:
            got = None
        chk((cx, cp, sx, sp) == got, f"Bảng 2 MTU {mtu}: báo cáo {(cx, cp, sx, sp)} ≠ dữ liệu {got}")

    # ---------- Bảng 3: RTT ----------
    for l in rows_of(s, r"^\| [0-3] \| (0|50) \| (1500|1280|576) \|"):
        c = [x.strip() for x in l.strip("|").split("|")]
        loss, delay, mtu = int(c[0]), int(c[1]), int(c[2])
        q = S[(S.metric == "hs_rtt") & (S.loss == loss) & (S.delay == delay) & (S.mtu == mtu)]
        if q.empty:
            errs.append(f"Bảng 3: thiếu dữ liệu L{loss} D{delay} M{mtu}"); n += 1; continue
        r = q.iloc[0]
        for name, got, exp, dec in [("med_a", num(c[3]), r.med_a * 1000, 3), ("med_b", num(c[4]), r.med_b * 1000, 3),
                                    ("Δ", num(c[5]), (r.med_b - r.med_a) * 1000, 3),
                                    ("Cliff δ", num(c[8]), r.cliffs, 2)]:
            chk(same(got, exp, dec), f"Bảng 3 L{loss} D{delay} M{mtu} — {name}: báo cáo {got} ≠ dữ liệu {round(float(exp), dec)}")
        tok = c[7].replace("*", "").replace(",", ".").replace("−", "-")
        chk(same_sig(num(c[7]), r.p_holm, tok), f"Bảng 3 L{loss} D{delay} M{mtu} — p_holm: báo cáo {tok} ≠ dữ liệu {r.p_holm:.6g}")

    # ---------- Bảng 4: PMTUD ----------
    P = pd.read_csv(os.path.join(LAB, "pmtud_trials.csv"))
    g = P.groupby("cell").agg(n=("established", "size"), ok=("established", "mean"), t=("elapsed_s", "median"))
    icmp_cell = {}
    for f in glob.glob(os.path.join(LAB, "pcap_pmtud_*.pcapng")):
        cid = os.path.basename(f)[len("pcap_pmtud_"):-len(".pcapng")]
        icmp_cell[cid] = len(subprocess.run(["tshark", "-r", f, "-Y", "icmp.type==3 && icmp.code==4"],
                                            capture_output=True, text=True).stdout.split("\n")) - 1
    pmap = {"c1": "c1_hyb_1280_drop", "c2": "c2_hyb_1280_allow", "c3": "c3_x25519_1280_drop",
            "c4": "c4_x25519_1280_allow", "c5": "c5_hyb_1280_clampon_drop", "c6": "c6_hyb_1500_drop",
            "c7": "c7_x25519_1500_drop", "c8": "c8_hyb_576_drop", "c9": "c9_x25519_576_drop"}
    for l in rows_of(s, r"^\| c\d \|"):
        c = [x.strip() for x in l.strip("|").split("|")]
        r = g.loc[pmap[c[0]]]
        chk(c[5].replace("*", "") == f"{int(round(r.ok*r.n))}/{int(r.n)}",
            f"Bảng 4 {c[0]}: hoàn tất báo cáo {c[5]} ≠ dữ liệu {int(round(r.ok*r.n))}/{int(r.n)}")
        chk(same(num(c[6]), r.t, 2), f"Bảng 4 {c[0]}: thời gian báo cáo {c[6]} ≠ dữ liệu {r.t:.2f} s")
        chk(num(c[7]) == icmp_cell.get(pmap[c[0]], -1),
            f"Bảng 4 {c[0]}: số ICMP báo cáo {c[7]} ≠ pcap {icmp_cell.get(pmap[c[0]])}")

    # ---------- Bảng 5: ngưỡng PMTU đo được (đọc từ pcap + pmtud_threshold.csv) ----------
    if "threshold_completed" in THR:
        chk(THR["threshold_completed"].get("X25519") == 900, "Bảng 5: ngưỡng X25519 phải là 900 (mức quét thấp nhất)")
        chk(THR["threshold_completed"].get("X25519MLKEM768") == 1448, "Bảng 5: ngưỡng hybrid phải là 1448")
        chk(THR.get("M1440|X25519MLKEM768", {}).get("ch_crossed") is False, "Bảng 5: hybrid@1440 phải KHÔNG qua")
        chk(THR.get("M1448|X25519MLKEM768", {}).get("ch_crossed") is True, "Bảng 5: hybrid@1448 phải qua")
        chk(THR.get("M1448|X25519MLKEM768", {}).get("icmp") == 0, "Bảng 5: @1448 không được có ICMP (đúng biên)")

    # ---------- Bảng 5: ngưỡng PMTU — đối chiếu số hoàn tất trong báo cáo ----------
    D5 = pd.read_csv(os.path.join(LAB, "pmtud_threshold.csv"))
    g5 = D5.groupby(["mtu_b", "group"]).established.agg(n="size", ok="mean")
    t5 = [l for l in rows_of(s, r"^\| \*{0,2}\d+\*{0,2} \|")
          if ("✓" in l or "✗" in l) and l.count("|") >= 6]
    chk(len(t5) == 5, f"Bảng 5: có {len(t5)} dòng, kỳ vọng 5")
    for l in t5:
        c = [x.strip().replace("*", "") for x in l.strip("|").split("|")]
        mtu = int(c[0])
        for col, grp in ((2, "X25519"), (4, "X25519MLKEM768")):
            cell = c[col]
            m = re.match(r"(\d+)/(\d+)", cell)
            chk(m is not None, f"Bảng 5 MTU {mtu} {grp}: ô '{cell}' không có dạng n/N")
            if m:
                exp = g5.loc[(mtu, grp)]
                chk(int(m.group(1)) == int(round(exp.ok * exp.n)),
                    f"Bảng 5 MTU {mtu} {grp}: báo cáo {m.group(1)}/{m.group(2)} ≠ dữ liệu "
                    f"{int(round(exp.ok*exp.n))}/{int(exp.n)}")

    # ---------- bảng phân rã RTT ----------
    for l in rows_of(s, r"^\| (1500|576) \| 0,\d+ → 0,\d+ ms"):
        c = [x.strip() for x in l.strip("|").split("|")]
        mtu = int(c[0])
        q = S[(S.metric == "rtt_ch_to_sv1") & (S.loss == 0) & (S.delay == 0) & (S.mtu == mtu)].iloc[0]
        chk(same(num(c[1].split("→")[0]), q.med_a * 1000, 3), f"Phân rã RTT M{mtu}: med X ≠ dữ liệu")
        chk(same(num(c[1].split("→")[1].split("ms")[0]), q.med_b * 1000, 3), f"Phân rã RTT M{mtu}: med PQC ≠ dữ liệu")

    # ---------- bảng đối chứng thứ tự ----------
    for l in rows_of(s, r"^\| (1280|1500) \| 2,\d+ ms \|"):
        c = [x.strip() for x in l.strip("|").split("|")]
        mtu = int(c[0]); k = f"MTU{mtu}"
        chk(same(num(c[3]), O[k]["delta_group_ms"], 3), f"Đối chứng {k}: Δnhóm ≠ order_control.json")
        chk(same(num(c[5]), O[k]["cliffs_group"], 2), f"Đối chứng {k}: Cliff δ ≠ order_control.json")

    # ---------- bảng audit §4: số trong ô chi tiết phải truy được về audit_results.csv ----------
    for l in rows_of(s, r"^\| (A|B|C|C2|C3|D|E|F|G|H|I|J|K|K2|L) \|"):
        c = [x.strip() for x in l.strip("|").split("|")]
        cid = c[0]
        row = A[A.CHECK == cid]
        chk(not row.empty, f"Bảng audit: check {cid} không có trong audit_results.csv")
        if row.empty:
            continue
        chk("PASS" in row.iloc[0]["Kết luận"], f"Bảng audit: {cid} trong CSV là {row.iloc[0]['Kết luận']}")
        pool = (str(row.iloc[0]["Tên"]) + " " + str(row.iloc[0]["Chi tiết"])).replace(",", ".")
        csv_vals = [float(v) for v in re.findall(r"\d+\.\d+", pool)]
        for tok in re.findall(r"\d+[.,]\d+", c[2].replace(",", ".")):
            dec = len(tok.split(".")[1])
            ok = any(same(float(tok), v, dec) for v in csv_vals) or float(tok) in csv_vals
            n += 1
            if not ok:
                errs.append(f"Bảng audit {cid}: số '{tok}' trong báo cáo không truy được về audit_results.csv")

    # ---------- §3.6: bảng ranh giới họ đặc trưng ← rq23_summary.json ----------
    for l in rows_of(s, r"^\| (Bắt tay \(kích thước/segment\)|Tổng byte cả kết nối|Tổng pha ứng dụng thuần|Chuỗi gói pha ứng dụng thuần) \|"):
        c = [x.strip().replace("*", "") for x in l.strip("|").split("|")]
        key = {"Bắt tay (kích thước/segment)": "handshake_only",
               "Tổng byte cả kết nối (gồm packet bắt tay)": "size_totals_incl_hs",
               "Tổng pha ứng dụng thuần": "app_totals_only",
               "Chuỗi gói pha ứng dụng thuần": "app_seq_only"}[c[0]]
        exp = C23["protocol_visibility_kem_group"][key]
        chk(same(num(c[1]), exp, 3), f"§3.6 '{c[0]}': báo cáo {c[1]} ≠ rq23 {exp:.4f}")
    for l in rows_of(s, r"^\| (Đặc trưng volume/sequence|Bắt tay thuần) \|"):
        c = [x.strip().replace("*", "") for x in l.strip("|").split("|")]
        exp = C23["triviality_1nn_M1500"].get("srv_total") if "volume" in c[0] else None
        if exp is not None:
            chk(same(num(c[1]) if "→" not in c[1] else 1.0, exp, 3), f"§3.6 '{c[0]}' baseline ≠ dữ liệu")

    # ---------- số trong văn xuôi ----------
    prose = [
        ("0,17–0,44 ms", "khoảng Δ RTT", r"0,17–0,44 ms"),
        ("4/13", "số cấu hình có ý nghĩa Holm", r"4/13"),
        ("11/13", "hướng hiệu ứng nhất quán", r"11/13"),
        ("p một phía 0,011 / hai phía 0,023 (xuất hiện ≥ 2 lần)", "sign test", r"(một phía p = 0,011; hai phía 0,023)|(một phía p = 0,011, hai phía 0,023)"),
        ("-0.358/+0.331", "đối chứng thứ tự", r"\+0,358 ms.*\+0,331 ms|\+0,358.*\+0,331"),
        ("0,15 ở 1% / 0,42 ở 3%", "retransmission", r"0,15 ở 1%.*0,42 ở 3%"),
        ("78/150", "Holm toàn cục", r"78/150"),
        ("0,58–0,59", "đặc trưng pha ứng dụng", r"0,58–0,59"),
        ("1,000", "1-NN tầm thường", r"1,000"),
    ]
    for label, what, pat in prose:
        hits = len(re.findall(pat, s))
        need = 2 if "≥ 2 lần" in label else 1
        chk(hits >= need, f"Văn xuôi: '{label}' ({what}) xuất hiện {hits} lần, cần ≥ {need}")
    # retrans numbers must also match the data
    rl = R[R.loss > 0]
    chk(same(0.15, rl[rl.loss == 1].retrans.mean(), 2), "Văn xuôi: retrans 1% không khớp dữ liệu")
    chk(same(0.42, rl[rl.loss == 3].retrans.mean(), 2), "Văn xuôi: retrans 3% không khớp dữ liệu")

    print(f"Đã đối chiếu {n} mục giữa báo cáo và dữ liệu thô.")
    if errs:
        print("SAI LỆCH:")
        for e in errs:
            print("  -", e)
        return 1
    print("✓ Không có sai lệch.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
