# Đo lường tác động mạng của mật mã hậu lượng tử và khả năng nhận dạng lưu lượng mã hóa

Đề tài nghiên cứu thực nghiệm về hệ quả của việc chuyển đổi TLS 1.3 từ trao đổi khóa cổ điển
(**X25519**) sang lai hậu lượng tử (**X25519MLKEM768**, theo FIPS 203) — xét trên hai khía cạnh:
hiệu năng mạng và phân loại lưu lượng mã hóa.

Toàn bộ số liệu trong báo cáo sinh từ thí nghiệm thật trong phòng thí nghiệm cách ly
(780 bắt tay TLS, 720 luồng ứng dụng, 26 cấu hình mạng) và tái lập được 100% bằng script
trong repo này.

---

## 1. Tóm tắt kết quả

| # | Phát hiện | Số liệu |
|---|---|---|
| 1 | Chi phí byte của bắt tay hybrid là thật và lớn | Client **4.96×** (297 → 1473 B); server **2.40×** (768 → 1846 B) |
| 2 | RTT bắt tay gần như không đổi trong mọi kịch bản có PMTUD đúng | Chênh lệch trung vị ≤ 0.25 ms; Cohen's d ≤ 0.28; p > 0.05 sau hiệu chỉnh Holm |
| 3 | Độ tin cậy bắt tay không suy giảm khi xử lý MTU đúng | 0/780 thất bại trên 26 cấu hình (loss 0–3%, delay 0–50 ms, MTU 576–1500) |
| 4 | Rủi ro thực tế nằm ở PMTUD/ICMP: khi ICMP "fragmentation needed" bị chặn và MTU nhỏ, bắt tay hybrid **treo hoàn toàn** | Tái hiện có kiểm soát trong lab |
| 5 | Classifier lưu lượng dùng đặc trưng volume/sequence **kháng** drift giao thức PQC | Accuracy 1.0 → 1.0 (cả MTU 1500 và 1280) |
| 6 | Ranh giới của drift: chỉ các đặc trưng *chạm vào handshake* mới bị ảnh hưởng | Khớp cơ chế với literature (arXiv:2608.22683) |
| 7 | Chuyển đổi PQC tạo tín hiệu fingerprint trực tiếp trên đường truyền | Phân loại nhóm KEM đạt **100% ± 0** chỉ từ 1 đặc trưng (kích thước packet đầu client: 297 B vs 1473 B) |

Kết luận vận hành: **PQC đắt về byte, rẻ về RTT** trên mạng khoẻ; checklist chuyển đổi nên
bao gồm kiểm tra xử lý MTU/ICMP. Trong thập kỷ chuyển đổi, quan sát viên thụ động có thể tách
biệt client "PQC-capable" khỏi client cũ mà không cần giải mã — hệ quả riêng tư mới cần được
đưa vào các thảo luận về traffic analysis.

## 2. Cấu trúc repository

```
.
├── 01-tong-quan-y-van/          Bản đồ tài liệu 2024–2026, 6 khoảng trống nghiên cứu
├── 02-de-xuat-de-tai/           6 đề tài ứng viên, bảng chấm điểm có trọng số
├── 03-kiem-cheo-phan-bien/      Quá trình phản biện đối kháng từng đề tài
├── 04-thiet-ke-nghien-cuu/
│   ├── THIET_KE_NGHIEN_CUU.md   Thiết kế nghiên cứu (giả thuyết, ma trận, tiến độ)
│   ├── BÁO_CÁO_NGHIÊN_CỨU.pdf   Báo cáo hoàn chỉnh (7 trang, 5 hình)
│   ├── BÁO_CÁO_NGHIÊN_CỨU.md    Nguồn của báo cáo
│   └── analysis/
│       ├── extract_metrics.sh        Trích xuất per-packet từ pcap → TSV
│       ├── rq1_analysis.py           Thống kê RQ1 (Wilcoxon paired + Cohen's d + Holm)
│       ├── rq23_analysis.py          Drift + thích ứng classifier (RQ2/RQ3)
│       ├── rq23_m1280.py             Biến thể MTU 1280
│       ├── rq2b_group_classifier.py  Fingerprint nhóm KEM (1 đặc trưng)
│       ├── md2pdf_report.py          Sinh lại PDF báo cáo từ nguồn Markdown
│       ├── tables/                   7 bảng CSV/JSON kết quả
│       └── figs/                     5 hình dùng trong báo cáo
├── 05-ma-hoa-thuat-toan/        Ghi chú nhánh thuật toán/mã hóa
├── 06-lo-hong-network/          Ghi chú nhánh lỗ hổng giao thức (ràng buộc cách ly)
└── docker-lab/                  Phòng thí nghiệm cách ly, tái lập toàn bộ thí nghiệm
    ├── docker-compose.yml       2 mạng internal, router netem, server TLS
    ├── pqc-node/                Dockerfile OpenSSL 3.5 (ML-KEM) + vai trò server/client/router
    ├── run_matrix.sh            Orchestrator ma trận 26 cấu hình × 30 lặp
    ├── run_sites_m1280.sh       Dataset phân loại ở MTU 1280
    ├── www/                     6 "site" ứng dụng (1.5 KB – 1.5 MB)
    └── results/                 CSV client + log vận hành (pcap thô: xem mục 5)
```

## 3. Môi trường yêu cầu

- Docker Engine + Docker Compose (đã kiểm chứng trên Docker 29.7.2, Linux)
- `tshark` ≥ 4.2 (phân tích pcap trên máy chủ)
- Python 3.12 với: `numpy`, `pandas`, `scipy`, `scikit-learn`, `matplotlib`
- Khoảng 2 GB dung lượng (image chứa OpenSSL 3.5 biên dịch từ nguồn)

Không cần privileged mode: mọi thay đổi mạng (netem, DNAT, MSS clamp) nằm gọn trong
container router có `NET_ADMIN`; hai mạng lab đều `internal: true`, không định tuyến ra
Internet.

## 4. Tái lập thí nghiệm

```bash
# 1. Dựng môi trường (build xác thực ML-KEM ngay lúc build — fail sớm nếu thiếu)
cd docker-lab
docker compose build

# 2. Ma trận RQ1: 26 cấu hình × 30 bắt tay (~30–40 phút) + dataset phân loại RQ2/3
bash run_matrix.sh

# 3. Biến thể MTU 1280 cho RQ2
bash run_sites_m1280.sh

# 4. Phân tích
cd ../04-thiet-ke-nghien-cuu/analysis
bash extract_metrics.sh
python rq1_analysis.py            # bảng + 3 hình + Wilcoxon/Holm
python rq23_analysis.py           # drift + thích ứng + hình 4
python rq23_m1280.py              # biến thể MTU 1280
python rq2b_group_classifier.py   # fingerprint nhóm KEM

# 5. Báo cáo (tuỳ chọn, cần reportlab)
python md2pdf_report.py
```

Script orchestrator tự: dò IP theo subnet (không phụ thuộc DNS), đặt `tc netem` với đơn vị
tường minh, clamp MSS để mô phỏng PMTUD hoạt động đúng, health-probe và khởi động lại server
trước mỗi cấu hình, và capture tại router — điểm quan sát trung gian nhìn thấy cả hai phía.

## 5. Dữ liệu

| Dữ liệu | Vị trí | Ghi chú |
|---|---|---|
| CSV thời điểm bắt tay client | `docker-lab/results/hs_*.csv`, `sites_*.csv` | 1.500+ dòng |
| Pcap thô (30 file, ~12 MB) | commit `7717a72` | Đã dọn khỏi working tree (`.gitignore`); khôi phục: `git show 7717a72:<đường-dẫn>` |
| Per-packet TSV (93.663 dòng) | commit `7717a72` | Sinh lại bằng `extract_metrics.sh` |
| Bảng kết quả tổng hợp | `04-thiet-ke-nghien-cuu/analysis/tables/` | 7 file CSV/JSON |
| Biểu đồ | `04-thiet-ke-nghien-cuu/analysis/figs/` | 5 PNG, 150 dpi |

## 6. Phạm vi và hạn chế

- Một máy, liên kết veth, delay ≤ 50 ms — không thay thế đo lường trên Internet thật.
- TSO/GSO trên veth làm che phân mảnh cấp wire; kết luận phân mảnh dựa trên byte-level và
  hiện tượng PMTUD blackhole (định tính có kiểm soát).
- Sáu "site" ứng dụng tổng hợp (kích thước cố định) — dùng để kiểm soát cơ chế, không khái
  quát hóa độ chính xác classifier trên lưu lượng thực.
- n = 30/cấu hình: đủ cho hiệu ứng lớn, không đủ cho hiệu ứng nhỏ (< 0.35).

Chi tiết đầy đủ trong báo cáo, mục "Threats to validity".

## 7. Hướng phát triển

1. **QUIC** (quiche/ngtcp2) — phiên bản UDP của cùng câu hỏi.
2. **Chuỗi chứng chỉ ML-DSA** — tái hiện đầy đủ kịch bản handshake tăng 5×–20×.
3. **Đo lường rộng trên Internet** cho tín hiệu fingerprint nhóm KEM (phát hiện #7).
4. Đề tài kế thừa đã định hình trong `02-de-xuat-de-tai/`: ECH và visibility (T2), fuzzing
   giao thức đa bên trong lab cách ly (T4).

## 8. Tài liệu tham khảo chính

1. NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), 2024; NIST IR 8547.
2. IETF, *Post-Quantum Cryptography for Engineers*, 2025; draft-ietf-tls-hybrid-design.
3. Zhou et al., "Challenges and Advances in Analyzing TLS 1.3-Encrypted Traffic", *Electronics* 13(20), 2024.
4. "The Colossus with Feet of Clay: Debunking Encrypted Traffic Classifiers under PQC Evolution", arXiv:2608.22683, 2026.
5. Sharma et al., "A survey on encrypted network traffic", *Computer Networks*, 2025.
6. Merlach et al., "Encrypted Client Hello Is Coming: A View from Passive Observers", 2025.

---

*Ngày thực nghiệm: 2026-10-01 · Bản lưu trữ dữ liệu thô: commit `7717a72` ·
Repo: [github.com/TranQuy-lab/anm](https://github.com/TranQuy-lab/anm)*
