# Chi phí mạng của bắt tay hậu lượng tử và điểm mù PMTUD

Nghiên cứu thực nghiệm về hệ quả của việc chuyển TLS 1.3 từ trao đổi khóa cổ điển (**X25519**)
sang lai hậu lượng tử (**X25519MLKEM768**, FIPS 203) — xét trên ba khía cạnh: ngân sách byte
và phân mảnh, độ tin cậy/độ trễ trên đường truyền xấu, và khả năng nhận dạng lưu lượng.

Toàn bộ số liệu sinh từ thí nghiệm thật trong phòng thí nghiệm cách ly: **780 bắt tay TLS
theo thiết kế xen kẽ A-B-A-B trên 13 cấu hình**, **720 luồng ứng dụng** ở hai MTU, **54 lần
thử PMTUD có kiểm soát**, và tái lập được 100% bằng script trong repo này.

> **Trạng thái:** phiên bản v2, viết lại sau kiểm chứng nội bộ + kiểm chứng chéo độc lập +
> xác minh y văn. Hồ sơ đầy đủ về các sai sót đã phát hiện và cách sửa:
> [`07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md`](07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md).

---

## 1. Tóm tắt kết quả

| # | Phát hiện | Số liệu |
|---|---|---|
| 1 | Chi phí byte khớp **FIPS 203 đến từng byte**, không phải "xấp xỉ" | ClientHello mang key_share **1216 B** = encapsulation key **1184 B** + X25519 32 B; ServerHello mang **1120 B** = ciphertext **1088 B** + X25519 32 B |
| 2 | Chênh lệch *tổng* nhỏ hơn các con số trên vì nhóm lai bỏ một extension | ΔClientHello **+1176 B** (1184 − 8 do bỏ `ec_point_formats`); Δflight server **+1076…1078 B** (1088 − 10 ± dao động chữ ký ECDSA) |
| 3 | **Phân mảnh cấp wire** đo được (sau khi tắt GSO/TSO) | Flight client: **1→2** segment ở MTU 1280, **1→3** ở MTU 576. Flight server: **1→2** ở 1500, **1→2** ở 1280, **2→4** ở 576 |
| 4 | **RTT bắt tay tăng có ý nghĩa** — bản v1 bỏ sót do kiểm định sai thiết kế | Hybrid chậm hơn **0,17–0,40 ms (~15–35%)** trên testbed; hướng hiệu ứng nhất quán **11/13** cấu hình (sign test p = 0,011), **có ý nghĩa sau Holm ở 4/13**; Cliff's δ ≈ 0,5 |
| 5 | **PMTUD blackhole tái hiện có kiểm soát** (đóng góp mới, chưa có tiền lệ) | Hybrid + PMTU 1280 + không clamp + ICMP frag-needed bị lọc: **0/6 hoàn tất** (timeout 8 s); X25519 cùng điều kiện: **6/6**. Chỉ cần cho ICMP qua / bật clamp / MTU 1500 → **6/6** |
| 6 | Bằng chứng nhân quả cho #5 | Capture ghi **6 gói ICMP type 3 code 4** ở nhánh "cho qua", **0** ở nhánh "chặn" |
| 7 | Rủi ro thuộc về *kích thước vượt PMTU*, không phải PQC | Ở PMTU 576, **X25519 cũng hỏng** (0/6) khi ICMP bị lọc |
| 8 | Độ tin cậy không suy giảm khi xử lý MTU đúng | **780/780** lần chạy client `rc=0`; **780/780** flow bắt được và phân tích được |
| 9 | **Ranh giới quan sát** (không tuyên bố tính mới) | Phân loại nhóm KEM: họ đặc trưng **bắt tay = 1,00**, họ đặc trưng **pha ứng dụng = 0,58–0,59** (≈ ngẫu nhiên 0,5) |
| 10 | Fixture phân loại của ta **tầm thường** — báo cáo thẳng | 1-NN trên **một** đặc trưng (tổng byte server) = **1.000**; vì vậy kết quả "kháng drift" không được coi là phát hiện |

Kết luận vận hành: **PQC đắt về byte, và rủi ro thật nằm ở PMTUD/ICMP** — checklist chuyển đổi
nên gồm hai việc cụ thể: **clamp MSS tại biên** và **không lọc ICMP type 3 code 4**.

## 2. Cấu trúc repository

```
.
├── 01-tong-quan-y-van/          Bản đồ tài liệu 2024–2026
├── 02-de-xuat-de-tai/           6 đề tài ứng viên, bảng chấm điểm
├── 03-kiem-cheo-phan-bien/      Phản biện đối kháng từng đề tài
├── 04-thiet-ke-nghien-cuu/
│   ├── BÁO_CÁO_NGHIÊN_CỨU.md    Báo cáo đầy đủ (nguồn)
│   ├── BÁO_CÁO_NGHIÊN_CỨU.pdf   Báo cáo (PDF, sinh từ MD)
│   ├── THIET_KE_NGHIEN_CUU.md   Thiết kế nghiên cứu
│   └── analysis/
│       ├── extract_metrics.sh        pcap → TSV per-packet
│       ├── rq1_analysis.py           RQ1: byte, phân mảnh, RTT (Mann–Whitney + Holm + Cliff's δ)
│       ├── rq23_analysis.py          RQ2/RQ3: drift, thích ứng, ranh giới họ đặc trưng
│       ├── rq2b_group_classifier.py  Quan sát tối thiểu để nhận diện nhóm KEM
│       ├── check_ch_budget.py        Bóc key_share từ capture snaplen đầy đủ
│       ├── audit_kiemdinh.py         Kiểm định chéo tự động (13 hạng mục)
│       ├── md2pdf_report.py          Sinh PDF từ Markdown
│       ├── tables/                   Bảng kết quả (CSV/JSON)
│       └── figs/                     Hình dùng trong báo cáo
├── 05-ma-hoa-thuat-toan/        Ghi chú nhánh mã hóa
├── 06-lo-hong-network/          Ghi chú nhánh lỗ hổng giao thức
├── 07-kiem-chung-doc-lap/       Hồ sơ kiểm chứng & kiểm chứng chéo
└── docker-lab/                  Phòng thí nghiệm cách ly, tái lập toàn bộ
    ├── docker-compose.yml       2 mạng internal, router netem, server TLS
    ├── pqc-node/                Dockerfile OpenSSL 3.5.1 + ethtool; role/hs_loop2/sites_loop2/capture
    ├── run_matrix2.sh           Ma trận 13 cấu hình × 30 cặp XEN KẼ + dataset phân loại
    ├── run_pmtud.sh             Thí nghiệm PMTUD blackhole có kiểm soát
    ├── run_ch_budget.sh         Capture snaplen đầy đủ để đối chiếu FIPS 203
    ├── run_matrix.sh            (v1, lịch sử) ma trận khối tuần tự, capture bị GSO che
    ├── www/                     6 "site" ứng dụng (1.5 KB – 1.5 MB)
    └── results/                 pcap2_*, hs2_*, sites2_*, pmtud_*, archive_gso_capture/
```

## 3. Môi trường yêu cầu

- Docker Engine + Docker Compose (đã kiểm chứng trên Docker 29.7.2, Linux)
- `dumpcap`/`tshark` ≥ 4.2 trên máy chủ (phân tích pcap)
- Python 3.12 với `numpy`, `pandas`, `scipy`, `scikit-learn`, `matplotlib` (và `reportlab` nếu sinh PDF)
- ~4 GB dung lượng (image OpenSSL 3.5.1 biên dịch từ nguồn + pcap)

Không cần privileged mode: mọi thay đổi mạng nằm trong container router (`NET_ADMIN`); hai mạng
lab đều `internal: true`.

## 4. Tái lập thí nghiệm

```bash
cd docker-lab
docker compose build                 # OpenSSL 3.5.1 + ethtool; xác thực ML-KEM ngay lúc build

bash run_matrix2.sh                  # 13 cấu hình × 30 cặp XEN KẼ + 2 dataset phân loại (~10 phút)
bash run_pmtud.sh                    # thí nghiệm PMTUD có kiểm soát (~10 phút)
bash run_ch_budget.sh                # capture snaplen đầy đủ cho ngân sách byte (~1 phút)

cd ../04-thiet-ke-nghien-cuu/analysis
bash extract_metrics.sh              # pcap2_* → packets_all.tsv
python rq1_analysis.py               # byte, phân mảnh cấp wire, RTT + thống kê
python rq23_analysis.py              # drift, thích ứng, ranh giới họ đặc trưng
python rq2b_group_classifier.py      # quan sát tối thiểu để nhận diện nhóm KEM
python audit_kiemdinh.py             # 13 hạng mục kiểm định chéo độc lập
python md2pdf_report.py              # (tuỳ chọn) sinh lại PDF
```

Ba điều kiện **bắt buộc** để kết quả có nghĩa (bản v1 thiếu cả ba — xem hồ sơ kiểm chứng):

1. **Tắt GSO/TSO/GRO** trên NIC ảo của router (`role.sh` làm tự động, cảnh báo nếu thiếu `ethtool`).
   Không tắt, gói 1847 B vẫn đi qua link MTU 576 và chiều "MTU" trở nên vô nghĩa.
2. **Capture bằng `dumpcap` trên từng interface vật lý** trong container riêng chia sẻ netns với
   router. `tcpdump -i any` mất gói trong workload này và bản 4.99.4 trong image chỉ nhận `-i`
   cuối cùng.
3. **Đơn vị netem tường minh** (`50ms`, không phải `50` — số trần bị hiểu là micro giây).

Với thí nghiệm PMTUD còn thêm: **router phải là điểm nghẽn thật** (`MTU_A=1500`, `MTU_B` nhỏ)
và **capture phải gồm ICMP** (`'tcp port 4433 or icmp'`, snaplen 0).

## 5. Dữ liệu

| Dữ liệu | Vị trí | Ghi chú |
|---|---|---|
| pcap bắt tay (v2) | `docker-lab/results/pcap2_L*.pcapng` | 13 cấu hình, snaplen 160 |
| pcap phân loại (v2) | `docker-lab/results/pcap2_sites_M{1500,1280}.pcapng` | snaplen 160 |
| pcap PMTUD | `docker-lab/results/pcap_pmtud_*.pcapng` | snaplen 0, **có ICMP** |
| pcap snaplen đầy đủ | `docker-lab/results/pcap_full_*.pcapng` | để bóc key_share |
| CSV lần chạy client | `docker-lab/results/hs2_*.csv`, `sites2_M*.csv`, `pmtud_trials.csv` | có `exit_code` để hoà giải |
| Trích xuất per-packet | `analysis/packets_all.tsv` | ≈402 nghìn dòng |
| Dữ liệu v1 (lưu trữ) | `docker-lab/results/archive_gso_capture/`, `analysis/packets_all_gso.tsv` | capture bị GSO che — giữ để đối chiếu |
| Bảng kết quả | `analysis/tables/` | rq1_flows/stats/failures/summary, rq23_summary, rq2b_summary, audit_results |
| Biểu đồ | `analysis/figs/` | fig1–fig5 |

## 6. Kiểm chứng chéo — những gì đã sửa so với v1

Ba tầng: **tái lập** (TSV và 4/4 bảng sinh lại giống hệt từng byte), **đo độc lập** (pipeline
viết mới, phát hiện lỗi phương pháp), **phản biện độc lập** (agent khác phản biện + agent khác
xác minh 16/16 trích dẫn và tìm tiền lệ).

| Vấn đề của v1 | Mức | Đã sửa thế nào |
|---|---|---|
| Dùng Wilcoxon **cặp ghép** trên hai nhóm chạy khối tuần tự ⇒ che mất khác biệt RTT thật | CRITICAL | Thiết kế lại **xen kẽ A-B-A-B**; kiểm định chính là Mann–Whitney + permutation + bootstrap CI + Cliff's δ |
| MTU **không có hiệu lực** vì GSO/TSO (gói 1847 B qua link 576) | CRITICAL | Tắt offload trong `role.sh`, thêm `ethtool` vào image, cảnh báo nếu thiếu; đo **phân mảnh cấp wire** |
| "PMTUD blackhole có kiểm soát" không có thao tác kiểm soát; capture không thấy ICMP; `sniff.txt` chỉ là SYN→RST | CRITICAL | `run_pmtud.sh`: nhân tố 4 chiều, capture gồm ICMP, đếm ICMP frag-needed trực tiếp, restart server giữa các lần |
| Kiểm tra "khớp lý thuyết FIPS 203" tự quy chiếu ("lý thuyết ≈1176") và gán sai ct/ek | CRITICAL | `check_ch_budget.py` bóc key_share thật; đối chiếu ek 1184 / ct 1088 và giải thích từng byte còn lại |
| `flow_dur` có ý nghĩa nhưng không được báo cáo (chọn lọc) | MAJOR | Báo cáo **mọi** metric, kể cả kết quả bất lợi |
| "0/780 thất bại" nhưng chỉ 773 flow được phân tích; 7 flow bỏ im lặng | MAJOR | Hoà giải tự động từ `exit_code`; dataset v2 đạt **780/780** |
| Fingerprint KEM ghi sai giá trị (297/1473 thay vì 217/1393) và bị trình bày như phát hiện | MAJOR | Tách hai mức quan sát; đo bền theo MTU; **rút tuyên bố tính mới** (đã có tiền lệ) |
| Classifier dùng CV ngẫu nhiên trên flow gần trùng nhau (rò rỉ) | MAJOR | Chia **theo thời gian** + phép kiểm tầm thường 1-NN bắt buộc |
| RQ3 là hiệu ứng trần, không đo được gì | MAJOR | Thêm bài toán khó (drift do đổi MTU); kết quả trung thực: **không có drift** ⇒ RQ3 báo cáo là không kiểm chứng được với fixture này |
| 9 trích dẫn sai chi tiết; **6 công trình tiền lệ** bị bỏ sót | — | Đã sửa toàn bộ và định vị lại (mục 7) |

## 7. Phạm vi và hạn chế

- Một máy, liên kết veth không giới hạn băng thông, delay ≤ 50 ms. Chênh lệch RTT 0.2–0.4 ms là
  chi phí xử lý/segment của host, **không** đại diện cho Internet thật.
- Fixture 6 site có kích thước cố định ⇒ bài toán phân loại tầm thường (1-NN = 1.000); vì vậy
  kết quả "classifier kháng drift" không được trình bày như phát hiện.
- n = 30/nhóm: chỉ phát hiện được hiệu ứng |Cliff's δ| ≳ 0.5 với công suất 0.8; mọi kết luận
  "không khác biệt" phải đọc là "không phát hiện được hiệu ứng cỡ vừa trở lên".
- Ma trận dùng snaplen 160 (đủ cho `tcp.len`/phân mảnh); kiểm tra mức payload cần capture riêng.
- PMTUD mới đo với một kiểu NAT 1-1, PMTU 1280/1500/576; chưa đo nhiều lớp NAT, IPv6, middlebox thật.
- 6 site tổng hợp, không phải lưu lượng thật; không đo throughput lớn.

## 8. Hướng phát triển

1. **Đo tỉ lệ blackhole PMTUD ngoài Internet thật** — dùng chính bắt tay lớn làm phép thử.
2. **QUIC** — PMTUD do ứng dụng thực hiện, có thể còn giòn hơn TLS/TCP.
3. **Chuỗi chứng chỉ ML-DSA** để tái hiện đầy đủ kịch bản 5×–20× (arXiv:2604.24869).
4. **Fixture phân loại khó thật** (site cùng kích thước, nhiều phiên/browser) để kiểm chứng lại
   kết luận về drift.

## 9. Tài liệu tham khảo chính

1. NIST FIPS 203/204/205 (2024); NIST IR 8547 (**Initial Public Draft**, 11/2024).
2. IETF **RFC 9954** *Hybrid Key Exchange in TLS 1.3* (7/2026); **RFC 9958** *PQC for Engineers* (6/2026); **RFC 9849** *ECH* (3/2026).
3. Mallick et al., *Classifying Implementations … Post-Quantum Algorithms*, arXiv:2503.17830.
4. Ibrahim et al., *Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection*, IACR ePrint 2026/834.
5. Chou & Cao, *Network Impact of Post-Quantum Certificate Chain sizes on TTFB*, arXiv:2604.24869.
6. Gómez-Cambronero et al., *Layered Performance Analysis of TLS 1.3 Handshakes*, arXiv:2603.11006.
7. Li et al., *The Colossus with Feet of Clay*, arXiv:2608.22683.
8. Paquin, Stebila, Tamvada, *Benchmarking Post-Quantum Cryptography in TLS*, PQCrypto 2020.
9. Zhou et al., *Electronics* 13(20):4000, 2024; Sharma & Lashkari, *Computer Networks* 257:110984, 2025;
   Merlach et al., *Network* 5(3):29, 2025.

---

*Ngày thực nghiệm: 2026-10-01 · Dữ liệu v1 lưu ở `docker-lab/results/archive_gso_capture/` ·
Hồ sơ kiểm chứng: [`07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md`](07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md)*
