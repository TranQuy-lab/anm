# Kiểm chứng & kiểm chứng chéo — hồ sơ đầy đủ

> Mục đích: ghi lại **mọi** sai sót phát hiện được trong bản báo cáo v1, cách xác minh,
> và cách sửa. Nguyên tắc: không có kết luận nào được giữ lại nếu không truy được về
> dữ liệu thô hoặc về một nguồn kiểm chứng được. Tài liệu này là phần bắt buộc của
> báo cáo, không phải phụ lục.

## 0. Ba tầng kiểm chứng đã thực hiện

| Tầng | Cách làm | Kết quả |
|---|---|---|
| **1. Tái lập** | Khôi phục 30 pcap thô từ commit `7717a72`, chạy lại `extract_metrics.sh` và cả 4 script phân tích | TSV tái tạo **trùng khớp tuyệt đối** (93.663 dòng của **bộ 30 pcap v1**; con số này KHÔNG áp cho `packets_all_gso.tsv` trong repo — file đó gồm thêm các capture `pcap_dec_*`/`pcap_full_*` nên có 93.924 dòng); 4/4 bảng kết quả sinh lại **giống hệt từng byte** ⇒ pipeline xác định, không có số liệu nhập tay |
| **2. Đo độc lập** | Viết pipeline mới (tshark JSON + phân cụm theo khoảng thời gian + ghép leg theo mốc SYN), không dùng lại code cũ; tự tính lại thống kê | Tái tạo đúng các con số byte (217/1393, 297/1473, 768/1846); **phát hiện 2 lỗi phương pháp** (mục 1.1, 1.2) |
| **3. Phản biện độc lập** | Giao cho một agent khác (không thấy kết luận của tôi) đọc repo và phản biện như reviewer; một agent khác xác minh **toàn bộ 16 trích dẫn** và tìm tiền lệ | 9 vấn đề CRITICAL/MAJOR; 16/16 trích dẫn có thật nhưng 7 mục sai chi tiết; **6 công trình tiền lệ chiếm mất tuyên bố "đầu tiên"** của báo cáo |

Hai tầng 2 và 3 **hội tụ độc lập về cùng một kết luận** ở các điểm quan trọng nhất
(1.1, 1.2, 1.3), đó là cơ sở để tin các phát hiện dưới đây.

---

## 1. Sai sót nghiêm trọng (CRITICAL)

### 1.1 Test thống kê sai thiết kế → đảo ngược kết luận chính về RTT

- **Vấn đề.** `rq1_analysis.py` (v1) dùng `scipy.stats.wilcoxon` — kiểm định **cặp ghép** —
  nhưng hai nhóm KEM chạy ở hai khối tuần tự (vòng lặp `for G in X25519 X25519MLKEM768`
  là vòng NGOÀI, `run_matrix.sh:64`), tức không hề có cặp tương ứng. Ghép cặp chỉ bằng
  thứ tự dòng (`a.head(n)`, `b.head(n)`, dòng 83–86). Effect size dùng `d_z` (độ lệch
  chuẩn của hiệu) nhưng báo cáo gọi là "Cohen's d".
- **Bằng chứng.** Ở cấu hình sạch MTU 1500: Wilcoxon paired cho `p_holm = 0.157` (không
  ý nghĩa) — trong khi Mann–Whitney U trên đúng dữ liệu đó cho `p = 0.0011`,
  `p_holm(13) = 0.0145` (**có ý nghĩa**); permutation trên trung vị `p = 0.0030`.
- **Sửa.** Bản 2: (a) đổi thiết kế sang **xen kẽ ABAB** trong cùng cấu hình
  (`hs_loop2.sh`) để ghép cặp theo `rep` là hợp lệ; (b) kiểm định chính là Mann–Whitney U
  (độc lập) + permutation trên trung vị; (c) báo cáo Cliff's δ, Hedges' g và bootstrap CI
  95% cho hiệu trung vị; (d) Wilcoxon paired chỉ còn là kiểm định phụ.

### 1.2 MTU trong bản v1 **không có hiệu lực** — GSO/TSO che đường truyền

- **Vấn đề.** Capture ở router cho thấy gói **1847 byte** đi qua link được đặt MTU **576**.
  Nguyên nhân: GSO/TSO trên veth làm skb lớn đi nguyên khối; TSO/GSO không bị tắt ở v1.
- **Bằng chứng.** `pcap_X25519MLKEM768_L0_D0_M576.pcapng`: MSS clamp **có** tác dụng
  (hai phía đều báo MSS 536), nhưng `max(tcp.len) = 1847`. Hệ quả: mọi kết luận về MTU
  ở v1 (kể cả "0 thất bại ở MTU 576") **không** đo cái mà nó tuyên bố đo.
- **Sửa.** `role.sh` bắt buộc tắt offload (`ethtool -K … tso/gso/gro off`) và **cảnh báo
  nếu thiếu ethtool**; `Dockerfile` thêm `ethtool`. Bản 2 đo được phân mảnh cấp wire thật
  (mục 3.2 của báo cáo).

### 1.3 "PMTUD blackhole tái hiện có kiểm soát" — bằng chứng v1 không đỡ được tuyên bố

- **Vấn đề.** (a) Capture v1 lọc `tcp port 4433` ⇒ **không bao giờ** thấy ICMP;
  (b) không có thao tác chặn ICMP nào trong code; (c) `sniff.txt` chỉ là một SYN bị trả
  `RST` (kết nối bị từ chối), không phải blackhole; (d) `sniff2.txt` cho thấy ClientHello
  1393 B được chuyển tiếp **nguyên khối** rồi server chỉ ACK và im lặng 8 s — dấu hiệu
  `s_server` bị kẹt, không chứng minh được MTU/ICMP.
- **Sửa.** Viết thí nghiệm **có kiểm soát** `run_pmtud.sh`: nhân tố
  {nhóm KEM} × {PMTU} × {cho qua / chặn ICMP type 3 code 4} × {clamp on/off}, capture
  **snaplen đầy đủ** với filter `tcp port 4433 or icmp`, đếm trực tiếp ICMP frag-needed,
  restart server giữa các lần để loại nhiễu `s_server` đơn luồng.
  Đồng thời sửa lab để **router là điểm nghẽn thật** (`MTU_A=1500`, `MTU_B` nhỏ):
  nếu đặt MTU nhỏ cả hai phía thì gói lớn bị chặn ở bridge/veth phía host **trước khi tới
  router**, khiến phép can thiệp ICMP trở nên vô nghĩa (đây chính là điều đã xảy ra ở
  lần chạy đầu — xem `pmtud_trials.csv` ghi chú trong báo cáo).

### 1.4 Kiểm tra "khớp lý thuyết FIPS 203" là vòng lặp

- **Vấn đề.** Audit v1 so `Δclient = 1176` với "lý thuyết ≈1176" — lấy chính giá trị đo
  được làm chuẩn, nên "lệch 0.0%" vô nghĩa. Phía server còn so với 1152 — không tồn tại
  trong FIPS 203. Phần văn bản còn gán sai: nói +1176 là "ciphertext 1088 B + header".
- **Sự thật (đo trực tiếp từ capture snaplen đầy đủ, giải mã TLS).**
  - ClientHello: key_share hybrid = **1216 B** = ek(ML-KEM-768) **1184** + X25519 **32** ⇒ khớp FIPS 203.
  - ServerHello: key_share hybrid = **1120 B** = ct **1088** + X25519 **32** ⇒ khớp FIPS 203.
  - ΔClientHello tổng = +1176 = 1184 − 8 vì nhóm hybrid **bỏ extension `ec_point_formats`**.
  - Δflight server = +1076…1078 ≈ 1088 − 10 (bỏ `ec_point_formats` trong EncryptedExtensions) ± độ dài chữ ký ECDSA.
- **Sửa.** `check_ch_budget.py` bóc tách key_share thật; audit check C/C2 đối chiếu với
  1184/1088 và giải thích phần chênh còn lại. Toàn bộ ngân sách byte được **giải thích
  từng byte**, không còn con số "0.0%" tự quy chiếu.

---

## 2. Sai sót lớn (MAJOR)

| # | Vấn đề | Bằng chứng | Sửa |
|---|---|---|---|
| M1 | `flow_dur` có ý nghĩa thống kê nhưng **không hề được báo cáo** (chọn lọc kết quả) | v1: median 2.42 → 3.00 ms, `p_holm = 0.002` | Bản 2 báo cáo đầy đủ mọi metric, kể cả kết quả bất lợi |
| M2 | "0/780 thất bại" nhưng chỉ **773** flow được phân tích; 7 flow bị bỏ im lặng; check H so pipeline với chính nó | `rq1_summary.json` cộng lại = 773 | Bản 2 ghép `exit_code` từ CSV và **hoà giải tự động**; dataset mới đạt 780/780 |
| M3 | Fingerprint KEM: ghi đặc trưng "packet đầu client" là **297/1473** — sai; giá trị thật **217/1393**; và bản chất là **định nghĩa** (kích thước do giao thức quy định), không phải phát hiện | `rq2b_summary.json` (v1) vs pcap | Bản 2 tách hai mức quan sát (một packet / toàn flight), đo bền theo MTU, và **rút tuyên bố tính mới** |
| M4 | Tuyên bố retransmission "mean 0.10–0.31" sai; không có CI nào cho retrans | tính lại: 0.033–0.467 | Bản 2 báo cáo mean/median + kiểm định, nêu rõ giới hạn công suất ở n=30 |
| M5 | Classifier RQ2 dùng `StratifiedKFold` ngẫu nhiên trên các flow gần như trùng nhau ⇒ **rò rỉ**, trái với chính preregistration trong `THIET_KE_NGHIEN_CUU.md` | 30 flow/lớp gần như đồng nhất | Bản 2 chia **theo thời gian**, báo cáo baseline 1-NN một-đặc-trưng như **phép kiểm tính tầm thường** |
| M6 | RQ3 (thích ứng) là **hiệu ứng trần**: baseline đã 1.0 nên không thể đo được gì | `rq23_summary.json` (v1): mọi k đều 1.0 | Bản 2 thêm bài toán **drift do đổi MTU**; kết quả trung thực: không có drift ⇒ RQ3 được báo cáo là **không kiểm chứng được** với fixture này |
| M7 | Nhiều con số trong văn bản không khớp dữ liệu (720 luồng → thực 710; 28 pcap → 30; "93.663 dòng" gồm header; `d ≤ 0.28`; "trung vị ≤ 0.25 ms") | đối chiếu bảng | Mọi số trong bản 2 sinh trực tiếp từ `tables/*.json` |
| M8 | Audit check E so với ngưỡng tuỳ ý 0.30; accuracy 0.238 so với mức ngẫu nhiên 1/6 = 0.167 (z ≈ 2.5) ⇒ "≈ ngẫu nhiên" không đúng | `audit_results.csv` v1 | Bản 2 dùng **kiểm nhị thức** với 1/6 và phát biểu đúng mức ý nghĩa |
| M9 | Ghép nhãn site bằng thứ tự ngầm định (dễ vỡ); `sites_loop.sh` quảng cáo cột `bytes_req` không tồn tại; `run_matrix.sh` truyền `0` trần cho netem delay | đọc code | Bản 2 ghép nhãn **theo mốc thời gian SYN** và gắn đơn vị `ms` tường minh |

---

## 3. Trích dẫn: 16/16 có thật, nhưng 7 mục sai chi tiết và **tuyên bố "đầu tiên" bị chiếm**

Không phát hiện trích dẫn bịa. Các lỗi cần sửa:

| Trích dẫn v1 | Vấn đề | Bản đúng |
|---|---|---|
| Merlach et al., "…A View from Passive **Observers**" | Sai tựa | "…A View from Passive **Measurements**", *Network* (MDPI) 5(3):29, 2025 |
| "PQC for Engineers" (2025, Internet-Draft) | Đã thành RFC | **RFC 9958** (Informational, 6/2026) |
| draft-ietf-tls-hybrid-design | Đã thành RFC | **RFC 9954**, "Hybrid Key Exchange in TLS 1.3" (7/2026) |
| NIST IR 8547 | Nêu như chuẩn cuối | Vẫn là **Initial Public Draft** (11/2024) |
| "Raspberry Pi 4: ML-KEM-512 ~58/51 µs" | Sai nền tảng đo | 58/51 µs là **Intel Xeon E5-2680 v4** (ePrint 2026/1467); Pi 4B ≈ 80/104 µs |
| Corrata "2026", "17% site vẫn lộ metadata" | Sai năm và sai ý nghĩa | Corrata "Living with ECH", **5/2025**; 17% là tỉ lệ site thuộc nhóm rủi ro |
| "arXiv handshake-size 5×–20×" (không ID) | Thiếu nguồn | **arXiv:2604.24869** (Chou & Cao, 2026) — nói về **chuỗi chứng chỉ**, không phải key share |
| Mahdi et al. "2025" | Sai năm | 2023 (ITT) |
| arXiv:2508.01750 "MQTT"; MultiFuzz "MQTT" | Sai lĩnh vực | 2508.01750: fuzzing giao thức nói chung; MultiFuzz: RTSP |

### Tiền lệ chiếm mất các tuyên bố "đầu tiên" (đã xác minh trực tiếp)

1. **arXiv:2503.17830** (Mallick, Nita-Rotaru, Kundu, Kompella; 3/2025, sửa 1/2026) —
   phân loại cổ điển vs hậu lượng tử **98–100%**, nhận dạng đúng thuật toán PQ (97% KEX),
   phân biệt cả hai thư viện liboqs/CIRCL, áp dụng cho **TLS/SSH/QUIC/OpenVPN/OIDC** và
   tìm domain bật PQC trong Tranco ⇒ **khả năng fingerprint PQC đã được công bố**.
2. **IACR ePrint 2026/834** (Ibrahim, Ajith, Haroon; Ulster; 5/2026) — đọc key_share ở
   mức byte trong ServerHello, phân loại CLASSICAL_ONLY / PQC_ONLY / HYBRID_CONFIRMED,
   xác nhận nhóm `0x11EC` (X25519MLKEM768) trên 38 endpoint thật.
3. **arXiv:2604.24869** (Chou & Cao, 4/2026) — handshake tăng 5×–20×, **phân tích TTFB
   theo giới hạn "flight" của tầng vận chuyển**, Merkle Tree Certificates, CDN.
4. **arXiv:2603.11006** (Gómez-Cambronero et al., 3/2026, SPIQE @ EuroS&P) — đo hiệu năng
   TLS 1.3 theo **từng tầng** (TCP, TLS, HTTP) cho cổ điển / lai / thuần PQC.
5. **arXiv:2608.22683** (Li et al., 8/2026) — benchmark website-fingerprinting cặp
   Non-PQC/Hybrid-PQC; accuracy sụp khi cross-domain.
6. **ePrint 2019/1447** (Paquin, Stebila, Tamvada; PQCrypto 2020) — đo trên mạng giả lập,
   mất gói >3–5% ảnh hưởng nặng tới thuật toán PQC phải phân mảnh.

**Khoảng trống còn thật sự mở** (sau khi tìm nhiều truy vấn khác nhau, không tìm thấy
công trình nào làm): phân tích **PMTUD/ICMP-blackhole** cho bắt tay PQC, và đo tỉ lệ
blackhole ngoài Internet thật. Báo cáo v2 định vị đóng góp của mình **đúng vào khoảng
trống này**, không tuyên bố "đầu tiên" ở chỗ đã có người làm.

---

## 4. Vòng tự kiểm chứng bổ sung sau khi sửa: nghi vấn "thứ tự chạy"

Sau khi đã sửa và chạy lại toàn bộ, chúng tôi tự đặt thêm một câu hỏi đối kháng mà **chưa**
vòng phản biện nào nêu: *"Trong mỗi cặp, X25519 luôn chạy trước. Nếu bản thân việc chạy thứ hai
đã chậm hơn, kết luận 'nhóm lai chậm hơn' có thể chỉ là hiệu ứng thứ tự."*

- **Cách kiểm.** `run_order_control.sh` chạy lại hai cấu hình mạng sạch ở MTU 1500 và 1280 với
  **thứ tự hai nhóm đảo ngẫu nhiên** cho từng cặp (`ORDER=random`), n = 60 cặp/nhóm;
  `analysis/order_control.py` phân rã 2×2 (hiệu ứng nhóm *trong* từng vị trí, và hiệu ứng vị trí
  *trong* từng nhóm).
- **Kết quả lần đầu (n = 30 cặp/MTU)** cho thấy một hiệu ứng vị trí trông đáng kể (+0,14…+0,20 ms,
  p = 0,08/0,014) — đủ để nghi ngờ chính kết luận RTT của mình. Vì vậy chúng tôi **tăng cỡ mẫu**
  lên 60 cặp/nhóm và chạy lại.
- **Kết quả cuối:** hiệu ứng **nhóm** +0,358 ms (MTU 1280) và +0,331 ms (MTU 1500),
  **p ≈ 10⁻¹⁷ và 10⁻¹⁵**, Cliff's δ ≈ 0,85–0,90 (hiệu ứng lớn); hiệu ứng **vị trí** +0,212 ms
  (p = 0,14) và −0,023 ms (p = 0,45) — **không đáng kể**. Phân rã 2×2 cho thấy hiệu ứng nhóm ổn
  định ở cả hai vị trí (+0,344…+0,387 ms), còn hiệu ứng vị trí trong từng nhóm chỉ 0,01–0,07 ms.
- **Kết luận.** Nghi vấn được **loại trừ**; kết luận RTT đứng vững và thực ra **mạnh hơn** ước
  lượng ban đầu.
- **Đính chính quan trọng (vòng phản biện thứ hai chỉ ra).** "Hiệu ứng vị trí" tính trên **trung
  vị lề** (+0,212 ms, p = 0,14) là **confound thành phần**, không phải hiệu ứng thật: ở MTU 1280,
  vị trí 1 gồm 37 X25519 + 23 PQC còn vị trí 2 gồm 23 X25519 + 37 PQC, nên so hai trung vị lề là
  so hai hỗn hợp khác thành phần. Tính **trong từng nhóm**, sai khác vị trí chỉ còn **+0,012 ms
  (X25519)** và **−0,045 ms (PQC)**. Vì vậy: (a) kết luận phải dựa trên phân rã trong nhóm, không
  dựa trên p lề; (b) tiêu chí `p_order > 0.05` đã bị **bỏ khỏi audit**; (c) cách giải thích "tăng
  n làm mất ý nghĩa" là **sai** — nguyên nhân là confound thành phần.

## 5. Những gì KHÔNG sửa được / còn nghi vấn

1. **Snaplen 160 của dataset v1** làm mọi kiểm tra mức payload bất khả thi. Bản 2 vẫn giữ
   `-s 160` cho ma trận (đủ cho `tcp.len`/phân mảnh) nhưng dùng capture **snaplen đầy đủ**
   riêng cho kiểm chứng ngân sách byte.
2. **`tcpdump -i any` (SLL2) mất gói** trong workload này: đo được 1.192 gói "received by
   filter" nhưng chỉ 892 gói được ghi; và tcpdump 4.99.4 trong image **chỉ nhận `-i` cuối
   cùng** nên mất hẳn một chiều. Đã chuyển sang **dumpcap** trong container riêng chia sẻ
   netns với router ⇒ 780/780 khớp.
3. **Giới hạn vật lý của lab**: một máy, veth, không có băng thông giới hạn. Chênh lệch
   RTT ~0.2–0.4 ms đo được là chi phí xử lý/segment của host, **không** đại diện cho WAN.
4. **Fixture 6 site là tầm thường** (1-NN một đặc trưng = 1.0). Vì vậy kết quả "classifier
   kháng drift" **không** được trình bày như một phát hiện; chỉ phần **ranh giới họ đặc
   trưng** được giữ, kèm phép kiểm tầm thường bắt buộc.
5. **Thí nghiệm PMTUD**: xem mục 3 của báo cáo — kết quả và diễn giải nằm ở đó; nếu tác
   nhân ICMP không tạo khác biệt thì báo cáo phải nói thẳng như vậy (xem `pmtud_trials.csv`).

---

## 6. Vòng phản biện thứ hai — trên chính bản v2

Sau khi v2 hoàn tất, một agent khác phản biện **bản v2** (không phải v1) để bắt lỗi do việc sửa
chữa gây ra. Kết quả và cách xử lý:

| Phát hiện trên v2 | Mức | Đã sửa |
|---|---|---|
| Check D của audit **tự quy chiếu** ("sự thật" định nghĩa bằng chính ngưỡng đang kiểm ⇒ accuracy luôn 1,0, không bao giờ FAIL) | CRITICAL | Thay bằng phép kiểm thật: luật ngưỡng 800 B đối chiếu **nhãn nhóm đọc từ CSV lần chạy** |
| Bảng §4 của báo cáo **chép tay sai** so với `audit_results.csv` (placebo 0,070 vs 0,080; mô tả check J) | CRITICAL | Sửa cho khớp từng ô; bảng phải sinh từ file kết quả, không chép tay |
| Hai ô PMTUD ở PMTU 576 **đo sai cơ chế** (hướng server→client vượt MTU trước router ⇒ 0 gói ICMP ⇒ drop im lặng, không phải PMTUD blackhole) | CRITICAL | Dán nhãn lại; kết luận c1/c2 không đổi |
| Test "hiệu ứng vị trí" bị **confound thành phần** | MAJOR | Chuyển sang sai khác **trong từng nhóm**; bỏ tiêu chí sai khỏi audit |
| `rq2b` tuyên bố "packet đầu bất biến theo MTU" — thực ra là **artifact GSO ở leg ingress** | MAJOR | Thêm `wire_cl_first` (leg egress); bất biến chỉ giữ cho **tổng byte flight** |
| Audit cho **PASS rỗng** khi thiếu dữ liệu (H, I); J đọc lại bảng công bố thay vì pcap | MAJOR | H/I trả WARN khi thiếu dữ liệu, FAIL khi có `rc≠0`; J tính lại từ pcap trên leg egress |
| Keylog của capture đầy đủ **không khớp pcap** ⇒ phần −10 B không giải mã được | MINOR (đã nâng) | `run_ch_budget.sh` truyền `-keylogfile` cùng lần chạy; thêm **check C3** giải mã EE (12 → 2 B) |
| Chi tiết nhỏ: thiếu ChangeCipherSpec trong mô tả flight; làm tròn 8,60 vs 8,59; `sv_spread` bị bỏ sót; sign test một phía; "≈ ngẫu nhiên" cho 0,58–0,59; `docker-lab/README.md` còn văn phong v1 | MINOR | Đã sửa toàn bộ; `sv_spread` nay được báo cáo như một góc nhìn của cùng cơ chế phân mảnh |

Sau tất cả các sửa, audit tự động đạt **15/15 PASS** (thêm check C3 và check K2 — kiểm chứng chuỗi nhân quả PMTUD trực tiếp trong pcap).

## 7. Bảng đối chiếu v1 → v2

| Hạng mục | v1 | v2 |
|---|---|---|
| Thiết kế RQ1 | hai khối tuần tự, "ghép cặp" giả | **xen kẽ ABAB**, ghép cặp theo `rep` |
| Kiểm định RTT | Wilcoxon paired (sai) | Mann–Whitney + permutation + bootstrap CI + Cliff's δ **+ đối chứng đảo thứ tự ngẫu nhiên** |
| MTU | bị GSO che (gói 1847 B qua link 576) | offload tắt, cảnh báo nếu thiếu ethtool |
| Phân mảnh | suy luận từ tổng byte | **đo số segment cấp wire** |
| Capture | `tcpdump -i any`, mất ~25% gói | **dumpcap**, 2 interface, 780/780 |
| Ngân sách byte | "khớp 0.0%" (tự quy chiếu) | ek 1184 / ct 1088, giải thích từng byte |
| PMTUD | giai thoại + `sniff.txt` không đỡ được | thí nghiệm nhân tố có kiểm soát |
| Fingerprint | 297/1473 (sai), "phát hiện mới" | 217/1393, rút tuyên bố mới, đo bền theo MTU |
| Classifier | CV ngẫu nhiên (rò rỉ) | chia theo thời gian + kiểm tầm thường 1-NN |
| Trích dẫn | 9 mục sai chi tiết, 6 tiền lệ bị bỏ sót | đã sửa và định vị lại toàn bộ |
