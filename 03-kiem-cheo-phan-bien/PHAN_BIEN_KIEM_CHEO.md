# Kiểm chéo đối kháng (adversarial cross-examination) — vai "chuyên gia an ninh mạng"

> Phương pháp: mỗi đề tài đi qua các vòng hỏi–đáp đối kháng. Sau mỗi vòng, độ tự tin được cập
> nhật. Tiêu chí dừng: ≥95% cho đề tài khuyến nghị. Mọi câu trả lời phải gắn bằng chứng; nếu
> không tìm được bằng chứng thì ghi "chưa kiểm chứng" và giảm điểm — không tự lừa mình.

---

## Đề tài T1 (PQC × mạng) — 5 vòng kiểm chéo

### Vòng 1 — "Đề tài này đã có ai làm chưa?" *(tính mới)*
- **Câu hỏi đối kháng:** "Cậu bảo tính mới 8.5/10 — nhưng 2026 ai cũng nhắc PQC, chắc chắn
  chưa có người làm y hệt?"
- **Hành động:** truy vấn y văn có chủ đích → tìm thấy **arXiv:2608.22683 (8/2026)**: chẩn đoán
  classifier suy giảm do drift X25519 → X25519MLKEM768 trong **TLS 1.3**.
- **Kết luận:** phần "chẩn đoán drift trên TLS" ĐÃ BỊ CHIẾM. Nếu giữ nguyên ý tưởng gốc, độ tự
  tin chỉ ~60%. **Điều chỉnh:** chuyển trọng tâm sang 3 delta chưa ai làm:
  (a) tác động **mạng** (phân mảnh/MTU/mất gói → RTT/throughput) có kiểm soát bằng netem;
  (b) mở rộng sang **QUIC**; (c) **thích ứng** (fine-tune/ghép dataset) thay vì chỉ chẩn đoán
  + phát hành dataset công khai.
- Độ tự tin sau vòng 1: **72%**.

### Vòng 2 — "Delta này có đủ lớn không, hay chỉ là 'thêm một bài đo hiệu năng'?"
- **Câu hỏi đối kháng:** "Measurement-only papers hay bị từ chối vì 'không có đóng góp trí tuệ'."
- **Bằng chứng:** cộng đồng thống nhất "PQC nhanh ở CPU, đắt ở mạng" (IETF PQC for Engineers
  5/2025; CSA; arXiv handshake-size 5×–20×) nhưng chưa ai có pipeline thống nhất đo chuỗi nhân
  quả handshake-size → fragmentation → loss → throughput VÀ gắn với hệ quả nhận dạng lưu lượng.
  Việc nối hai thế giới (network measurement + traffic classification drift) thành một khung
  là đóng góp khung (framework), không chỉ là số liệu.
- **Đối trọng:** nếu reviewer nói "hai mảng này rời rạc" → biện pháp: thiết kế RQ3 (thích ứng)
  làm chất kết dính: chính dữ liệu đo được dùng để xây tập thích ứng.
- Độ tự tin sau vòng 2: **84%**.

### Vòng 3 — "Khả thi trên một máy đơn không cluster/GPU?"
- **Câu hỏi đối kháng:** "Cậu có GPU không? Classifier deep learning cần GPU đấy."
- **Bằng chứng:** (1) OpenSSL 3.5 LTS (4/2025) tích hợp ML-KEM/ML-DSA mặc định → s_server/s_client
  với `-groups X25519MLKEM768` chạy ngay; (2) benchmark Raspberry Pi 4 cho thấy ML-KEM cực nhanh
  → phần mã hóa không cần phần cứng mạnh; (3) classifier cho drift study có thể dùng model nhẹ
  (Random Forest/XGBoost trên flow statistics — đúng hướng các bài robustness cũ) → CPU đủ;
  (4) netem/tc trong Docker router mô phỏng mất gói/trễ chính xác và tái lập được.
- **Rủi ro sót:** QUIC + ML-KEM cần quiche/boringssl hoặc ngtcp2 build → công việc build tăng;
  biện pháp: phase 2, TLS trước QUIC sau.
- Độ tự tin sau vòng 3: **90%**.

### Vòng 4 — "An toàn và đạo đức: có vướng gì không?"
- **Câu hỏi đối kháng:** "Phân loại lưu lượng mã hóa có phải kỹ thuật giám sát vi phạm riêng tư?
  Nghiên cứu lỗ hổng có phải vẽ đường cho kẻ xấu?"
- **Phân tích:** (1) toàn bộ dữ liệu tự sinh trong lab, không capture lưu lượng người thật →
  không có vấn đề dữ liệu cá nhân; (2) mục tiêu là hiểu hệ quả chuyển đổi PQC cho người vận
  hành mạng — phòng thủ, công khai y văn từ trước (2608.22683 đã công bố phần nhạy cảm nhất);
  (3) T4 (fuzzing) mới cần ràng buộc: Docker internal network, không xuất ngoại, responsible
  disclosure — đã ghi trong thiết kế lab.
- Độ tự tin sau vòng 4: **94%**.

### Vòng 5 — "Cái gì có thể giết chết đề tài này, và kế hoạch B là gì?"
- **Tự hỏi lần cuối:**
  1. *"Có ai publish đúng delta (QUIC + thích ứng) trước khi mình bắt đầu?"* → Giảm nhẹ: theo
     dõi arXiv cs.CR/cr-NI hàng tuần 30 phút; nếu xảy ra, pivot sang T2 (ECH) — testbed dùng lại
     90%.
  2. *"Dữ liệu tự sinh có bị chê là không thực tế?"* → Giảm nhẹ: tham chiếu cấu hình thực tế
     (Chrome/Firefox đã bật X25519MLKEM768; Cloudflare/Google vận hành) để biện minh tham số.
  3. *"Kết quả nếu ra 'không có khác biệt'?"* → Không âm: kết quả rỗng có giá trị (PQC không
     ảnh hưởng throughput ở loss 1% là phát hiện có ích cho người vận hành) — thiết kế metric
     để cả hai nhánh kết quả đều công bố được.
- **Kết luận vòng 5:** mọi rủi ro có giảm减缓 thích hợp và kế hoạch B cụ thể.
- Độ tự tin cuối: **96% ≥ 95%** → **T1 qua cổng kiểm chéo, chốt làm đề tài khuyến nghị chính.**

---

## Đề tài T2 (ECH) — 3 vòng

1. **Tính mới?** Measurement thụ động đầu tiên đã có (Merlach 2025); Corrata 2026 báo 17% leak.
   Delta còn lại: hệ thống hóa "leak surface" trong lab + phương pháp phát hiện không giải mã.
   → tự tin 78%.
2. **Song công?** Kết quả "cái gì còn nhìn thấy khi ECH bật" có thể bị đọc theo hướng né giám
   sát. Phải đóng khung: mục tiêu = khôi phục khả năng phòng thủ của doanh nghiệp, không phải
   né DPI; tránh hướng dẫn bypass cụ thể. → tự tin 84%.
3. **Khả thi?** Cần Chrome/DoH/local DNS infrastructure — cấu hình phức tạp hơn T1 một bậc;
   Chrome ECH phụ thuộc DNS ECHConfig công khai → khó kiểm soát trong lab (phải giả lập权威 DNS).
   → tự tin dừng ở **90% < 95%** → **chưa chốt**, giữ làm phase-2/hướng thay thế.

## Đề tài T4 (fuzzing lỗ hổng) — 3 vòng

1. **Tính mới?** MBFuzzer (USENIX'25) và LLM-assisted (2508.01750) mới ra → dư địa đa bên cho
   QUIC + LLM còn trống, nhưng lĩnh vực di chuyển cực nhanh. → 80%.
2. **Khả thi?** Công kỹ thuật lớn (state machine inference, build QUIC servers, triage crash);
   thời gian dài hơn T1 đáng kể; risk "không tìm ra bug nào" thật sự tồn tại. → 72%.
3. **An toàn?** Ràng buộc dễ xác định (Docker internal, OSS targets, disclosure) nhưng chi phí
   đạo đức/quy trình cao hơn. → dừng ở **86% < 95%** → **không đề xuất làm đề tài chính**;
   giữ làm phương án khi người dùng muốn hướng công cụ, hoặc giai đoạn 2 sau T1.

## Tổng kết cổng chất lượng

| Đề tài | Tự tin cuối | Vượt ngưỡng 95%? | Quyết định |
|---|---|---|---|
| T1 PQC × mạng | **96%** | ✅ | **Chốt — khuyến nghị chính** |
| T2 ECH | 90% | ❌ | Phase-2 / phương án thay thế |
| T4 Fuzzing | 86% | ❌ | Giữ, kèm ràng buộc Docker bắt buộc |
| T3 NIDS drift | 90% (đánh giá nhanh: lĩnh vực đông, khác biệt khó) | ❌ | Kế thừa testbed T1 nếu muốn hướng ML |
| T5 SDN DDoS | 88% (đông tương tự T3) | ❌ | Dự phòng |
| T6 ASCON IoT | 92% (khả thi cao, mới vừa phải) | ❌ | Dự phòng hướng mã hóa thuần |

> Ghi chú trung thực: mức % là ước lượng có cấu trúc của agent dựa trên bằng chứng đã truy vấn
> trong ngày 2026-10-01, không phải xác suất khách quan. Ngưỡng 95% chỉ đạt khi mỗi vòng hỏi
> đều có bằng chứng hoặc kế hoạch giảm rủi ro cụ thể — đúng tinh thần của skill peer-review:
> "không được tuyên bố tính mới chỉ vì tìm kiếm nhanh không thấy gì".

---

## Cập nhật v2 — kiểm chứng chéo **kết quả** (khác với kiểm chéo **đề tài** ở trên)

Các vòng ở trên chấm điểm **việc chọn đề tài** và kết thúc trước khi có dữ liệu. Sau khi có kết
quả, một vòng kiểm chứng độc lập khác đã được chạy trên chính repo (một agent phản biện như
reviewer + một agent xác minh y văn). Vòng đó tìm ra các vấn đề **không** được phủ bởi 5 vòng
chọn đề tài:

| Phát hiện | Mức | Ý nghĩa cho quy trình |
|---|---|---|
| Kiểm định cặp ghép không hợp lệ (hai nhóm chạy khối tuần tự) làm **đảo** kết luận chính về RTT | CRITICAL | Kiểm chéo đề tài không thể thay kiểm chéo **phân tích** — cần một vòng riêng sau khi có số |
| MTU bị GSO/TSO che ⇒ chiều "MTU" của ma trận v1 đo sai thứ nó tuyên bố đo | CRITICAL | "Thiết kế đúng trên giấy" ≠ "lab thực thi đúng"; phải có phép kiểm độ trung thực (ở đây: đo `max(tcp.len)` so với MTU) |
| "PMTUD blackhole có kiểm soát" không có thao tác kiểm soát nào trong code | CRITICAL | Mọi tuyên bố nhân quả phải truy được về một thao tác cụ thể + bằng chứng ghi được |
| Kiểm tra "khớp FIPS 203" tự quy chiếu ("lý thuyết ≈1176") | CRITICAL | Phép kiểm phải có hằng số **độc lập** với dữ liệu (ở đây: ek 1184 / ct 1088) |
| **6 công trình tiền lệ** chiếm mất tuyên bố "đầu tiên" | — | Vòng 1 (tính mới) chỉ tìm được 1 tiền lệ; tìm kỹ hơn thấy 6 ⇒ phải **định vị lại**, không đổi đề tài |

**Kết luận quy trình (đáng giữ lại):** kiểm chéo đề tài và kiểm chéo kết quả là hai việc khác
nhau, và cả hai đều phải làm. Mức tự tin 96% ở trên vẫn đúng với câu hỏi "có nên làm đề tài
này không"; nó **không** nói gì về chất lượng thực thi. Hồ sơ đầy đủ:
`07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md`.
