# NCKH An ninh mạng — workspace nghiên cứu

Tạo ngày 2026-10-01 theo quy trình: skill giáo sư (giao-su: literature-review →
hypothesis-generation → experimental-design → peer-review) × skill security-agent (kiểm chéo
an toàn/đối kháng). **Đề tài T1 đã được THỰC THI đến hoàn thành cùng ngày** — xem báo cáo
[BÁO_CÁO_NGHIÊN_CỨU.pdf](04-thiet-ke-nghien-cuu/BÁO_CÁO_NGHIÊN_CỨU.pdf) (7 trang, 5 hình,
bảng thống kê đầy đủ; bản md cùng thư mục).

## Kết quả chính (TL;DR) — từ thực nghiệm thật, không phải kế hoạch

- **780 bắt tay TLS 1.3** qua 26 cấu hình (loss/delay/MTU) × 2 nhóm KEM, **0 thất bại**:
  chi phí byte client **4.96×**, server **2.40×**; RTT **không** tăng có ý nghĩa (Holm p>0.05);
  tái hiện được **PMTUD blackhole** khi ICMP bị chặn — rủi ro thật của PQC.
- **720 luồng ứng dụng**: classifier volume/sequence **kháng drift** PQC (1.0→1.0, cả MTU
  1500 & 1280) — ranh giới: drift chỉ đánh vào đặc trưng chạm handshake.
- **Phát hiện mới:** chuyển đổi PQC tạo **tín hiệu fingerprint một-đặc-trưng** (100% ± 0 phân
  loại nhóm KEM từ kích thước packet đầu tiên) — hệ quả riêng tư mới của thập kỷ chuyển đổi.
- Toàn bộ tái lập được: `docker compose build && bash docker-lab/run_matrix.sh` …


*(Bối cảnh lập kế hoạch trước thực nghiệm — xem `02-de-xuat-de-tai/` và
`03-kiem-cheo-phan-bien/`: T1 đạt 96% tự tin qua 5 vòng kiểm chéo đối kháng; T2 (ECH, 90%)
là phase-2; T4 (fuzzing lỗ hổng, 86%) giữ với ràng buộc Docker cách ly bắt buộc.)*

## Cấu trúc thư mục

| Thư mục | Nội dung |
|---|---|
| `01-tong-quan-y-van/` | Bản đồ y văn 2024–2026 + 6 khoảng trống nghiên cứu |
| `02-de-xuat-de-tai/` | 6 đề tài ứng viên, bảng chấm điểm có trọng số, xếp hạng |
| `03-kiem-cheo-phan-bien/` | Vòng hỏi–đáp đối kháng từng đề tài, cập nhật độ tự tin tới ngưỡng ≥95% |
| `04-thiet-ke-nghien-cuu/` | Thiết kế chi tiết T1: giả thuyết, testbed, ma trận thử nghiệm, tiến độ 16 tuần, kế hoạch B |
| `05-ma-hoa-thuat-toan/` | Ghi chú nhánh mã hóa (an toàn, chạy trực tiếp) |
| `06-lo-hong-network/` | Ghi chú nhánh lỗ hổng (bắt buộc Docker + disclosure) |
| `docker-lab/` | Lab cách ly sẵn dùng: OpenSSL 3.5 ML-KEM, router netem, broker MQTT, mạng internal |

## Bước tiếp theo đề xuất

1. Đọc báo cáo PDF; nếu đưa ra hội đồng → phần "Hạn chế" đã viết sẵn để phản biện.
2. Phase 2: QUIC (quiche) + chuỗi chứng chỉ ML-DSA (kịch bản 5×–20× đầy đủ).
3. Theo dõi arXiv cs.CR/cs.NI hàng tuần (chống "bị giậm chân" cho phần fingerprint RQ2b).
