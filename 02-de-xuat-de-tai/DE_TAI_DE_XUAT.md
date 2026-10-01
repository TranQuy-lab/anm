# Danh mục đề tài đề xuất & xếp hạng (2026-10-01)

> Người yêu cầu thiên hướng đề tài về **mạng**. Ràng buộc an toàn: nghiên cứu mã độc/lỗ hổng
> bắt buộc cách ly Docker; thuật toán/mã hóa chạy trực tiếp được. Điểm thang 10 cho từng tiêu chí;
> "điểm tổng" là trung bình có trọng số: Tính mới 0.3, Khả thi 0.25, An toàn 0.15, Phù hợp mạng 0.2,
> Giá trị xuất bản 0.1.

## Bảng xếp hạng

| # | Đề tài (rút gọn) | Mới | Khả thi | An toàn | Mạng | XB | Điểm |
|---|---|---|---|---|---|---|---|
| **T1** | **Ảnh hưởng chuyển đổi PQC lên mạng: đo lường handshake → phân mảnh → hiệu năng, và khả năng nhận dạng lưu lượng sau drift** | 8.5 | 8.5 | 10 | 10 | 8.5 | **9.05** |
| T2 | ECH: những tín hiệu gì còn sót lại cho giám sát mạng khi không giải mã? | 9 | 7 | 8* | 10 | 8.5 | 8.60 |
| T3 | NIDS thích ứng concept-drift trên dataset tự sinh (Mininet/Docker testbed) | 6.5 | 8.5 | 10 | 9 | 7 | 8.05 |
| T4 | Fuzzing đa bên cho broker MQTT / server QUIC hướng LLM (tìm lỗ hổng) | 8 | 6.5 | 9** | 8.5 | 8.5 | 7.98 |
| T5 | Đánh giá độ bền đối kháng của ML DDoS detector trong SDN | 6 | 8 | 10 | 9 | 7 | 7.95 |
| T6 | ASCON (NIST lightweight crypto) tích hợp MQTT/CoAP cho IoT | 7 | 8 | 10 | 8 | 7.5 | 7.90 |

\* T2 cần đóng khung cẩn thận thành nghiên cứu phòng thủ (visibility cho doanh nghiệp) vì có yếu tố
song công (dual-use) khi nói về "né DPI".
\** T4 bắt buộc chạy trong Docker lab cách ly hoàn toàn (đã dựng sẵn ở `docker-lab/`), chỉ nhắm
vào mã nguồn mở tự vận hành, tuân thủ responsible disclosure.

## T1 — Đề tài khuyến nghị chính (chi tiết)

**Tên đầy đủ:** *"Đo lường và thích ứng trước sự dịch chuyển giao thức do mật mã hậu lượng tử:
tác động mạng và khả năng nhận dạng lưu lượng mã hóa TLS/QUIC"*

- **Câu hỏi nghiên cứu:**
  - RQ1: Kích thước handshake tăng (5×–20×) của ML-KEM hybrid gây bao nhiêu phân mảnh/mất gói
    trên đường truyền có mất gói/trễ kiểm soát được, và ảnh hưởng thế nào đến RTT/throughput?
  - RQ2: Sau khi giao thức drift sang X25519MLKEM768, classifier lưu lượng mã hóa huấn luyện
    trên dữ liệu cũ suy giảm thế nào khi mở rộng sang QUIC (chưa được kiểm chứng y văn)?
  - RQ3: Chiến lược thích ứng nào (fine-tune, feature any hóa, tập dữ liệu ghép) khôi phục
    độ chính xác với chi phí nhỏ nhất?
- **Đóng góp kỳ vọng:** (1) pipeline thực nghiệm tái lập được (Docker + OpenSSL 3.5 ML-KEM
  + netem + tshark); (2) bộ số liệu công khai TLS/QUIC trước–sau PQC; (3) phân tích thích ứng
  drift (không chỉ chẩn đoán như arXiv:2608.22683).
- **An toàn:** không mã độc, không nhắm hệ thống thật, toàn bộ trong lab cục bộ. Mã hóa thuần
  nên theo ràng buộc của người dùng có thể chạy trực tiếp — dùng Docker chỉ để tái lập.

## T4 — Đề tài hướng lỗ hổng (chi tiết ràng buộc)

- Chỉ fuzz phần mềm mã nguồn mở tự vận hành (Mosquitto/EMQX, ngtcp2/quic-go) **bên trong Docker
  network `internal`**, không xuất cổng ra host/Internet, không bao giờ quét hệ thống bên ngoài.
- Mọi crash → lưu artifact, báo cáo theo responsible disclosure (CVE nếu được chấp nhận).
- Khả thi trung bình do công kỹ thuật lớn; giữ làm phương án thứ hai hoặc giai đoạn 2 của T1.

## Điều kiện chuyển tiếp giữa các đề tài

- T1 hoàn tất sớm → mở rộng sang T2 (ECH) như phase 2 tự nhiên.
- Muốn hướng công cụ/lỗ hổng → T4 với lab Docker sẵn có.
- Muốn hướng dataset/ML → T3 kế thừa trực tiếp testbed của T1.
