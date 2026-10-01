# Ghi chú nhánh lỗ hổng giao thức mạng (BẮT BUỘC cách ly Docker)

> Quy tắc của người dùng: nghiên cứu lỗ hổng/mã độc → bắt buộc Docker tách biệt. File này
> ghi ràng buộc vận hành; lab mẫu nằm ở `docker-lab/`.

## 1. Đối tượng nghiên cứu hợp lệ

- Phần mềm mã nguồn mở **tự vận hành trong lab**: Mosquitto/EMQX (MQTT), ngtcp2/quic-go/nghttp3
  (QUIC), h2o/nghttp2 (HTTP/2), máy chủ DNS BIND/Unbound trong mạng nội bộ giả lập.
- Tuyệt đối KHÔNG: quét hay gửi packet tới IP ngoài lab; thử nghiệm trên dịch vụ của bên thứ ba;
  phát hành PoC trước khi vendor có bản vá (theo coordinated disclosure 90 ngày).

## 2. Ràng buộc cách ly trong Docker (checklist bắt buộc trước mỗi phiên fuzzing)

1. `docker compose` dùng mạng `internal: true` — container không có route ra Internet.
2. Không khai báo `ports:` ra host; nếu cần debug → dùng `docker exec` trong lab.
3. Container fuzzer chạy user không phải root; drop capabilities không cần thiết
   (`cap_drop: [ALL]`, chỉ thêm những cái cần).
4. Snapshot trạng thái: image/tag cố định + volume riêng cho crash artifact
   (`./artifacts:/lab/artifacts`) để truy vết sau.
5. Resource limit (`mem_limit`, `cpus`) để fuzzing không làm sập máy host.
6. Trước khi publish bất kỳ crash nào: kiểm tra lại không chứa dữ liệu ngoài lab trong artifact.

## 3. Dư địa nghiên cứu (từ khảo sát y văn — xem 01-tong-quan-y-van)

- **Trạng thái sâu (deep states)**: fuzzer khó chạm trạng thái giao thức xa — hướng suy luận
  state machine tự động (stateful SCGF, statemap, arXiv:2408.06844).
- **Đa bên (multi-party)**: MBFuzzer (USENIX Sec'25) mới mở hướng cho broker MQTT — broker
  nhiều client, nhiều subscriber — dư địa cho QUIC đa luồng connection.
- **LLM-assisted**: dùng LLM suy luận state model/ sinh thông điệp hợp lệ (arXiv:2508.01750,
  MultiFuzz 2508.14300) — còn non trẻ, benchmark chưa thống nhất.
- **Khoảng trống hợp nhất**: chưa có khung đánh giá chung TLS+QUIC+MQTT (search 2026-10-01).

## 4. Quy trình responsible disclosure (mặc định khi tìm được lỗi)

1. Lưu crash + reproduce script (chỉ chạy được trong lab).
2. Kiểm tra lại trên phiên bản mới nhất của upstream để tránh báo lỗi đã vá.
3. Báo cáo riêng tư cho security contact của dự án (SECURITY.md / security.txt).
4. Chờ đúng thời hạn công bố của dự án; nhấn mạnh tác động theo CWE.
5. Trong bài báo: chỉ mô tả ở mức phương pháp + số lượng lỗi đã xác nhận với vendor.

## 5. Quan điểm chuyên gia (từ vòng kiểm chéo — độ tự tin 86%)

T4 là đề tài tốt nhưng công kỹ thuật lớn và có rủi ro "không ra kết quả dương". Khuyến nghị:
làm **sau** T1 hoặc song song phần nhỏ (fuzz broker MQTT như bài tập nền), để tích lũy kỹ năng
state machine trước khi mở rộng. Nếu người dùng quyết định đi T4 ngay: bắt đầu bằng tái lập
kết quả fuzzer công khai (baseline) trong Docker lab để hiệu chỉnh harness — đây là bước an
toàn về mặt nghiên cứu (không đụng hệ thống ngoài) và về mặt học thuật (đối chứng).
