# Ghi chú nhánh thuật toán mã hóa (an toàn — chạy trực tiếp được, không cần cách ly)

> Theo ràng buộc của người dùng: nghiên cứu thuật toán/mã hóa KHÔNG ảnh hưởng máy → không bắt
> buộc Docker. Tuy nhiên testbed T1 vẫn dùng Docker vì lý do tái lập, không phải an ninh.

## 1. Bản đồ thuật toán đáng theo dõi (2025–2026)

| Họ | Thuật toán | Chuẩn | Trạng thái nghiên cứu |
|---|---|---|---|
| PQC-KEM | ML-KEM (Kyber) | FIPS 203 | Chuẩn hóa xong; OpenSSL 3.5 có sẵn; dư địa = tác động mạng/vận hành |
| PQC-Chữ ký | ML-DSA (Dilithium), SLH-DSA (SPHINCS+) | FIPS 204/205 | Chuỗi chứng chỉ lớn 5×–20× → vấn đề MTU (nối sang T1) |
| Hybrid | X25519MLKEM768 | IETF **RFC 9954** (7/2026) | Đang là cầu nối chuyển đổi; Chrome/Firefox/Cloudflare đã bật |
| Lightweight | ASCON | NIST SP 800-232 | IoT/constrained; dư địa tích hợp MQTT/CoAP (đề tài T6) |
| Cổ điển | AES-GCM, ChaCha20-Poly1305, X25519, Ed25519 | — | Cơ sở so sánh mọi benchmark |

## 2. Thí nghiệm "an toàn tuyệt đối" có thể làm ngay trên máy này

1. **So sánh kích thước handshake cổ điển vs hybrid** (gói tin chụp được, không payload):
   `openssl s_client -groups X25519MLKEM768 -tls1_3 ...` vs `-groups X25519` → đo bằng tshark.
2. **Benchmark CPU KEM**: `openssl speed` với nhóm quantum-safe (OpenSSL 3.5 hỗ trợ speed
   cho các nhóm KEM) → xác nhận "CPU không phải nút thắt".
3. **Vẽ bảng MTU**: tính kích thước ClientHello/HelloRetry với từng nhóm → dự đoán ngưỡng
   phân mảnh, đối chiếu với phép đo thật.
4. (T6) Nhúng ASCON (thư viện C tham khảo của NIST) vào MQTT thử nghiệm, đo overhead.

Tất cả các thí nghiệm trên: không mã độc, không nhắm dịch vụ nào, chỉ loopback/lab cục bộ.

## 3. Cạm bẫy đã được skill ctf-crypto/security-agent nhắc nhở (áp dụng vào nghiên cứu)

- Đừng tự chế "thuật toán mã hóa mới" làm đề tài — chuẩn hóa và cryptanalysis là việc của
  cộng đồng hàng chục năm; rủi ro bị bóc lỗi thiết kế rất cao. Nghiên cứu có giá trị nằm ở
  **tích hợp, đo lường, vận hành** (systematization & measurement), không phải phát minh nguyên bản.
- Mọi benchmark phải công bố: phiên bản thư viện, cờ biên dịch, phần cứng, số lần lặp,
  phân vị (p50/p95) chứ không chỉ trung bình.

## 4. Nguồn chính

- NIST FIPS 203/204/205; NIST IR 8547 (**Initial Public Draft**, 11/2024 — chưa phải bản cuối);
- IETF **RFC 9954** *Hybrid Key Exchange in TLS 1.3* (7/2026) và **RFC 9958** *Post-Quantum
  Cryptography for Engineers* (6/2026) — cả hai đã là RFC, không còn là Internet-Draft;
- OpenSSL 3.5 release notes (ML-KEM/ML-DSA/SLH-DSA mặc định);
- Tiền lệ đã chiếm phần "fingerprint PQC": arXiv:2503.17830 (Mallick et al.), IACR ePrint
  2026/834 (Ibrahim et al.), arXiv:2608.22683 (Li et al.);
- Tiền lệ đã đo hiệu năng mạng của PQC: arXiv:2604.24869 (Chou & Cao),
  arXiv:2603.11006 (Gómez-Cambronero et al.), ePrint 2019/1447 (Paquin et al.);
- Khoảng trống còn mở mà T1 khai thác: **PMTUD/ICMP-blackhole cho bắt tay PQC**.
