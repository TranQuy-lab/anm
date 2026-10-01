# Bản đồ y văn — An ninh mạng / Mã hóa / Lỗ hổng (cắt cạnh 2024–2026)

> Ngày khảo sát: 2026-10-01. **Đã cập nhật sau kiểm chứng chéo** (xem
> `07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md`): sáu công trình tiền lệ được bổ sung và nhiều
> chi tiết trích dẫn được sửa. Phương pháp: truy vấn đa nguồn (arXiv, ScienceDirect, MDPI, USENIX,
> IETF/CSA) theo quy trình literature-review. Mỗi nhận định dưới đây gắn với nguồn; phần suy luận
> của agent được ghi rõ là "suy luận".

## 1. Lưu lượng mã hóa & khả năng quan sát mạng (thiên hướng chính: MẠNG)

| Nguồn | Nội dung cốt lõi | Khoảng trống nó hé lộ |
|---|---|---|
| Zhou et al. 2024, *Electronics* (MDPI), TLS 1.3 survey — cited 63 | TLS 1.3 mã hóa handshake, phá phương pháp giám sát truyền thống | Cần kỹ thuật phát tín hiệu còn sót lại |
| Sharma et al. 2025, *Computer Networks* | Survey toàn cảnh encrypted traffic: an toàn ↑ nhưng visibility ↓ | Cân bằng privacy vs. giám sát chưa có khung giải pháp |
| Luxemburk et al., TMA 2023 — QUIC | QUIC không còn trường metadata plaintext → phân loại khó căn bản | Bộ dữ liệu QUIC công khai còn thiếu |
| Merlach et al. 2025 (MDPI) — ECH passive view | Phân tích thụ động ECH+HTTPS-DNS đầu tiên trên mạng vận hành 1 tháng | Chưa có nghiên cứu hệ thống trong lab về tín hiệu còn sống sót |
| Corrata 2026 (industry) | ~17% site bật ECH vẫn lộ metadata quan sát được | Chưa ai hệ thống hóa "leak surface" thành phương pháp phát hiện |
| RFC 9849 (ECH chuẩn hóa) | Định nghĩa chính thức attacker model thụ động/tích cực | Vấn đề policy/enterprise còn bỏ ngỏ |
| arXiv:2503.20093 | Robustness của classifier lưu lượng mã hóa | Generalization cross-protocol chưa rõ |

## 2. Chuyển đổi hậu lượng tử (PQC) — giao điểm MẠNG × MÃ HÓA

| Nguồn | Nội dung cốt lõi | Khoảng trống nó hé lộ |
|---|---|---|
| **arXiv:2608.22683 (8/2026) "The Colossus with Feet of Clay"** | Benchmark website-fingerprinting cặp Non-PQC/Hybrid-PQC (X25519MLKEM768); accuracy sụp khi cross-domain | Họ làm **fingerprinting**, không làm mạng; chưa đo PMTUD/MTU |
| **arXiv:2503.17830 (3/2025, sửa 1/2026)** | Phân loại cổ điển vs PQ **98–100%**; nhận dạng đúng thuật toán PQ 97% (KEX); phân biệt liboqs/CIRCL; áp dụng TLS/SSH/QUIC/OpenVPN/OIDC; tìm domain PQC trong Tranco | ⇒ **không thể tuyên bố "đầu tiên"** về fingerprint PQC |
| **IACR ePrint 2026/834 (5/2026)** | Đọc key_share ở mức byte trong ServerHello; phân loại CLASSICAL_ONLY/PQC_ONLY/HYBRID_CONFIRMED; xác nhận nhóm 0x11EC trên 38 endpoint thật | Như trên |
| **arXiv:2604.24869 (4/2026)** | Handshake tăng 5×–20× (chuỗi chứng chỉ); TTFB theo **giới hạn flight** tầng vận chuyển; Merkle Tree Certificates | Đã chạm MTU/flight limit ⇒ không tuyên bố "đầu tiên đo tác động mạng" |
| **arXiv:2603.11006 (3/2026, SPIQE @ EuroS&P)** | Đo TLS 1.3 theo từng tầng (TCP, TCP-TLS, TLS, TLS-HTTP, HTTP) cho cổ điển/lai/thuần PQC, 30+ thí nghiệm | Như trên |
| **ePrint 2019/1447 (PQCrypto 2020)** | Mạng giả lập: mất gói >3–5% hại nặng thuật toán PQC phải phân mảnh | Đã biết từ 2019 |
| **RFC 9954 (7/2026)** / **RFC 9958 (6/2026)** | Chuẩn hóa hybrid key exchange cho TLS 1.3 / hướng dẫn kỹ sư PQC. RFC 9954 §4 nói rõ ML-KEM *"may result in ClientHello messages larger than a single packet"* | **Chưa ai đo hệ quả vận hành của việc đó** — đây là khoảng trống T1 khai thác |
| NIST FIPS 203/204/205 (8/2024); NIST IR 8547 (**draft**, 11/2024) | Chuẩn hóa PQC hoàn tất | Áp lực chuyển đổi thực tế |
| Nagy et al., *Sci* 7(3):91 (2025) | ML-KEM trên Raspberry Pi 4B: KeyGen 65,6 / Encap 79,8 / Decap 103,8 µs (liboqs) | Tính toán KHÔNG phải nút thắt — **lưu ý: con số 58/51 µs mà bản v1 gán cho Pi 4 thực ra là đo trên Intel Xeon E5-2680 v4** (ePrint 2026/1467) |
| CSA guidance; IETF PQC for Engineers | MTU drop → phân mảnh cho handshake lớn | Thiếu mô hình thực nghiệm có kiểm soát, đặc biệt khi ICMP bị lọc |

**Suy luận then chốt (agent, đã thu hẹp sau kiểm chứng chéo):** cộng đồng đã thống nhất
"PQC nhanh về CPU, nặng về mạng", và **đã có** công trình đo hiệu năng mạng (2603.11006,
2604.24869), **đã có** công trình fingerprint PQC (2503.17830, ePrint 2026/834, 2608.22683).
Khoảng trống **còn thật sự mở** — sau khi tìm nhiều truy vấn khác nhau mà không thấy công trình
nào làm — là: **hành vi PMTUD/ICMP-blackhole của bắt tay PQC khi ICMP "fragmentation needed"
bị lọc**, và **đo tỉ lệ blackhole ngoài Internet thật**. Đây là chỗ đề tài T1 đặt đóng góp.

## 3. IDS / phát hiện tấn công mạng

- **Dataset lỗi thời**: CIC-IDS2017/2018, UNSW-NB15 bị phê phán chất lượng thấp, mẫu traffic cũ
  (arXiv "Network Intrusion Datasets: A Survey, Limitations"; ScienceDirect IoT IDS survey) →
  accuracy ~99% không chuyển được sang tấn công mới.
- **Concept drift**: vấn đề mở được thừa nhận từ Mahdi et al. (cited 38) đến các hệ thích ứng
  2025 (CCA-ID); SDN làm drift nhanh hơn nữa.
- **LLM trong phát hiện tấn công**: Springer SLR 2025 (455 trích dẫn), C&S survey (210);
  hướng dùng flow statistics cho LLM (T5) mới xuất hiện → cạnh tranh cao, chi phí tính toán lớn.

## 4. Fuzzing giao thức (hướng LỖ HỎNG)

- arXiv:2401.01568 (survey protocol fuzzing, ~97 trích dẫn): thách thức = đạt trạng thái sâu.
- arXiv:2301.02490: taxonomy fuzzers stateful + research directions.
- QUIC: arXiv:2503.19402 greybox fuzzer (2025); MQTT: MBFuzzer (USENIX Sec'25, multi-party);
  LLM-assisted fuzzing MQTT (arXiv:2508.01750, 8/2025); MultiFuzz (arXiv:2508.14300).
- **Khoảng trống**: fuzzing đa bên cho QUIC + tích hợp LLM suy luận state machine; thống nhất
  TLS+QUIC+MQTT trong một khung đánh giá (search chưa thấy survey hợp nhất).

## 5. SDN / 5G

- Kalambe et al. 2025 (JNCA, cited 37) + Batool et al. 2025 (Electronics): DDoS lên control plane
  SDN — saturation attack chưa giải quyết triệt để.
- 5G slicing: isolation/side-channel giữa slice; zero-trust operationalization còn ở mức khung lý thuyết.
- Dataset SDN mới: DDOSDN2025 (Mendeley) → chứng tỏ nhu cầu dataset thế hệ mới.

## 6. Mật mã nhẹ cho IoT (hướng MÃ HÓA thuần)

- NIST ASCON (2023) là chuẩn lightweight crypto; hướng đi: tích hợp ASCON vào MQTT/CoAP,
  benchmark trên constrained device, so sánh AES-GCM. Cạnh tranh vừa phải, khả thi cao.

---
**Tổng hợp khoảng trống có thể khai thác (gap → đề tài)**:
1. PQC migration tác động mạng + thích ứng (gap #2) → **T1** ← khuyến nghị
2. Tầm nhìn mạng dưới ECH (gap #1) → **T2**
3. Drift-aware NIDS + dataset tự sinh (gap #3) → **T3**
4. Fuzzing đa bên QUIC/MQTT (gap #4) → **T4**
5. Robust ML chống DDoS trong SDN (gap #5) → **T5**
6. ASCON cho IoT networking (gap #6) → **T6**

Chi tiết chấm điểm & xếp hạng: xem `02-de-xuat-de-tai/DE_TAI_DE_XUAT.md`.
Kiểm chéo đối kháng từng đề tài: xem `03-kiem-cheo-phan-bien/PHAN_BIEN_KIEM_CHEO.md`.
