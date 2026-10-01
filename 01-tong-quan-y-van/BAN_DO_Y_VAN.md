# Bản đồ y văn — An ninh mạng / Mã hóa / Lỗ hổng (cắt cạnh 2024–2026)

> Ngày khảo sát: 2026-10-01. Phương pháp: truy vấn đa nguồn (arXiv, ScienceDirect, MDPI, USENIX,
> IETF/CSA) theo quy trình literature-review (skill giáo sư). Mỗi nhận định dưới đây gắn với nguồn;
> phần suy luận của agent được ghi rõ là "suy luận".

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
| **arXiv:2608.22683 (8/2026) "The Colossus with Feet of Clay"** | Chẩn đoán: PQC drift (X25519 → X25519MLKEM768 trong TLS 1.3) làm sụt accuracy của classifier đã huấn luyện | Họ chỉ **chẩn đoán**, chưa có (a) đo lường tác động mạng, (b) QUIC, (c) giải pháp thích ứng, (d) dataset công khai |
| NIST FIPS 203/204/205 (ML-KEM/ML-DSA/SLH-DSA) | Chuẩn hóa PQC hoàn tất | Áp lực chuyển đổi thực tế: NIST IR 8547 khử RSA/ECC khỏi FIPS |
| IETF "PQC for Engineers" (5/2025) | IKEv2 fragmentation lỗi ở IKE_SA_INIT; hybrid trong TLS 1.3 (draft-ietf-tls-hybrid-design) | Vấn đề MTU/fragmentation network-level chưa đo hệ thống |
| arXiv (handshake-size study) | Chuỗi chứng chỉ PQC làm handshake tăng 5×–20× | Tác động lên đường truyền mất gói/trễ chưa được định lượng đầy đủ |
| Raspberry Pi 4 benchmark (Semantic Scholar/RG) | ML-KEM-512: ~58µs enc / 51µs dec → tính toán KHÔNG phải nút thắt | Nút thắt nằm ở **mạng**, không phải CPU → đúng trọng tâm nghiên cứu mạng |
| CSA guidance | MTU drop → fragmentation/segmentation cho handshake lớn | Thiếu mô hình thực nghiệm có kiểm soát (controlled testbed) |

**Suy luận then chốt (agent):** cộng đồng đã thống nhất "PQC nhanh về CPU, nặng về mạng" nhưng
chưa có pipeline thực nghiệm công khai đo (kích thước handshake → phân mảnh → mất gói → RTT/throughput)
và đồng thời đánh giá hệ quả nhận dạng lưu lượng + biện pháp thích ứng. Đây là lỗ hổng nghiên cứu.

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
