# Thiết kế nghiên cứu — Đề tài T1 (đã qua kiểm chéo 96%)

## 1. Khung nghiên cứu

- **Loại:** thực nghiệm có kiểm soát (controlled measurement) + học máy nhẹ.
- **Đơn vị phân tích:** phiên bắt tay TLS/QUIC và luồng (flow) sinh ra trong lab.
- **Giả thuyết:**
  - H1: với mất gói ≥1% hoặc MTU nhỏ, hybrid X25519MLKEM768 làm RTT bắt tay và tỉ lệ phân mảnh
    tăng có ý nghĩa so với X25519 thuần (kiểm định: paired test + effect size).
  - H2: classifier huấn luyện trên dữ liệu pre-PQC suy giảm khi gặp post-PQC, kể cả trên QUIC.
  - H3: fine-tune trên tập nhỏ (<10% dữ liệu mới) khôi phục phần lớn độ chính xác.
  - Rival explanation phải loại trừ: khác biệt do cài đặt TCP/QUIC, do hằng số thời gian tải,
    do phân bố site — ghi nhận trong thiết kế (theo skill hypothesis-generation: luôn lập
    giải thích cạnh tranh trước khi chọn test).

## 2. Testbed (đã dựng sẵn: `docker-lab/`)

```
[pqc-client] ---netem router (tc: delay/loss/mtu)--- [pqc-server]
                     |
              [capture: tshark trên bridge host]
```
- OpenSSL 3.5 (ML-KEM mặc định) cho TLS 1.3: `s_server`/`s_client`, tham số `-groups
  X25519MLKEM768` vs `X25519`.
- QUIC (phase 2): quiche (Cloudflare, đã hỗ trợ hybrid KEM) hoặc ngtcp2.
- Ma trận thử nghiệm: {X25519, X25519MLKEM768} × {loss 0/0.5/1/3%, delay 0/20/100ms,
  MTU 1500/1280/576} × {file 10KB/1MB/10MB} × 30 lặp → đủ để kiểm định (skill statistical-power:
  tính trước n với α=0.05, power 0.8).

## 3. Đặc trưng & mô hình (RQ2/RQ3)

- Đặc trưng flow: độ dài chuỗi gói bắt tay, số packet/byte mỗi hướng, IAT, kích thước bản ghi
  TLS/QUIC frame —KHÔNG cần payload.
- Mô hình: Random Forest / XGBoost baseline (CPU-only) trước, chỉ dùng DL nếu cần thiết.
- Quy trình chống "leakage": tách session/website giữa train/test (never cross-session), báo cáo
  macro-F1 kèm khoảng tin cậy bootstrap.

## 4. Tiến độ gợi ý (16 tuần)

| Tuần | Việc |
|---|---|
| 1–2 | Cài testbed, xác minh `openssl list -kem-algorithms` có ML-KEM; chụp handshake đầu tiên |
| 3–4 | Chạy ma trận TLS; viết script tự động hóa + thu thập CSV |
| 5–6 | Phân tích RQ1 (thống kê); vẽ biểu đồ |
| 7–9 | Sinh dataset flow + huấn luyện baseline classifier; tái lập hiện tượng drift (RQ2) |
| 10–12 | Thí nghiệm thích ứng (RQ3); fine-tune/ghép dataset |
| 13–14 | QUIC phase 2 (nếu thời gian cho phép; nếu không → future work) |
| 15–16 | Viết báo cáo/bài báo; phát hành dataset + code (GitHub, license rõ ràng) |

## 5. Rủi ro & kế hoạch B (từ kiểm chéo vòng 5)

| Rủi ro | Dấu hiệu | Kế hoạch B |
|---|---|---|
| Bị giậm chân (scooped) | arXiv tuần nào đó ra bài trùng delta | Pivot sang T2 (ECH), tái dùng testbed |
| QUIC build khó | quiche/boringssl không build được | Thu hẹp về TLS, nêu QUIC là future work |
| Kết quả "không khác biệt" | H1 không bác bỏ H0 | Báo cáo như phát hiện tích cực cho vận hành; bổ sung vùng tham số khắc nghiệt hơn (MTU 576, loss 3%) |

## 6. Phụ lục: ràng buộc an toàn khi chuyển sang hướng lỗ hổng (T4)

- Bắt buộc chạy trong `docker-lab` với network `internal: true`, không publish port ra host,
  không truy cập Internet từ container fuzzer.
- Chỉ nhắm dịch vụ mã nguồn mở tự vận hành trong lab; crash → artifact + responsible disclosure;
  tuyệt đối không quét/nhắm hệ thống bên ngoài.
