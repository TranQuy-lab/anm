# Thiết kế nghiên cứu — Đề tài T1 (phiên bản 2, sau kiểm chứng chéo)

> **Lịch sử.** Bản v1 của tài liệu này ghi "đã qua kiểm chéo 96%" — mức tự tin đó áp dụng cho
> **việc chọn đề tài**, không phải cho chất lượng thực thi. Kiểm chứng chéo **kết quả** (xem
> `07-kiem-chung-doc-lap/KIEM_CHUNG_DOC_LAP.md`) tìm ra lỗi thiết kế và lỗi độ trung thực của
> testbed, nên thiết kế dưới đây đã được sửa. Phần sai khác so với kế hoạch ban đầu được ghi
> rõ ở mục 6 — không giấu.

## 1. Khung nghiên cứu

- **Loại:** thực nghiệm có kiểm soát (controlled measurement) + học máy nhẹ.
- **Đơn vị phân tích:** phiên bắt tay TLS 1.3 và luồng (flow) sinh ra trong lab cách ly.
- **Giả thuyết (đã sửa để kiểm định được):**
  - **H1.** Nhóm lai X25519MLKEM768 làm **số segment cấp wire** của flight bắt tay tăng so với
    X25519 khi PMTU nhỏ hơn kích thước bắt tay.
  - **H2.** Nhóm lai làm **RTT bắt tay tăng**; hiệu ứng là **nhỏ về tuyệt đối** (< 0,5 ms trên
    liên kết cục bộ) nhưng **ổn định**.
  - **H3.** Khi PMTU nhỏ hơn kích thước bắt tay **và ICMP "fragmentation needed" bị lọc**,
    bắt tay lai **không hoàn tất**, trong khi X25519 không bị ảnh hưởng. Bỏ bất kỳ nhân tố nào
    (cho ICMP qua / bật MSS clamp / PMTU đủ lớn) là đủ để khôi phục.
  - **H4.** Việc chuyển nhóm KEM chỉ quan sát được qua **họ đặc trưng chạm vào bắt tay**; họ
    đặc trưng pha ứng dụng gần như không thấy gì.
  - **Giải thích cạnh tranh phải loại trừ:** (a) khác biệt do thứ tự chạy/trôi hệ thống →
    loại bằng **thiết kế xen kẽ**; (b) khác biệt do MTU bị GSO che → loại bằng **tắt offload**;
    (c) "hỏng do PQC" vs "hỏng do kích thước vượt PMTU" → phân biệt bằng **ô đối chứng PMTU 576**
    (ở đó X25519 cũng hỏng); (d) nhiễu `s_server` đơn luồng → loại bằng **restart server giữa
    các lần thử**.

## 2. Testbed

```
[pqc-client] --- netem router (tc delay/loss, MTU A/B, DNAT, TCPMSS) --- [pqc-server]
                          |
                 capture: dumpcap trên eth0 + eth1 (container riêng, chung netns)
```

- OpenSSL **3.5.1** biên dịch từ nguồn, ML-KEM mặc định; `s_server -WWW` phục vụ 6 file tĩnh.
- **Ba điều kiện bắt buộc** (nếu thiếu, phép đo vô nghĩa — xem hồ sơ kiểm chứng):
  1. `ethtool -K <if> tso/gso/gro off` trên router (nếu không, MTU bị GSO che);
  2. capture bằng **dumpcap** trên từng interface vật lý (không dùng `tcpdump -i any`);
  3. đơn vị netem tường minh (`50ms`, không phải `50`).
- Ma trận thực thi: {loss 0/1/3%} × {delay 0/50 ms} × {MTU 1500/1280} + MTU 576 = **13 cấu hình**,
  **30 cặp xen kẽ** mỗi cấu hình.

## 3. Thiết kế xen kẽ và thống kê (khai báo trước khi phân tích)

- Trong mỗi lần lặp, hai nhóm chạy **luân phiên** trong cùng phiên và cùng cấu hình mạng; chỉ số
  `rep` là khoá ghép cặp hợp lệ.
- Kiểm định chính **Mann–Whitney U** (hai mẫu độc lập) + **Holm–Bonferroni** trong từng họ metric;
  kèm permutation trên trung vị, bootstrap CI 95% cho hiệu trung vị, Cliff's δ và Hedges' g.
- **Mọi metric đều báo cáo**, kể cả kết quả bất lợi (bài học từ v1: `flow_dur` có ý nghĩa đã bị bỏ sót).
- Hoà giải tự động: số flow phân tích được phải bằng số lần chạy client có `exit_code=0`.

## 4. Đặc trưng & mô hình (RQ phân loại)

- Họ đặc trưng tách bạch: `handshake` (kích thước/segment bắt tay), `size_totals` (tổng byte cả
  kết nối), `app_totals` và `app_seq` (**chỉ** gói pha ứng dụng, sau flight-2 của client).
- Chia train/test **theo thời gian** trong từng lớp (không rò rỉ).
- **Bắt buộc** kèm phép kiểm tính tầm thường: 1-NN trên một đặc trưng duy nhất. Nếu phép kiểm
  này đã đạt xấp xỉ 1,0 thì bài toán không nói lên điều gì về classifier thật — và phải nói rõ.

## 5. Kế hoạch phân tích (theo thứ tự thực thi)

1. `extract_metrics.sh` → `packets_all.tsv`
2. `rq1_analysis.py` → byte, phân mảnh cấp wire, RTT + phân rã, thống kê
3. `rq23_analysis.py` → drift (cùng MTU, đổi MTU), thích ứng, ranh giới họ đặc trưng
4. `rq2b_group_classifier.py` → quan sát tối thiểu để nhận diện nhóm KEM + độ bền theo MTU
5. `check_ch_budget.py` → đối chiếu key_share với FIPS 203
6. `audit_kiemdinh.py` → 13 hạng mục kiểm định chéo độc lập
7. `md2pdf_report.py` → PDF

## 6. Sai khác so với kế hoạch v1 (ghi trung thực)

| Kế hoạch v1 | Thực thi v2 | Lý do |
|---|---|---|
| loss {0, 0.5, 1, 3%}, delay {0, 20, 100 ms} | loss {0, 1, 3%}, delay {0, 50 ms} | Giữ số cấu hình trong ngân sách thời gian; 50 ms mỗi chiều ⇒ RTT ~100 ms, đủ đại diện WAN nội địa |
| "paired test" | **thay bằng thiết kế xen kẽ + Mann–Whitney** | Kiểm định cặp ghép trên hai khối tuần tự là sai thiết kế (phát hiện khi kiểm chứng chéo) |
| QUIC ở giai đoạn 2 | **hoãn** | Ưu tiên sửa độ trung thực testbed và làm thí nghiệm PMTUD — khoảng trống thật sự của y văn |
| Hypothesis H2/H3 về "classifier suy giảm do drift" | **không xác nhận được** với fixture này | Fixture 6 site tầm thường; báo cáo trung thực là "không kiểm chứng được" thay vì giữ kết luận |

## 7. Rủi ro & kế hoạch B

| Rủi ro | Dấu hiệu | Kế hoạch B |
|---|---|---|
| Bị giậm chân | arXiv ra bài trùng delta | Đã xảy ra một phần: 6 tiền lệ được tìm thấy ⇒ **định vị lại** vào khoảng trống PMTUD thay vì đổi đề tài |
| Kết quả "không khác biệt" | H2 không bác bỏ H0 | Báo cáo như phát hiện vận hành (PQC không đắt RTT trên WAN) — nhánh này vẫn công bố được |
| Thí nghiệm PMTUD không tái hiện | ô "chặn ICMP" vẫn hoàn tất | Hạ tuyên bố xuống "quan sát được khi dựng lab" và nêu rõ điều kiện; **không** giữ tuyên bố nhân quả |
| `s_server` đơn luồng làm nhiễu | nhiều lần thử liên tiếp cùng hỏng | Restart server trước/sau mỗi lần thử không hoàn tất |

## 8. Phụ lục: ràng buộc an toàn khi chuyển sang hướng lỗ hổng (T4)

- Bắt buộc chạy trong `docker-lab` với network `internal: true`, không publish port ra host,
  không truy cập Internet từ container fuzzer.
- Chỉ nhắm dịch vụ mã nguồn mở tự vận hành trong lab; crash → artifact + responsible disclosure;
  tuyệt đối không quét/nhắm hệ thống bên ngoài.
