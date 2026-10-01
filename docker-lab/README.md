# Docker Lab — cách ly cho nghiên cứu an ninh mạng

Lab này phục vụ 2 mục đích:
- **T1 (PQC × mạng):** đo handshake TLS 1.3 cổ điển vs hybrid ML-KEM, kiểm soát loss/delay/MTU
  qua router netem — kể cả **thí nghiệm PMTUD blackhole có kiểm soát**.
- **T4 (lỗ hổng/fuzzing):** cách ly tuyệt đối cho broker MQTT và (sau này) server QUIC.

> **Đã cập nhật cho bản v2.** Các script chính nay là `run_matrix2.sh` (thiết kế xen kẽ + MTU
> thật), `run_pmtud.sh`, `run_ch_budget.sh`, `run_order_control.sh`. `run_matrix.sh` và
> `run_sites_m1280.sh` là **bản v1 lịch sử** (chạy khối tuần tự, capture bị GSO che) — giữ để
> đối chiếu, không dùng cho kết quả mới.

## Kiến trúc

```
[lab-pqc-client] --- labnet-a --- [lab-netem-router] --- labnet-b --- [lab-pqc-server]
   (OpenSSL 3.5.1 s_client)        (DNAT + tc/netem + TCPMSS)         (s_server -WWW, 4433)
                                          |
                       capture: container RIÊNG chia sẻ netns với router (dumpcap, eth0+eth1)
[lab-mqtt-broker] nằm ở labnet-b — không mở port ra host, không ra Internet
```

Cả hai mạng đều `internal: true`. Không service nào khai báo `ports:` → không gì lọt ra host/Internet.

## Ba điều kiện BẮT BUỘC để phép đo có nghĩa

1. **Tắt GSO/TSO/GRO trên NIC ảo của router** — `role.sh` làm tự động bằng `ethtool` (và in cảnh
   báo nếu thiếu). Không tắt, gói 1847 B vẫn đi qua link MTU 576 và chiều "MTU" trở nên vô nghĩa.
2. **Capture bằng `dumpcap` trên từng interface vật lý** (`pqc-node/capture.sh`, chạy trong
   container riêng chia sẻ netns với router). `tcpdump -i any` mất gói trong workload này và bản
   4.99.4 trong image **chỉ nhận `-i` cuối cùng** nên mất hẳn một chiều.
3. **Đơn vị netem tường minh** (`50ms`, không phải `50` — số trần bị hiểu là **micro giây**).

Thêm cho thí nghiệm PMTUD: **router phải là điểm nghẽn thật** (`MTU_A=1500`, `MTU_B` nhỏ; nếu đặt
nhỏ cả hai phía thì gói lớn bị chặn ở bridge/veth phía host *trước* router và phép can thiệp ICMP
trở nên vô nghĩa) và **capture phải gồm ICMP** (`'tcp port 4433 or icmp'`, snaplen 0).

## Chạy

```bash
cd docker-lab
docker compose build                 # OpenSSL 3.5.1 + ethtool; build fail nếu thiếu ML-KEM (là ý muốn)

bash run_matrix2.sh                  # 13 cấu hình × 30 cặp XEN KẼ + 2 dataset phân loại (~10 phút)
bash run_pmtud.sh                    # PMTUD blackhole có kiểm soát, 9 ô × 6 lần (~10 phút)
bash run_ch_budget.sh                # capture snaplen đầy đủ + keylog để đối chiếu FIPS 203 (~1 phút)
N_HS=60 bash run_order_control.sh    # đối chứng đảo thứ tự ngẫu nhiên (~6 phút)
```

Tham số mạng khi chạy tay một cấu hình:

```bash
LOSS=3 DELAY=50ms MTU=1280 CLAMP=on DROP_ICMP_FRAG=0 \
  docker compose up -d --force-recreate --no-deps netem-router
```
(`CLAMP=off` để PMTUD phải tự xử lý; `DROP_ICMP_FRAG=1` để chặn ICMP type 3 code 4.)

## Bắt gói tin

Dùng `pqc-node/capture.sh` trong container chia sẻ netns (xem điều kiện 2 ở trên):

```bash
docker run -d --name cap --net=container:lab-netem-router \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/results:/lab/results" -v "$PWD/pqc-node:/lab/scripts:ro" nckh/pqc-node:3.5 \
  bash /lab/scripts/capture.sh /lab/results/mycap.pcapng 160 "tcp port 4433"
# ... chạy thí nghiệm ...
docker kill -s INT cap && docker rm -f cap    # script tự chmod 644 file kết quả
```

## Xác minh an toàn trước mỗi phiên

```bash
docker compose exec netem-router ping -c2 9.9.9.9   # PHẢI thất bại (internal network) → cách ly OK
docker compose ps                                    # không service nào có mapping port host
```

## Vị trí kết quả

- CSV lần chạy + pcap: volume gắn `/lab/results` → `docker-lab/results/`
  (`hs2_*.csv`, `sites2_M*.csv`, `pmtud_trials.csv`, `pcap2_*.pcapng`, `pcap_pmtud_*.pcapng`).
- Dữ liệu thô **không** commit vào git (tái tạo bằng script); bảng/phân tích đã commit nằm ở
  `04-thiet-ke-nghien-cuu/analysis/tables/`.

## Lưu ý trung thực

- Capture của ma trận dùng snaplen 160 (đủ cho `tcp.len`/phân mảnh); kiểm tra mức payload cần
  `run_ch_budget.sh` (snaplen 0 + keylog).
- Offload chỉ được tắt trên router: **leg ingress** từ client vẫn có thể là GSO super-packet, nên
  muốn đo "kích thước packet" phải dùng **leg egress** (xem `wire_cl_first` trong
  `rq1_analysis.py`). Đây chính là artifact đã được phát hiện và sửa ở bản v3 của RQ2b.
- QUIC (quiche/ngtcp2) là phase 2 — thêm service riêng vào compose, vẫn giữ nguyên cách ly.
