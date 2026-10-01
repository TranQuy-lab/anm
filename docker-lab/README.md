# Docker Lab — cách ly cho nghiên cứu an ninh mạng

Lab này phục vụ 2 mục đích:
- **T1 (PQC × mạng):** đo handshake TLS 1.3 cổ điển vs hybrid ML-KEM, kiểm soát loss/delay/MTU qua router netem.
- **T4 (lỗ hổng/fuzzing):** cách ly tuyệt đối cho broker MQTT và (sau này) server QUIC.

## Kiến trúc

```
[lab-pqc-client] --- labnet-a --- [lab-netem-router] --- labnet-b --- [lab-pqc-server]
                                                                        (4433, chỉ nội bộ)
[lab-mqtt-broker] nằm ở labnet-b — không mở port ra host, không ra Internet
```

Cả hai mạng đều `internal: true` (Docker chặn route ra ngoài). Không service nào khai báo
`ports:` → không gì lọt ra host/Internet.

## Chạy lần đầu

```bash
cd docker-lab
docker compose build                 # build OpenSSL 3.5 (build fail nếu thiếu ML-KEM → là ý muốn)
docker compose up -d pqc-server netem-router
# đặt tham số mạng (tùy chọn, mặc định 20ms/0%/1500):
#   docker compose down && LOSS=3% DELAY=100ms MTU=1280 docker compose up -d netem-router
docker compose up -d netem-router
docker compose run --rm pqc-client   # chạy vòng đo handshake X25519 vs X25519MLKEM768
```

## Bắt gói tin (chạy trên HOST, lọc đúng subnet lab)

```bash
# tìm bridge interface của labnet-a:
docker network inspect labnet-a | jq -r '.[0].Options["com.docker.network.bridge.name"] // "br-?(xem Id)"'
# hoặc: ip -o link | grep br-
sudo tshark -i <bridge-iface> -f "net 172.30.10.0/24" \
     -w /tmp/lab_tls_$(date +%s).pcapng
```
(Chiếc capture chạy trên host vì bridge Linux là switched — container thứ ba trên cùng mạng
không thấy unicast của cặp khác.)

## Xác minh an toàn trước mỗi phiên

```bash
docker compose exec netem-router ping -c2 9.9.9.9   # PHẢI thất bại (internal network) → cách ly OK
docker compose ps                                    # không service nào có mapping port host
```

## Vị trí kết quả

- Log handshake client: volume gắn `/lab/results` → `docker compose cp pqc-client:/lab/results .`
- pcap: `/tmp` trên host (chuyển vào thư mục `04-thiet-ke-nghien-cuu/data/` khi hoàn tất).

## Lưu ý trung thực

- `s_time_connect`/vòng đo trong `role.sh` là khung khởi điểm, không phải benchmark hoàn chỉnh —
  giai đoạn tuần 1–2 của thiết kế nghiên cứu là hiệu chỉnh lại script đo (p50/p95, paired design).
- QUIC (quiche/ngtcp2) là phase 2 — thêm service riêng vào compose, vẫn giữ nguyên cách ly.
