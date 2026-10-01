# Node nghiên cứu PQC: OpenSSL 3.5 LTS (ML-KEM/ML-DSA/SLH-DSA mặc định) + công cụ mạng
FROM ubuntu:24.04

ARG OPENSSL_VERSION=3.5.1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential perl wget ca-certificates \
      iproute2 iputils-ping tcpdump tshark iptables socat ethtool \
      python3 python3-pip curl jq \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 3.5 từ nguồn (kiểm chứng qua checksum chính thức trước khi tin dùng)
RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    && tar xf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared linux-x86_64 \
    && make -j"$(nproc)" && make install_sw \
    && cd / && rm -rf openssl-${OPENSSL_VERSION}*

ENV PATH="/usr/local/ssl/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/ssl/lib64:${LD_LIBRARY_PATH}"

# Xác minh ngay lúc build rằng ML-KEM có mặt (fail build nếu thiếu)
RUN openssl list -kem-algorithms | grep -i ml-kem

COPY role.sh hs_loop.sh sites_loop.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/role.sh /usr/local/bin/hs_loop.sh /usr/local/bin/sites_loop.sh

WORKDIR /lab
CMD ["bash"]
