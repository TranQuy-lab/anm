#!/usr/bin/env python3
# check_ch_budget.py — bóc TÁCH key_share từ capture snaplen ĐẦY ĐỦ để đối chiếu FIPS 203.
#
# Cần pcap_full_X25519.pcapng và pcap_full_X25519MLKEM768.pcapng (sinh bằng
# docker-lab/run_ch_budget.sh). Vì sao cần riêng: capture của ma trận dùng -s 160 nên chỉ
# đủ để đọc tcp.len, không đủ để đọc nội dung extension.
import subprocess, struct, os, json

def _payload(pcap, filt):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", filt, "-T", "fields", "-e", "tcp.payload"],
                         capture_output=True, text=True).stdout.strip().split("\n")
    for line in out:
        if line.strip():
            return bytes.fromhex(line.replace(":", ""))
    return b""

def _exts(body, p):
    tot = int.from_bytes(body[p:p+2], "big"); p += 2
    exts, end = {}, p+tot
    while p < end:
        et = int.from_bytes(body[p:p+2], "big"); el = int.from_bytes(body[p+2:p+4], "big")
        exts[et] = body[p+4:p+4+el]; p += 4+el
    return exts

def _parse_ch(b):
    hs = b[5:5+struct.unpack(">H", b[3:5])[0]]
    body = hs[4:4+int.from_bytes(hs[1:4], "big")]
    p = 2+32; sl = body[p]; p += 1+sl
    cl = int.from_bytes(body[p:p+2], "big"); p += 2+cl
    p += 1+body[p]
    e = _exts(body, p)
    ks = e.get(51, b""); n = int.from_bytes(ks[0:2], "big")
    out = []
    j = 2
    while j < 2+n:
        g = int.from_bytes(ks[j:j+2], "big"); kl = int.from_bytes(ks[j+2:j+4], "big")
        out.append((g, kl)); j += 4+kl
    return dict(hs_len=int.from_bytes(hs[1:4], "big"), key_share=out,
                ext_lens={hex(k): len(v) for k, v in e.items()})

def _parse_sh(b):
    hs = b[5:5+struct.unpack(">H", b[3:5])[0]]
    body = hs[4:4+int.from_bytes(hs[1:4], "big")]
    p = 2+32; sl = body[p]; p += 1+sl
    p += 2; p += 1+body[p]
    e = _exts(body, p)
    ks = e.get(51, b"")
    g = int.from_bytes(ks[0:2], "big"); kl = int.from_bytes(ks[2:4], "big")
    return dict(hs_len=int.from_bytes(hs[1:4], "big"), group=g, key_len=kl,
                ext_lens={hex(k): len(v) for k, v in e.items()})

def measure(lab_dir):
    """Trả về độ dài key_share của cả hai nhóm ở cả hai chiều (byte)."""
    res = {}
    for tag in ("X25519", "X25519MLKEM768"):
        pcap = os.path.join(lab_dir, f"pcap_full_{tag}.pcapng")
        if not os.path.exists(pcap):
            raise FileNotFoundError(pcap)
        ch = _parse_ch(_payload(pcap, "tls.handshake.type==1 && ip.src==172.30.10.3"))
        sh = _parse_sh(_payload(pcap, "tls.handshake.type==2 && ip.src==172.30.20.2"))
        res[tag] = dict(ch=ch, sh=sh)
    return dict(
        ch_x25519_key_len=res["X25519"]["ch"]["key_share"][0][1],
        ch_pqc_key_len=res["X25519MLKEM768"]["ch"]["key_share"][0][1],
        sh_x25519_key_len=res["X25519"]["sh"]["key_len"],
        sh_pqc_key_len=res["X25519MLKEM768"]["sh"]["key_len"],
        ch_hs_len={"X25519": res["X25519"]["ch"]["hs_len"], "X25519MLKEM768": res["X25519MLKEM768"]["ch"]["hs_len"]},
        sh_hs_len={"X25519": res["X25519"]["sh"]["hs_len"], "X25519MLKEM768": res["X25519MLKEM768"]["sh"]["hs_len"]},
        ch_ext_lens={"X25519": res["X25519"]["ch"]["ext_lens"], "X25519MLKEM768": res["X25519MLKEM768"]["ch"]["ext_lens"]},
        sh_ext_lens={"X25519": res["X25519"]["sh"]["ext_lens"], "X25519MLKEM768": res["X25519MLKEM768"]["sh"]["ext_lens"]},
    )

if __name__ == "__main__":
    lab = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docker-lab", "results"))
    print(json.dumps(measure(lab), indent=2))
