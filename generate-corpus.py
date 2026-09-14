#!/usr/bin/env python3

import argparse
import fcntl
import hashlib
import hmac
import os
import socket
import struct
import time
from pathlib import Path

TCP_FLAG = 0x01
MULTIPACKET_FLAG = 0x02
WAIT_FOR_RESPONSE_FLAG = 0x04
RAW_TCP_FLAG = 0x08
TSIG_FLAG = 0x10
COOKIE_SECRET = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
TSIG_KEY_NAME = "fuzz-key."
TSIG_ALGORITHM = "hmac-sha256."
TSIG_SECRET = b"0123456789abcdef0123456789abcdef"
# Keep valid seeds usable throughout the initial large-corpus replay.
TSIG_FUDGE = 65535


def rotate_left(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & 0xffffffffffffffff


def siphash_round(state):
    v0, v1, v2, v3 = state
    v0 = (v0 + v1) & 0xffffffffffffffff
    v1 = rotate_left(v1, 13) ^ v0
    v0 = rotate_left(v0, 32)
    v2 = (v2 + v3) & 0xffffffffffffffff
    v3 = rotate_left(v3, 16) ^ v2
    v0 = (v0 + v3) & 0xffffffffffffffff
    v3 = rotate_left(v3, 21) ^ v0
    v2 = (v2 + v1) & 0xffffffffffffffff
    v1 = rotate_left(v1, 17) ^ v2
    v2 = rotate_left(v2, 32)
    return v0, v1, v2, v3


def siphash24(data, key):
    k0, k1 = struct.unpack("<QQ", key)
    state = (0x736f6d6570736575 ^ k0, 0x646f72616e646f6d ^ k1,
             0x6c7967656e657261 ^ k0, 0x7465646279746573 ^ k1)
    offset = 0
    while offset + 8 <= len(data):
        message = struct.unpack_from("<Q", data, offset)[0]
        state = state[0], state[1], state[2], state[3] ^ message
        state = siphash_round(siphash_round(state))
        state = state[0] ^ message, state[1], state[2], state[3]
        offset += 8

    tail = int.from_bytes(data[offset:], "little") | (len(data) << 56)
    state = state[0], state[1], state[2], state[3] ^ tail
    state = siphash_round(siphash_round(state))
    state = state[0] ^ tail, state[1], state[2] ^ 0xff, state[3]
    for _ in range(4):
        state = siphash_round(state)
    return struct.pack("<Q", state[0] ^ state[1] ^ state[2] ^ state[3])


def dns_name(name):
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"


def edns_option(code, data=b""):
    return struct.pack(">HH", code, len(data)) + data


def edns_record(options=b"", udp_size=1232, version=0, do=True):
    ttl = (version << 16) | (0x8000 if do else 0)
    return b"\x00" + struct.pack(">HHIH", 41, udp_size, ttl, len(options)) + options


def with_additional(packet, *records):
    return packet[:10] + struct.pack(">H", len(records)) + packet[12:] + b"".join(records)


def soa_record(name, serial):
    rdata = dns_name("dns1.example.com")
    rdata += dns_name("hostmaster.example.com")
    rdata += struct.pack(">IIIII", serial, 21600, 3600, 604800, 86400)
    return dns_name(name) + struct.pack(">HHIH", 6, 1, 0, len(rdata)) + rdata


def query(name, qtype, message_id, flags=0x0100, qclass=1, edns=False,
          options=b"", edns_version=0, edns_do=True, udp_size=1232,
          answer=b"", authority=b""):
    additional = 1 if edns else 0
    answers = 1 if answer else 0
    nameservers = 1 if authority else 0
    packet = struct.pack(">HHHHHH", message_id, flags, 1, answers, nameservers, additional)
    packet += dns_name(name) + struct.pack(">HH", qtype, qclass)
    packet += answer
    packet += authority
    if edns:
        packet += edns_record(options, udp_size, edns_version, edns_do)
    return packet


def tsig_query(packet, key_name=TSIG_KEY_NAME, signed_time=None,
               corrupt_mac=False, fudge=TSIG_FUDGE):
    if len(packet) < 12:
        raise ValueError("TSIG requires a complete DNS header")
    if signed_time is None:
        signed_time = int(time.time())

    key_wire = dns_name(key_name)
    algorithm_wire = dns_name(TSIG_ALGORITHM)
    time_wire = signed_time.to_bytes(6, "big")
    variables = key_wire + struct.pack(">HI", 255, 0)
    variables += algorithm_wire + time_wire
    variables += struct.pack(">HHH", fudge, 0, 0)
    mac = hmac.new(TSIG_SECRET, packet + variables, hashlib.sha256).digest()
    if corrupt_mac:
        mac = bytes([mac[0] ^ 0xff]) + mac[1:]

    original_id = struct.unpack_from(">H", packet)[0]
    rdata = algorithm_wire + time_wire + struct.pack(">HH", fudge, len(mac))
    rdata += mac + struct.pack(">HHH", original_id, 0, 0)
    record = key_wire + struct.pack(">HHIH", 250, 255, 0, len(rdata)) + rdata

    additional = struct.unpack_from(">H", packet, 10)[0]
    if additional == 0xffff:
        raise ValueError("DNS additional-record count is full")
    return packet[:10] + struct.pack(">H", additional + 1) + packet[12:] + record


def empty_question_edns(message_id):
    packet = struct.pack(">HHHHHH", message_id, 0x0100, 0, 0, 0, 1)
    return packet + edns_record(do=False)


def multipacket(*packets):
    return b"".join(struct.pack(">H", len(packet)) + packet for packet in packets)


def tcp_frame(packet):
    return struct.pack(">H", len(packet)) + packet


def main():
    parser = argparse.ArgumentParser(description="Generate the initial NSD fuzzing corpus")
    parser.add_argument("directory", nargs="?", default="corpus")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    lock_files = []
    if os.environ.get("NSD_FUZZ_CORPUS_LOCKED") != "1":
        lock_dir = Path(__file__).resolve().parent / "run" / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        if args.clean:
            campaign_lock = (lock_dir / "campaign.lock").open("w")
            fcntl.flock(campaign_lock, fcntl.LOCK_EX)
            lock_files.append(campaign_lock)
        corpus_lock = (lock_dir / "corpus.lock").open("w")
        fcntl.flock(corpus_lock, fcntl.LOCK_EX)
        lock_files.append(corpus_lock)
        if args.clean:
            for owner_file in lock_dir.parent.glob("run_*/run/fuzzer.owner"):
                if owner_file.is_file() and owner_file.stat().st_size:
                    owner = owner_file.read_text().strip()
                    raise SystemExit(
                        f"A fuzzing campaign owns a configuration under "
                        f"run.sh PID {owner}. Stop it before resetting the corpus."
                    )

    output = Path(args.directory)
    output.mkdir(parents=True, exist_ok=True)
    if args.clean:
        for old_file in output.iterdir():
            if old_file.is_file() or old_file.is_symlink():
                old_file.unlink()

    a = query("example.com", 1, 0x1001)
    aaaa = query("example.com", 28, 0x1002)
    mx = query("example.com", 15, 0x1003)
    ns = query("example.com", 2, 0x1004)
    soa = query("example.com", 6, 0x1005)
    txt = query("example.com", 16, 0x1006)
    nxdomain = query("does-not-exist.example.com", 1, 0x1007)
    root_dnskey = query(".", 48, 0x1008, edns=True)
    edns_any = query("example.org", 255, 0x1009, edns=True)
    notify = query("example.org", 6, 0x1010, flags=0x2400)
    update = query("example.org", 6, 0x1011, flags=0x2800)
    axfr = query("example.com", 252, 0x1012)
    ixfr_current = query("example.com", 251, 0x1013,
                         authority=soa_record("example.com", 2))
    ixfr_old = query("example.com", 251, 0x1014,
                     authority=soa_record("example.com", 1))

    nsid = edns_option(3)
    client_cookie = b"NSDFUZZ!"
    cookie = edns_option(10, client_cookie)
    cookie_prefix = client_cookie + b"\x01\x00\x00\x00"
    cookie_prefix += struct.pack(">I", int(time.time()))
    cookie_hash_input = cookie_prefix + socket.inet_aton("127.0.0.1")
    cookie_to_verify = cookie_prefix + siphash24(cookie_hash_input, COOKIE_SECRET)
    cookie_hash_input_ip6 = cookie_prefix + socket.inet_pton(
        socket.AF_INET6, "::1")
    cookie_to_verify_ip6 = cookie_prefix + siphash24(
        cookie_hash_input_ip6, COOKIE_SECRET)
    padding = edns_option(12, b"\x00" * 16)
    zoneversion = edns_option(19)
    combined_options = nsid + cookie + padding + zoneversion
    combined_options += edns_option(65001, b"fuzz")

    duplicate_opt = with_additional(
        query("example.com", 1, 0x1510), edns_record(), edns_record())
    unexpected_additional = dns_name("extra.example.com")
    unexpected_additional += struct.pack(">HHIH", 1, 1, 0, 4)
    unexpected_additional += socket.inet_aton("192.0.2.99")
    opt_then_address = with_additional(
        query("example.com", 1, 0x1511), edns_record(), unexpected_additional)
    bad_edns_owner = dns_name("bad") + edns_record()[1:]
    option_overrun = struct.pack(">HH", 65002, 8) + b"x"
    framed_a = tcp_frame(a)
    tsig_a = tsig_query(a)
    tsig_bad_signature = tsig_query(a, corrupt_mac=True)
    tsig_bad_key = tsig_query(a, key_name="unknown-fuzz-key.")
    tsig_bad_time = tsig_query(
        a, signed_time=int(time.time()) - TSIG_FUDGE - 3600)
    tsig_edns = tsig_query(query(
        "example.com", 1, 0x1515, edns=True, options=nsid))
    tsig_axfr = tsig_query(axfr)

    seeds = {
        "udp-a-example": bytes([0]) + a,
        "udp-aaaa-example": bytes([0]) + aaaa,
        "udp-mx-example": bytes([0]) + mx,
        "udp-ns-example": bytes([0]) + ns,
        "udp-soa-example": bytes([0]) + soa,
        "udp-txt-example": bytes([0]) + txt,
        "udp-nxdomain": bytes([0]) + nxdomain,
        "udp-root-dnskey-edns": bytes([0]) + root_dnskey,
        "udp-root-dnskey-no-edns": bytes([0]) + query(".", 48, 0x1101),
        "udp-root-referral-do": bytes([0]) + query("com", 1, 0x1102, edns=True),
        "udp-any-edns": bytes([0]) + edns_any,
        "udp-notify": bytes([0]) + notify,
        "udp-notify-soa": bytes([0]) + query(
            "example.org", 6, 0x1103, flags=0x2400,
            answer=soa_record("example.org", 3)),
        "udp-update": bytes([0]) + update,
        "udp-axfr-example": bytes([0]) + axfr,
        "tcp-a-example": bytes([TCP_FLAG]) + a,
        "tcp-axfr-example": bytes([TCP_FLAG]) + axfr,
        "tcp-axfr-unknown": bytes([TCP_FLAG]) + query("unknown.invalid", 252, 0x1104),
        "tcp-ixfr-current": bytes([TCP_FLAG]) + ixfr_current,
        "tcp-ixfr-old": bytes([TCP_FLAG]) + ixfr_old,

        "udp-cname-example": bytes([0]) + query("dc1.example.com", 1, 0x1201),
        "udp-cname-chain": bytes([0]) + query("chain1.example.com", 1, 0x1202),
        "tcp-cname-long-chain": bytes([TCP_FLAG]) + query(
            "longchain01.example.com", 1, 0x120B),
        "udp-cname-loop": bytes([0]) + query("loop1.example.com", 1, 0x1203),
        "udp-wildcard-example": bytes([0]) + query("host.wild.example.com", 1, 0x1204),
        "udp-dname-example": bytes([0]) + query("host.rewrite.example.org", 1, 0x1205),
        "udp-srv-example": bytes([0]) + query("srv.example.com", 33, 0x1206),
        "udp-kx-example": bytes([0]) + query("kx.example.com", 36, 0x1207),
        "udp-rt-example": bytes([0]) + query("rt.example.com", 21, 0x1208),
        "udp-mb-example": bytes([0]) + query("mb.example.com", 7, 0x1209),
        "udp-delegation-example": bytes([0]) + query("www.child.example.com", 1, 0x120A),

        "udp-nsec3-nxdomain": bytes([0]) + query("nope.example", 1, 0x1301, edns=True),
        "udp-nsec3-nodata": bytes([0]) + query("ai.example", 16, 0x1302, edns=True),
        "udp-nsec3-wildcard": bytes([0]) + query("z.w.example", 15, 0x1303, edns=True),
        "udp-nsec3-delegation": bytes([0]) + query("www.a.example", 1, 0x1304, edns=True),
        "udp-nsec3-insecure-delegation": bytes([0]) + query("www.c.example", 1, 0x1308, edns=True),
        "udp-nsec3-ds": bytes([0]) + query("a.example", 43, 0x1305, edns=True),
        "udp-nsec3-dnskey": bytes([0]) + query("example", 48, 0x1306, edns=True),
        "udp-nsec3-param": bytes([0]) + query("example", 51, 0x1307, edns=True),

        "udp-chaos-id-server": bytes([0]) + query("id.server", 16, 0x1401, qclass=3),
        "udp-chaos-hostname-bind": bytes([0]) + query("hostname.bind", 16, 0x1402, qclass=3),
        "udp-chaos-version-bind": bytes([0]) + query("version.bind", 16, 0x1403, qclass=3),
        "udp-chaos-version-server": bytes([0]) + query("version.server", 16, 0x1404, qclass=3),
        "udp-chaos-unknown": bytes([0]) + query("unknown.bind", 16, 0x1405, qclass=3),
        "udp-class-any": bytes([0]) + query("example.com", 1, 0x1406, qclass=255),
        "udp-class-unknown": bytes([0]) + query("example.com", 1, 0x1407, qclass=65280, edns=True),

        "udp-edns-empty": bytes([0]) + query("example.com", 1, 0x1501, edns=True, edns_do=False),
        "udp-edns-badvers": bytes([0]) + query("example.com", 1, 0x1502, edns=True, edns_version=1),
        "udp-edns-nsid": bytes([0]) + query("example.com", 1, 0x1503, edns=True, options=nsid),
        "udp-edns-cookie": bytes([0]) + query("example.com", 1, 0x1504, edns=True, options=cookie),
        "udp-edns-cookie-verify": bytes([0]) + query(
            "example.com", 1, 0x1505, edns=True,
            options=edns_option(10, cookie_to_verify)),
        "udp-edns-cookie-verify-ipv6": bytes([0]) + query(
            "example.com", 1, 0x1517, edns=True,
            options=edns_option(10, cookie_to_verify_ip6)),
        "udp-edns-cookie-length-16": bytes([0]) + query(
            "example.com", 1, 0x150D, edns=True,
            options=edns_option(10, client_cookie + b"\x00" * 8)),
        "udp-edns-cookie-length-40": bytes([0]) + query(
            "example.com", 1, 0x150E, edns=True,
            options=edns_option(10, client_cookie + b"\x00" * 32)),
        "udp-edns-cookie-length-41": bytes([0]) + query(
            "example.com", 1, 0x150F, edns=True,
            options=edns_option(10, client_cookie + b"\x00" * 33)),
        "udp-edns-cookie-short": bytes([0]) + query(
            "example.com", 1, 0x1506, edns=True,
            options=edns_option(10, b"short")),
        "udp-edns-padding": bytes([0]) + query("example.com", 1, 0x1507, edns=True, options=padding),
        "tcp-edns-padding": bytes([TCP_FLAG]) + query("example.com", 1, 0x1508, edns=True, options=padding),
        "udp-edns-zoneversion": bytes([0]) + query("example.com", 6, 0x1509, edns=True, options=zoneversion),
        "udp-edns-small-buffer": bytes([0]) + query(".", 48, 0x150A, edns=True, udp_size=64),
        "udp-edns-unknown-option": bytes([0]) + query(
            "example.com", 1, 0x150B, edns=True,
            options=edns_option(65001, b"fuzz")),
        "udp-edns-no-question": bytes([0]) + empty_question_edns(0x150C),
        "udp-edns-combined-options": bytes([0]) + query(
            "example.com", 1, 0x1512, edns=True, options=combined_options),
        "udp-edns-option-overrun": bytes([0]) + query(
            "example.com", 1, 0x1513, edns=True, options=option_overrun),
        "udp-edns-duplicate-opt": bytes([0]) + duplicate_opt,
        "udp-edns-opt-then-address": bytes([0]) + opt_then_address,
        "udp-edns-bad-owner": bytes([0]) + with_additional(
            query("example.com", 1, 0x1514), bad_edns_owner),

        "udp-tsig-valid": bytes([0]) + tsig_a,
        "udp-tsig-bad-signature": bytes([0]) + tsig_bad_signature,
        "udp-tsig-bad-key": bytes([0]) + tsig_bad_key,
        "udp-tsig-bad-time": bytes([0]) + tsig_bad_time,
        "udp-edns-tsig-valid": bytes([0]) + tsig_edns,
        "tcp-tsig-axfr": bytes([TCP_FLAG]) + tsig_axfr,
        "udp-harness-tsig-a": bytes([TSIG_FLAG]) + a,
        "udp-harness-tsig-edns": bytes([TSIG_FLAG]) + query(
            "example.com", 1, 0x1516, edns=True, options=nsid),
        "tcp-harness-tsig-axfr": bytes([TCP_FLAG | TSIG_FLAG]) + axfr,
        "udp-multi-harness-tsig": bytes([
            MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG | TSIG_FLAG
        ]) + multipacket(a, nxdomain),

        "udp-qr-set": bytes([0]) + query("example.com", 1, 0x1701, flags=0x8100),
        "udp-nonzero-rcode": bytes([0]) + query("example.com", 1, 0x1702, flags=0x0103),
        "udp-iquery-opcode": bytes([0]) + query("example.com", 1, 0x1703, flags=0x0900),
        "udp-status-opcode": bytes([0]) + query("example.com", 1, 0x1704, flags=0x1100),
        "udp-two-questions": bytes([0]) + struct.pack(
            ">HHHHHH", 0x1705, 0x0100, 2, 0, 0, 0) +
            dns_name("example.com") + struct.pack(">HH", 1, 1) +
            dns_name("example.org") + struct.pack(">HH", 28, 1),

        "udp-dname-cname-query": bytes([0]) + query(
            "host.rewrite.example.org", 5, 0x1801),
        "udp-dname-owner-query": bytes([0]) + query(
            "rewrite.example.org", 39, 0x1802),
        "udp-root-soa-do": bytes([0]) + query(".", 6, 0x1803, edns=True),
        "udp-root-nsec-do": bytes([0]) + query(".", 47, 0x1804, edns=True),
        "udp-root-any-do": bytes([0]) + query(".", 255, 0x1805, edns=True),
        "udp-root-missing-ds-do": bytes([0]) + query(
            "missing", 43, 0x1806, edns=True),

        "udp-minfo-example": bytes([0]) + query("minfo.example.com", 14, 0x1901),
        "udp-rp-example": bytes([0]) + query("rp.example.com", 17, 0x1902),
        "udp-afsdb-example": bytes([0]) + query("afsdb.example.com", 18, 0x1903),
        "udp-px-example": bytes([0]) + query("px.example.com", 26, 0x1904),
        "udp-naptr-example": bytes([0]) + query("naptr.example.com", 35, 0x1905),
        "udp-svcb-example": bytes([0]) + query("svcb.example.com", 64, 0x1906),
        "udp-https-example": bytes([0]) + query("https.example.com", 65, 0x1907),
        "udp-lp-example": bytes([0]) + query("lp.example.com", 107, 0x1908),

        "udp-multi-delay": bytes([MULTIPACKET_FLAG]) + multipacket(a, aaaa, mx),
        "udp-multi-response": bytes([MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(ns, soa, txt),
        "udp-multi-edns": bytes([MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(
            query("example.com", 1, 0x1601, edns=True, options=nsid),
            query("example.com", 1, 0x1602, edns=True, options=cookie),
            query("example.com", 1, 0x1603, edns=True, options=zoneversion)),
        "udp-multi-rrl-positive": bytes([MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(*([a] * 8)),
        "udp-multi-rrl-nxdomain": bytes([MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(*([nxdomain] * 8)),
        "udp-multi-rrl-wildcard": bytes([MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(*([
            query("host.wild.example.com", 1, 0x1604)] * 8)),
        "tcp-multi-delay": bytes([TCP_FLAG | MULTIPACKET_FLAG]) + multipacket(a, nxdomain),
        "tcp-multi-response": bytes([TCP_FLAG | MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(soa, axfr),
        "tcp-multi-edns-state": bytes([TCP_FLAG | MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(
            query("example.com", 1, 0x1A01, edns=True, edns_version=1),
            query("example.com", 1, 0x1A02, edns=True, options=combined_options),
            query("example.com", 1, 0x1A03, edns=True,
                  options=edns_option(10, cookie_to_verify))),
        "tcp-multi-cookie-reuse": bytes([TCP_FLAG | MULTIPACKET_FLAG | WAIT_FOR_RESPONSE_FLAG]) + multipacket(
            query("example.com", 1, 0x1A04, edns=True,
                  options=edns_option(10, cookie_to_verify)),
            query("example.com", 28, 0x1A05, edns=True,
                  options=edns_option(10, cookie_to_verify))),
        "tcp-raw-valid-frame": bytes([TCP_FLAG | RAW_TCP_FLAG]) + framed_a,
        "tcp-raw-two-frames": bytes([TCP_FLAG | RAW_TCP_FLAG]) + framed_a + tcp_frame(aaaa),
        "tcp-raw-length-too-long": bytes([TCP_FLAG | RAW_TCP_FLAG]) + struct.pack(">H", len(a) + 8) + a,
        "tcp-raw-zero-length": bytes([TCP_FLAG | RAW_TCP_FLAG]) + b"\x00\x00",
        "tcp-raw-chunked-prefix": bytes([TCP_FLAG | MULTIPACKET_FLAG | RAW_TCP_FLAG]) + multipacket(
            framed_a[:1], framed_a[1:8], framed_a[8:]),
        "tcp-raw-chunked-body": bytes([TCP_FLAG | MULTIPACKET_FLAG | RAW_TCP_FLAG]) + multipacket(
            framed_a[:10], framed_a[10:20], framed_a[20:]),
        "malformed-short-header": b"\x00\x12\x34\x01",
        "malformed-compression-loop": b"\x00\x22\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
        "malformed-large-counts": b"\x00\x33\x33\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00",
    }

    for name, data in seeds.items():
        temporary = output / f".{name}.tmp-{os.getpid()}"
        temporary.write_bytes(data)
        os.replace(temporary, output / name)
    print(f"Wrote {len(seeds)} seeds to {output}")


if __name__ == "__main__":
    main()
