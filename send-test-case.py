#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import socket
import struct
import time
from pathlib import Path

TCP_FLAG = 0x01
MULTIPACKET_FLAG = 0x02
WAIT_FOR_RESPONSE_FLAG = 0x04
RAW_TCP_FLAG = 0x08
TSIG_FLAG = 0x10
MAX_PACKET_COUNT = 64
MAX_UDP_PACKET_SIZE = 65507
MAX_PACKET_SIZE = 65535
MAX_INPUT_SIZE = 131072
MULTIPACKET_TIMEOUT_SECONDS = 3.0
TSIG_KEY_NAME = "fuzz-key."
TSIG_ALGORITHM = "hmac-sha256."
TSIG_SECRET = b"0123456789abcdef0123456789abcdef"
TSIG_FUDGE = 300


def dns_name(name):
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    return b"".join(
        bytes([len(label)]) + label.encode() for label in labels
    ) + b"\x00"


def sign_tsig(packet, maximum_size):
    if len(packet) < 12:
        return packet
    additional = struct.unpack_from(">H", packet, 10)[0]
    if additional == 0xffff:
        return packet

    key_wire = dns_name(TSIG_KEY_NAME)
    algorithm_wire = dns_name(TSIG_ALGORITHM)
    time_wire = int(time.time()).to_bytes(6, "big")
    variables = key_wire + struct.pack(">HI", 255, 0)
    variables += algorithm_wire + time_wire
    variables += struct.pack(">HHH", TSIG_FUDGE, 0, 0)
    mac = hmac.new(TSIG_SECRET, packet + variables, hashlib.sha256).digest()
    original_id = struct.unpack_from(">H", packet)[0]
    rdata = algorithm_wire + time_wire
    rdata += struct.pack(">HH", TSIG_FUDGE, len(mac)) + mac
    rdata += struct.pack(">HHH", original_id, 0, 0)
    record = key_wire + struct.pack(">HHIH", 250, 255, 0, len(rdata)) + rdata
    if len(packet) + len(record) > maximum_size:
        return packet
    return (packet[:10] + struct.pack(">H", additional + 1) + packet[12:] +
            record)


def split_packets(data):
    packets = []
    offset = 0
    while offset < len(data) and len(packets) < MAX_PACKET_COUNT:
        if len(data) - offset < 2:
            break
        size = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        if size > len(data) - offset:
            break
        packets.append(data[offset : offset + size])
        offset += size
    return packets


def send_packet(sock, packet, use_tcp, raw_tcp):
    if raw_tcp:
        sock.sendall(packet)
        return len(packet)
    elif use_tcp:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        return len(packet)
    else:
        return sock.send(packet[:MAX_UDP_PACKET_SIZE])


def receive_exact(sock, size):
    data = b""
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            break
        data += block
    return data


def receive(sock, use_tcp):
    if not use_tcp:
        return sock.recv(65535)
    length = receive_exact(sock, 2)
    if len(length) != 2:
        return length
    return receive_exact(sock, struct.unpack(">H", length)[0])


def main():
    parser = argparse.ArgumentParser(description="Replay an NSD fuzzer testcase")
    parser.add_argument("testcase")
    parser.add_argument("--port", type=int, default=5301)
    parser.add_argument("--packet", type=int, help="send one 1-based packet from a multipacket input")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--ipv6", action="store_true", help="send to loopback ::1")
    args = parser.parse_args()

    data = Path(args.testcase).read_bytes()[:MAX_INPUT_SIZE]
    if len(data) < 2:
        raise SystemExit("testcase is too short")

    flags = data[0]
    use_tcp = bool(flags & TCP_FLAG)
    raw_tcp = use_tcp and bool(flags & RAW_TCP_FLAG)
    payload = data[1:]
    if flags & MULTIPACKET_FLAG:
        packets = split_packets(payload)
        if not packets:
            packets = [payload if raw_tcp else payload[:MAX_PACKET_SIZE]]
    else:
        packets = [payload[:MAX_PACKET_SIZE]]

    if args.packet is not None:
        if args.packet < 1 or args.packet > len(packets):
            raise SystemExit(f"packet must be between 1 and {len(packets)}")
        packets = [packets[args.packet - 1]]

    socket_type = socket.SOCK_STREAM if use_tcp else socket.SOCK_DGRAM
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    address = "::1" if args.ipv6 else "127.0.0.1"
    with socket.socket(family, socket_type) as sock:
        sock.settimeout(args.timeout)
        sock.connect((address, args.port))
        response_count = 0
        started = time.monotonic()
        for index, packet in enumerate(packets, 1):
            if (flags & MULTIPACKET_FLAG and not raw_tcp and
                    time.monotonic() - started >= MULTIPACKET_TIMEOUT_SECONDS):
                print("multipacket work limit reached")
                break
            if flags & TSIG_FLAG and not raw_tcp:
                maximum_size = MAX_PACKET_SIZE if use_tcp else MAX_UDP_PACKET_SIZE
                packet = sign_tsig(packet, maximum_size)
            sent_size = send_packet(sock, packet, use_tcp, raw_tcp)
            print(f"sent packet {index}: {sent_size} bytes")
            last_packet = index == len(packets)
            if raw_tcp and flags & MULTIPACKET_FLAG and not last_packet:
                time.sleep(0.001)
                continue
            if use_tcp and last_packet:
                continue
            if not last_packet and not flags & WAIT_FOR_RESPONSE_FLAG:
                continue
            try:
                response = receive(sock, use_tcp)
                response_count += 1
                print(f"response {response_count}: {response.hex()}")
            except socket.timeout:
                print(f"response {response_count + 1}: timeout")

        if use_tcp:
            sock.shutdown(socket.SHUT_WR)
            while True:
                try:
                    response = receive(sock, True)
                    if not response:
                        break
                    response_count += 1
                    print(f"response {response_count}: {response.hex()}")
                except socket.timeout:
                    print(f"response {response_count + 1}: timeout")
                    break


if __name__ == "__main__":
    main()
