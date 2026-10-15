#!/usr/bin/env python3
"""A UDP relay that writes down every datagram that passes through it.

The encryption test points Deterium's WireGuard endpoint at this relay instead
of the real server. The relay forwards everything to the real server and back,
so the tunnel works as usual, and logs the exact bytes Deterium sends out and
receives. `check-wire-log.py` then judges that log.

    wire-relay.py --listen 127.0.0.1:51888 --upstream host:2408 \
                  --log relay.jsonl --stop-file relay.stop

It runs until the stop file appears. One log line per datagram:
{"t": seconds, "dir": "out"|"in", "len": n, "data": "<base64>"}
"""

import argparse
import base64
import json
import os
import select
import socket
import sys
import time


def split_host_port(text):
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"expected host:port, got {text!r}")
    return host.strip("[]"), int(port)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--listen", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--stop-file", required=True)
    args = parser.parse_args()

    listen = split_host_port(args.listen)
    host, port = split_host_port(args.upstream)
    upstream = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]

    inside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inside.bind(listen)
    outside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    outside.bind(("0.0.0.0", 0))
    for sock in (inside, outside):
        try:  # Windows reports ICMP "port unreachable" as a read error; ignore it.
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (AttributeError, OSError, ValueError):
            pass

    started = time.monotonic()
    client = None
    # What went through, so a tunnel that never came up can be told apart:
    # nothing from the client (a problem on this PC), or nothing back from the
    # server (the server did not answer).
    counts = {"out": [0, 0], "in": [0, 0], "ignored": [0, 0]}
    with open(args.log, "w", encoding="ascii") as log:

        def record(direction, data):
            log.write(
                json.dumps(
                    {
                        "t": round(time.monotonic() - started, 3),
                        "dir": direction,
                        "len": len(data),
                        "data": base64.b64encode(data).decode("ascii"),
                    }
                )
                + "\n"
            )
            log.flush()

        print(f"relay: {args.listen} -> {upstream[0]}:{upstream[1]}", flush=True)
        while not os.path.exists(args.stop_file):
            ready, _, _ = select.select([inside, outside], [], [], 0.2)
            for sock in ready:
                try:
                    data, addr = sock.recvfrom(65535)
                except (ConnectionResetError, OSError):
                    continue
                if sock is inside:
                    client = addr
                    record("out", data)
                    outside.sendto(data, upstream)
                    counts["out"][0] += 1
                    counts["out"][1] += len(data)
                elif client is not None and addr[0] == upstream[0]:
                    record("in", data)
                    inside.sendto(data, client)
                    counts["in"][0] += 1
                    counts["in"][1] += len(data)
                else:
                    # An answer from an address other than the one we forward to.
                    counts["ignored"][0] += 1
                    counts["ignored"][1] += len(data)
                    if counts["ignored"][0] <= 3:
                        print(f"relay: ignored {len(data)} bytes from {addr[0]}:{addr[1]}", flush=True)
    print(
        "relay: stopped. "
        f"from Deterium to the server: {counts['out'][0]} datagrams ({counts['out'][1]} bytes); "
        f"from the server back: {counts['in'][0]} datagrams ({counts['in'][1]} bytes); "
        f"ignored from other addresses: {counts['ignored'][0]}",
        flush=True,
    )


if __name__ == "__main__":
    sys.exit(main())
