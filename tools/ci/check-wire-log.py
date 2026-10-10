#!/usr/bin/env python3
"""Judges what `wire-relay.py` saw: is everything that left this PC encrypted?

    check-wire-log.py relay.jsonl --marker DETERIUM-PROBE-1234 [--marker ...]
    check-wire-log.py --selftest

The log holds the exact datagrams Deterium sent to (and got from) its server
while the test pushed a recognisable plaintext (the marker, repeated) through
the tunnel. The checks, all of which must pass:

  1. Framing. Every datagram is a WireGuard message: type 1, 2, 3 or 4, three
     zero bytes after it, and the fixed size of its type (148 / 92 / 64) or, for
     transport data (type 4), at least 32 bytes (16-byte header + 16-byte tag;
     a bare keepalive is exactly that). Anything else
     leaving the PC would be a leak or a bug.
  2. No plaintext. Neither the marker nor common plaintext protocol tokens
     (HTTP request lines, Host headers) appear anywhere in any datagram, in
     either direction.
  3. Looks like ciphertext. The transport payloads together have a byte entropy
     of at least 7.9 bits per byte. The test sends a highly repetitive body, so
     unencrypted or weakly encrypted data would score far lower.
  4. Enough was observed. A handshake and enough transport data went out that
     the judgement means something.

`--selftest` proves the checks themselves work: good traffic passes, and
plaintext, a marker, a wrong frame and low-entropy "ciphertext" are caught.
"""

import argparse
import base64
import json
import math
import os
import sys
from collections import Counter

SIZES = {1: 148, 2: 92, 3: 64}
PLAINTEXT_TOKENS = [b"HTTP/1.", b"GET /", b"POST /", b"Host:", b"User-Agent:", b"Content-Length:"]
MIN_ENTROPY = 7.9


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def load(path):
    out, inbound = [], []
    with open(path, encoding="ascii") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            data = base64.b64decode(item["data"])
            (out if item["dir"] == "out" else inbound).append(data)
    return out, inbound


def frame_problem(data):
    if len(data) < 4:
        return f"{len(data)} bytes is too short for a WireGuard message"
    kind = data[0]
    if kind not in (1, 2, 3, 4):
        return f"message type {kind} is not a WireGuard message"
    if data[1:4] != b"\x00\x00\x00":
        return "the reserved bytes are not zero"
    if kind in SIZES and len(data) != SIZES[kind]:
        return f"type {kind} must be {SIZES[kind]} bytes, got {len(data)}"
    # The WireGuard paper asks for padding to a multiple of 16 bytes, but boringtun
    # (which Deterium uses) leaves it out on purpose ("works fine without it"), so
    # only the minimum size is enforced. Padding hides packet sizes slightly; it is
    # not what makes the contents unreadable.
    if kind == 4 and len(data) < 32:
        return f"transport data must be at least 32 bytes, got {len(data)}"
    return None


def judge(out, inbound, markers, min_transport=20, min_bytes=16384):
    """Returns (problems, summary)."""
    problems = []
    transport = b""
    transport_out = 0
    handshakes = 0

    for direction, datagrams in (("out", out), ("in", inbound)):
        for index, data in enumerate(datagrams):
            where = f"{direction} datagram #{index} ({len(data)} bytes)"
            problem = frame_problem(data)
            if problem:
                problems.append(f"{where}: {problem}")
            for marker in markers:
                if marker in data:
                    problems.append(f"{where}: contains the plaintext marker")
            for token in PLAINTEXT_TOKENS:
                if token in data:
                    problems.append(f"{where}: contains plaintext {token!r}")
            if data[:1] == b"\x04":
                transport += data[16:]
                if direction == "out":
                    transport_out += 1
            elif data[:1] == b"\x01" and direction == "out":
                handshakes += 1

    if handshakes == 0:
        problems.append("no handshake went out, so nothing meaningful was observed")
    if transport_out < min_transport:
        problems.append(f"only {transport_out} transport packets went out (need {min_transport})")
    bits = entropy(transport)
    if len(transport) < min_bytes:
        problems.append(f"only {len(transport)} transport bytes seen (need {min_bytes}) to judge entropy")
    elif bits < MIN_ENTROPY:
        problems.append(f"transport payload entropy is {bits:.3f} bits/byte (need >= {MIN_ENTROPY})")

    summary = {
        "datagrams_out": len(out),
        "datagrams_in": len(inbound),
        "handshake_initiations": handshakes,
        "transport_packets_out": transport_out,
        "transport_bytes": len(transport),
        "transport_entropy_bits_per_byte": round(bits, 4),
    }
    return problems, summary


def selftest():
    marker = b"DETERIUM-PROBE-SELFTEST"
    rng = os.urandom

    def handshake():
        return b"\x01\x00\x00\x00" + rng(144)

    def transport(n=1392):
        return b"\x04\x00\x00\x00" + rng(n - 4)

    good_out = [handshake()] + [transport() for _ in range(40)]
    good_in = [b"\x02\x00\x00\x00" + rng(88)] + [transport() for _ in range(40)]
    cases = []

    problems, _ = judge(good_out, good_in, [marker])
    cases.append(("genuine-looking WireGuard traffic passes", not problems, problems))

    leaked = good_out[:-1] + [b"\x04\x00\x00\x00" + rng(100) + marker + rng(1272)]
    problems, _ = judge(leaked, good_in, [marker])
    cases.append(("a datagram carrying the marker is caught", any("marker" in p for p in problems), problems))

    http = good_out + [b"POST / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n" + marker]
    problems, _ = judge(http, good_in, [marker])
    cases.append(("a plaintext HTTP request is caught", any("plaintext" in p or "type" in p for p in problems), problems))

    bad_frame = good_out + [b"\x07\x00\x00\x00" + rng(60)]
    problems, _ = judge(bad_frame, good_in, [marker])
    cases.append(("a non-WireGuard datagram is caught", any("not a WireGuard" in p for p in problems), problems))

    weak = [handshake()] + [b"\x04\x00\x00\x00" + (b"ABCDEFGH" * 175)[:1388] for _ in range(40)]
    problems, _ = judge(weak, good_in, [marker])
    cases.append(("repetitive, 'encrypted' data is caught by entropy", any("entropy" in p for p in problems), problems))

    unpadded = good_out[:-3] + [b"\x04\x00\x00\x00" + rng(n) for n in (75, 107, 144)]
    problems, _ = judge(unpadded, good_in, [marker])
    cases.append(("unpadded transport packets (boringtun) are fine", not problems, problems))

    runt = good_out + [b"\x04\x00\x00\x00" + rng(12)]
    problems, _ = judge(runt, good_in, [marker])
    cases.append(("a transport packet shorter than header+tag is caught", any("at least 32" in p for p in problems), problems))

    problems, _ = judge([], [], [marker])
    cases.append(("an empty capture is not a pass", bool(problems), problems))

    failed = 0
    for name, ok, problems in cases:
        print(("ok   " if ok else "FAIL ") + name)
        if not ok:
            failed += 1
            for p in problems[:3]:
                print("       " + p)
    print(f"{len(cases) - failed}/{len(cases)} self-tests passed")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("log", nargs="?")
    parser.add_argument("--marker", action="append", default=[])
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.log or not args.marker:
        parser.error("give the relay log and at least one --marker (or use --selftest)")

    out, inbound = load(args.log)
    problems, summary = judge(out, inbound, [m.encode() for m in args.marker])
    print(json.dumps(summary, indent=2))
    if problems:
        print("\nNOT everything that left this PC was encrypted:")
        for problem in problems[:20]:
            print("  - " + problem)
        if len(problems) > 20:
            print(f"  ... and {len(problems) - 20} more")
        return 1
    print("\nEverything that left this PC was WireGuard ciphertext.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
