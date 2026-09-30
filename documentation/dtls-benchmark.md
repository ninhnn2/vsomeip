# DTLS vs plaintext UDP: latency, throughput and CPU

Measured results for the optional DTLS 1.2 PSK transport described in
[dtls.md](dtls.md), taken with the `dtls-bench-service` / `dtls-bench-client`
example pair.

## Setup

| | Client | Service |
|---|---|---|
| Machine | x86_64 Host | AArch64 target ECU (Cortex-A72) |
| Address | 192.0.2.111 | 192.0.2.225 |
| Compiler | GCC 12.3.0 | GCC 13.3.0 |
| OpenSSL | 3.0.2 | 3.2.4 |
| Link | 1 GbE, ICMP RTT 0.131 ms min/avg/max 0.112/0.131/0.146 ms | |

Both ends run the same vSomeIP build (3.7.6 plus this branch), so the only
difference between the two columns of every table is whether the `dtls` object is
enabled. Cipher: DTLS 1.2 with `PSK-AES128-GCM-SHA256`. One benchmark process pair
per payload size, so the CPU time reported belongs to that size alone.

Configuration that the measurement depends on, identical in both modes:

- `npdu-default-timings` all zero. vSomeIP otherwise applies 2 ms nPDU debounce plus
  5 ms retention per direction, which puts a ~10 ms floor under every request and
  response and hides the transport completely (measured: 10.9 ms round trip in both
  modes before this was disabled).
- `someip-tp` for methods `0x0421`/`0x0422` in both directions with
  `max-segment-length` 1392, `separation-time` 0 - required for any payload above
  1400 bytes.
- `max-payload-size-unreliable` and `max-payload-size-local` both 16 MiB. The local
  one matters: the application reaches its routing manager over a local endpoint
  first, and a 10 MiB request is dropped there (`le::send: ... message size
  (10485791) exceeded the limit`) before it ever reaches the wire.
- `udp-receive-buffer-size` 64 MiB plus `net.core.rmem_max` raised on the target.
  A 10 MiB message is 7532 TP segments; with the stock 208 KiB limit the receiver
  cannot drain the burst and SOME/IP-TP has no retransmission, so the message is
  lost.

## Test cases

| ID | Case | Payloads | Expectation | Result |
|---|---|---|---|---|
| TC-01 | PSK handshake per endpoint | - | one handshake per client process | pass, 1 per run over 28 runs |
| TC-02 | Single-datagram round trip | 64 B, 512 B, 1400 B | no segmentation, no loss | pass, 300/300 each |
| TC-03 | Maximum single-MTU payload | 1400 B | one Ethernet frame, no IP fragmentation | pass, see below |
| TC-04 | SOME/IP-TP round trip | 4 KiB .. 1 MiB | segmented and reassembled | pass, 10..200 iterations each |
| TC-05 | Upload throughput | 1400 B .. 10 MiB | no loss, stable rate | pass, 3..300 iterations each |
| TC-06 | 10 MiB single message | 10 MiB (7532 segments) | delivered intact | pass, 3/3 |
| TC-07 | Plaintext control | same matrix | same functional result | pass, all points |
| TC-08 | Client restart on a live service | - | new handshake replaces old session | pass after the fix below |

Every point in the matrix ran to completion with zero failed requests: 28 runs,
2440 requests per mode.

## TC-03: the 1 MTU case

vSomeIP caps a single unsegmented UDP SOME/IP message at
`VSOMEIP_MAX_UDP_MESSAGE_SIZE` (1416 bytes), so 1400 bytes of payload is the largest
that travels as one message - which is also the AUTOSAR maximum for UDP. On the wire:

| | plaintext | DTLS |
|---|---:|---:|
| SOME/IP message | 1416 B | 1416 B |
| DTLS record overhead | - | 37 B (13 header + 8 explicit nonce + 16 GCM tag) |
| UDP payload | 1416 B | 1453 B (measured) |
| IP total length | 1444 B | 1481 B |
| Fits 1500 B MTU | yes | yes |
| IP fragments observed | 0 | 0 |

So DTLS costs 37 bytes per datagram and the AUTOSAR-legal maximum payload still fits
in one Ethernet frame. Above 1400 bytes SOME/IP-TP takes over; a TP segment of 1392
bytes plus its headers and the DTLS record is 1449 bytes of UDP payload, so segments
also stay unfragmented.

## A. Round-trip latency (echo: payload travels both ways)

| Payload | plaintext p50 | DTLS p50 | Δ p50 | plaintext p99 | DTLS p99 | ok/total |
|---|---:|---:|---:|---:|---:|---:|
| 64 B | 198 us | 251 us | +27% | 275 us | 412 us | 300/300 |
| 512 B | 196 us | 250 us | +27% | 264 us | 390 us | 300/300 |
| 1400 B | 221 us | 296 us | +34% | 360 us | 436 us | 300/300 |
| 4 KiB | 298 us | 444 us | +49% | 389 us | 671 us | 200/200 |
| 16 KiB | 537 us | 1140 us | +112% | 691 us | 1284 us | 100/100 |
| 64 KiB | 1936 us | 3927 us | +103% | 2062 us | 4206 us | 50/50 |
| 256 KiB | 6684 us | 14179 us | +112% | 6868 us | 14581 us | 20/20 |
| 1 MiB | 26363 us | 57001 us | +116% | 27086 us | 60291 us | 10/10 |

## B. Upload throughput and CPU (sink: payload one way, 8 byte ack)

CPU is the target's service process, which is the side that decrypts. "CPU per MiB" is
its CPU time divided by the payload it received, and is the metric to use for sizing.

| Payload | plaintext | DTLS | Δ speed | target CPU plain | target CPU DTLS | CPU/MiB plain | CPU/MiB DTLS | CPU factor |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1400 B | 6.2 MiB/s | 4.8 MiB/s | -21% | 1.01% | 1.37% | 118.3 ms | 162.5 ms | 1.37x |
| 64 KiB | 63.6 MiB/s | 27.5 MiB/s | -57% | 1.72% | 4.28% | 13.0 ms | 33.2 ms | 2.56x |
| 256 KiB | 68.2 MiB/s | 27.2 MiB/s | -60% | 3.64% | 8.53% | 13.3 ms | 33.0 ms | 2.47x |
| 1 MiB | 69.7 MiB/s | 30.6 MiB/s | -56% | 5.96% | 13.89% | 13.2 ms | 32.6 ms | 2.46x |
| 4 MiB | 86.7 MiB/s | 31.4 MiB/s | -64% | 7.24% | 17.94% | 11.4 ms | 32.3 ms | 2.83x |
| 10 MiB | 86.4 MiB/s | 33.6 MiB/s | -61% | 11.62% | 27.33% | 10.8 ms | 29.9 ms | 2.77x |

## Reading the numbers

- **Small messages pay a fixed cost.** At 64 B to 1400 B the round trip grows by
  53 to 75 us, or 27 to 34%. That is per-record AEAD plus one extra copy on each of
  the four crossings, not anything that scales with payload.
- **Large messages pay per byte.** From 16 KiB upward the round trip roughly doubles
  and upload throughput settles at 27 to 34 MiB/s against 64 to 87 MiB/s plaintext.
  The target becomes the bottleneck: it spends 2.5 to 2.8x the CPU per MiB, and at
  10 MiB it is already at 27% of one core just to receive.
- **Throughput ceiling.** DTLS tops out near 33 MiB/s regardless of message size,
  while plaintext keeps scaling to 86 MiB/s. On this hardware the limit is AES-GCM
  plus the extra buffer handling on the AArch64 side, not the link.
- **Latency is stable.** p99/p50 stays near 1.05 for both modes at every size, so
  DTLS adds cost but not jitter.
- **Small-payload throughput is request-rate bound.** The 1400 B rows measure a
  synchronous request/response loop, so 4.8 and 6.2 MiB/s reflect the round-trip
  rate, not a transport limit.

## Two defects this benchmark exposed

Both were found by running the matrix, not by reading the code, and both are fixed
in this branch:

1. `udp_server_endpoint_impl::send_queued_dtls_unlocked()` returned `false`
   unconditionally. The caller reads that as "nothing in flight" and clears
   `is_sending_`, which lets a second send start while the first is still running and
   corrupts SOME/IP-TP reassembly. It now returns whether the write was accepted,
   matching the plaintext path.
2. The server kept a DTLS session per peer address and port and reused it forever.
   A restarted peer sends a fresh ClientHello from the same port, the established
   session could not consume it, and the new peer instance could never complete a
   handshake - every client process after the first was dead. A ClientHello arriving
   on a ready session now replaces that session.

## Reproducing

```bash
# service on the target
VSOMEIP_CONFIGURATION=<service json> ./dtls-bench-service

# one payload size on the Host
VSOMEIP_CONFIGURATION=<client json> ./dtls-bench-client \
    --size 1400 --iters 300 --warmup 3 --mode echo --label dtls
```

`--mode echo` returns the same payload and measures round-trip latency; `--mode sink`
answers with an 8 byte ack and measures upload throughput. Both binaries print one
machine-readable `CLIENT_STATS` / `SERVICE_STATS` line, so a driver script can build
the tables above without parsing prose.

## Scope

Single client, single service, idle 1 GbE segment, no competing traffic, one run per
point (no repeat-and-average). The numbers describe this pair of machines and should
be re-measured on target hardware before they are used for sizing.
