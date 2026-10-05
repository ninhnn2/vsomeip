# DTLS with X.509 certificates

Certificate mode is the second way the DTLS transport of the UDP endpoints can
authenticate peers. In PSK mode both peers hold the same symmetric key; in
certificate mode each ECU holds its own private key, and a common CA vouches for
its identity. The record layer, the endpoint integration and the fail-closed
behaviour are the same as in [PSK mode](dtls.md); only the handshake and the key
material differ.

Status: proof of concept, verified between an aarch64 target ECU and an x86_64
host with PEM key files. Keeping the private key in a hardware token through
PKCS#11 is supported by the OpenSSL backend (see [Key storage](#key-storage)).

## When to use which mode

| | PSK, one key per pair | Certificate |
|---|---|---|
| Secret material for N ECUs | N(N−1)/2 pair keys, each stored on two ECUs | N private keys, each on one ECU only |
| Adding an ECU | new key for every ECU it talks to | one certificate for the new ECU |
| Cipher with forward secrecy | `ECDHE-PSK-CHACHA20-POLY1305` (no AES-GCM variant in OpenSSL) | `ECDHE-ECDSA-AES128-GCM-SHA256` (hardware AES) |
| Proof of identity | possession of the pair key | CA chain **and** name pinned per address |
| Handshake | 4 datagrams | more and larger datagrams, cookie round trip |
| Infrastructure | key provisioning | CA, issuing, rotation |

PSK is simpler for a handful of fixed links. Certificates scale with the number
of ECUs and give every ECU an identity of its own, which is what lifecycle
management (issuing, rotation, replacement of a part) needs.

## What a peer has to prove

A handshake succeeds only if all of the following hold, checked by both sides
(mutual authentication):

1. **Chain** — the peer's certificate chains to a trust anchor in `ca`.
2. **Possession** — the peer signs the handshake with the private key of that
   certificate (`ServerKeyExchange` signature on the server, `CertificateVerify`
   on the client).
3. **Name** — the certificate's subjectAltName DNS entry equals the `name`
   configured for the peer's address. The subject CN is ignored.
4. **Purpose** — `extendedKeyUsage` allows the role: `serverAuth` when the peer
   is the server, `clientAuth` when it is the client. ECU certificates carry
   both, because an ECU serves some services and consumes others.
5. **Validity** — not expired and not before its start date, subject to the
   [time floor](#time) when the clock is not trusted.

Point 3 is the one a plain "valid chain" check misses: every ECU certificate of
the OEM CA has a valid chain, so without the name pin a compromised camera ECU
could present its own genuine certificate and pass as any other ECU. A peer
address that is not listed in `peers` is refused outright.

## Handshake

DTLS 1.2, captured on the target, host 192.0.2.112 as client, target 192.0.2.4
as server:

| # | From | Bytes | Messages |
|---|---|---|---|
| 1 | client | 147 | ClientHello |
| 2 | server | 60 | HelloVerifyRequest (32 B cookie) |
| 3 | client | 179 | ClientHello + cookie |
| 4 | server | 1200 | ServerHello (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`), Certificate, ServerKeyExchange (X25519 public key, ECDSA-signed), CertificateRequest (first fragment) |
| 5 | server | 64 | CertificateRequest (rest), ServerHelloDone |
| 6 | client | 1147 | Certificate, ClientKeyExchange (X25519 public key), CertificateVerify, ChangeCipherSpec, Finished |
| 7 | server | 746 | NewSessionTicket, ChangeCipherSpec, Finished |

7 datagrams and 3543 bytes, against 4 datagrams and 728 bytes for ECDHE-PSK;
one extra round trip for the cookie. The server flight is split at the 1200-byte
DTLS MTU the session sets. Each side signs once and verifies two signatures
(leaf and issuing CA); on an idle Cortex-A72 core an ECDSA P-256 signature takes
0.13 ms and a verification 0.32 ms, so the handshake adds well under 1 ms of CPU
per side.

The ephemeral X25519 keys give forward secrecy exactly as in ECDHE-PSK; the
long-term ECDSA keys only sign, they never encrypt. The server's first answer is
a `HelloVerifyRequest` with a stateless cookie (RFC 6347 4.2.1): a certificate
flight is about ten times the size of a ClientHello, and without the cookie a
spoofed sender could aim it at a victim.

## Time

An ECU without a battery-backed clock boots at 1970-01-01 and has no time source
when the endpoints start. Checked against that clock every certificate is "not
yet valid". Turning time checks off would accept expired certificates forever.

The configuration therefore carries a **time floor** (`time-floor`, default
2026-10-01), normally the firmware release date:

- clock ≥ floor: the TLS library checks validity against the clock, as usual;
- clock < floor: the clock is treated as unset. Expiry is checked against the
  floor (a certificate that expired before the firmware was released is
  rejected); not-before cannot be checked. A warning is logged once.

Certificates are therefore issued with a start date at or before the floor.
Once a trusted time base is available (StbM, GNSS, authenticated NTP) the
regular check applies automatically.

## PKI

`test/unit_tests/dtls_session_tests/pki.sh` builds a small PKI with the shape of
a vehicle PKI:

```
Lab Vehicle Root CA      10 y   P-256   pathlen 1   offline trust anchor; ECUs get ca.crt only
└─ Lab ECU Issuing CA     2 y   P-256   pathlen 0   signs ECU certificates
   └─ <ecu>.ecu.lab      90 d   P-256   CA:false    KU digitalSignature
                                                    EKU serverAuth, clientAuth
                                                    SAN DNS:<ecu>.ecu.lab
```

Each ECU receives `node.key` (0600), `node.crt` (its certificate followed by the
issuing CA, so the peer can build the chain) and `ca.crt` (the root). The tool is
for tests only: it keeps every private key, including the CA keys, in one
directory. In production the root CA stays in the OEM's offline HSM, the issuing
CA lives in the factory infrastructure, and an ECU generates its key pair inside
its own HSM, so only a CSR ever leaves the ECU.

## Key storage

`private-key` accepts either a PEM file or, with the OpenSSL backend, an OpenSSL
store URI (the wolfSSL backend reads PEM files only). A URI is passed
to `OSSL_STORE_open()` unchanged, so with a PKCS#11 provider installed

```json
"private-key": "pkcs11:token=ecu-identity;object=dtls-identity;type=private"
```

makes OpenSSL sign the handshake inside the token; the key never enters the
process. No vsomeip code changes between the file and the token form.

For a token, generate the key inside it with `CKA_SENSITIVE=TRUE` and
`CKA_EXTRACTABLE=FALSE`, create the CSR through the provider, and install only
the signed certificate. Configure the provider with
`default_properties = ?provider=default`, so hashing, record encryption and peer
verification stay in the default provider and only operations on the token key
go to the token. The token PIN is then read by the provider from a 0600 file:
root on the ECU can **use** the key while the process runs, but copying the file
system does not yield the key.

Without a token the key is a 0600 file; the configuration loader refuses a key
file that group or others can read.

## Revocation and rotation

The SSL context, including certificate, key and CA, is built per session, so a
renewed certificate or a replaced CA bundle is used from the next handshake on,
without restarting the application.

Online revocation (OCSP) does not fit a vehicle without permanent connectivity,
and CRL checking is not implemented in this proof of concept. The intended model
is short-lived ECU certificates (90 days in the lab PKI) renewed over the air,
plus removal of a compromised ECU's name from the `peers` lists.

## Failure behaviour

Every failure keeps DTLS enabled and delivers nothing; there is no plaintext
fallback. Missing, unreadable or mismatching certificate, key or CA files are
rejected when the configuration loads or the session is created; certificate
problems are reported with the verification reason, for example
`certificate rejected: hostname mismatch`.

A rejected handshake does not fix itself, so the client endpoint backs off
exponentially (100 ms, 200 ms, … capped at 30 s, reset after a successful
handshake) instead of retrying at once, and the handshake-failure warning is
limited to one line per second with a count of the lines folded into it. With a
misconfigured peer this turns 51 attempts and 51 log lines in six seconds into
7 attempts and 4 lines.

## Verification

Between the aarch64 target 192.0.2.4 and the x86_64 host 192.0.2.112, both
directions.

**Functional** — host→target and target→host each pass 100/100 requests of
1400 B in DTLS and in plain mode, one handshake per direction. Each side logs
the peer it verified:

```
target: DTLS: certificate handshake completed, peer host.ecu.lab, cipher ECDHE-ECDSA-AES128-GCM-SHA256
host:   DTLS: certificate handshake completed, peer server.ecu.lab, cipher ECDHE-ECDSA-AES128-GCM-SHA256
target: DTLS: system clock is before the time floor (1790812800); certificate expiry is checked against the floor, ...
```

**Rejections** — 12/12, host client → target service; in every failing case the
client received 0 responses, so nothing reached the application by any path:

| Case | Rejected by | Reason logged |
|---|---|---|
| Reference, correct certificates | — | handshake completed, 3/3 responses |
| Host certificate from another CA, correct name | target | `unable to get local issuer certificate` |
| Host certificate expired; target clock at 1970, time floor applies | target | `certificate has expired` |
| Target certificate expired; host clock correct | host | `certificate has expired` |
| Target certificate not yet valid | host | `certificate is not yet valid` |
| Host presents another ECU's valid certificate (`camera.ecu.lab`) | target | `hostname mismatch` |
| Host certificate without `clientAuth` | target | `unsuitable certificate purpose` |
| Target trusts a different CA | target | `unable to get local issuer certificate` |
| Target has no name configured for the host's address | target | `no expected certificate name configured for peer` |
| Host private key does not match its certificate | host, at start-up | `private key does not match certificate` |
| Host private key mode 0644 | host, at load | `private key is readable by group or others` |
| Host in PSK mode, target in certificate mode | target | `no shared cipher` |

The PSK rejection cases still pass, so certificate mode did not change PSK
behaviour. The same rejections are covered without a network by
`unit_tests_dtls_session_tests`.

**Rotation without restart** — with the target service running (one pid
throughout), its certificate was replaced by an expired one and back:

| Step | Result |
|---|---|
| valid certificate | 3/3, handshake completed |
| replaced by an expired certificate, no restart | 0/3, host rejects: `certificate has expired` |
| valid certificate restored, no restart | 3/3, handshake completed |

**Build** — the changed sources compile with the repository's own flags
including `-Werror` (GCC 12, x86_64) and with an aarch64 cross toolchain
(GCC 13.3).

## Reproducing

```bash
cmake -DGTEST_ROOT=<googletest> ..           # optionally -DVSOMEIP_DTLS_BACKEND=wolfssl
make unit_tests_dtls_session_tests
./test/unit_tests/dtls_session_tests/unit_tests_dtls_session_tests
```

The test generates its own PKI with `pki.sh` (bash and the `openssl` command
line tool are needed) and removes it afterwards.

## Limitations

- DTLS 1.2 only.
- No CRL or OCSP; revocation relies on short certificate lifetimes and the
  `peers` lists.
- Not-before cannot be checked while the clock is below the time floor.
- The name is pinned per peer address. Authorisation of which ECU may offer or
  use which service is outside DTLS and still follows the vsomeip security
  policies.
