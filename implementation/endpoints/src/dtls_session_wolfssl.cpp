// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// wolfSSL backend of dtls_session (CMake: -DVSOMEIP_DTLS_BACKEND=wolfssl).
//
// Behaviour matches the OpenSSL backend in dtls_session.cpp: same public
// interface, same datagram queues, same retransmit and failure handling, and
// the same log texts for every rejection, so documentation and tests apply to
// both. What differs is only how the TLS library is driven:
//
//   OpenSSL                         wolfSSL
//   custom BIO (bio_read/write)     I/O callbacks (io_recv/io_send)
//   SSL_set_mtu(1200)               1200 during the handshake, 1500 after it
//   own HMAC cookie callbacks       wolfSSL's HMAC cookie, bound to the peer address
//   X509_VERIFY_PARAM host pin      wolfSSL_check_domain_name (SAN only)
//   OSSL_STORE (file or pkcs11:)    PEM file only

#include "../include/dtls_record_limit.hpp"
#include "../include/dtls_session.hpp"
#include "../include/dtls_wolfssl_device.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <iterator>
#include <mutex>

#include <boost/asio/error.hpp>
#include <boost/asio/ip/udp.hpp>

#include <vsomeip/internal/logger.hpp>

// options.h first: the application must see exactly the defines the library
// was configured with, otherwise struct layouts differ (wolfSSL AGENTS.md).
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(WOLFSSL_DTLS) || defined(NO_PSK) || !defined(OPENSSL_EXTRA) || !defined(WOLFSSL_DTLS_MTU)
#error "wolfSSL must be configured with --enable-dtls --enable-psk --enable-dtls-mtu --enable-opensslextra"
#endif
// ALWAYS_VERIFY_CB: verify_certificate() sees every certificate (time floor, reasons).
// ALT_NAME_ONLY: the pinned peer name must be in the SAN; no fallback to the CN.
// STATIC_PSK: the plain PSK suites, including the default PSK-AES128-GCM-SHA256.
#if !defined(WOLFSSL_ALWAYS_VERIFY_CB) || !defined(WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY) || !defined(WOLFSSL_STATIC_PSK)
#error "wolfSSL must be built with -DWOLFSSL_ALWAYS_VERIFY_CB -DWOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY -DWOLFSSL_STATIC_PSK"
#endif

namespace vsomeip_v3 {
namespace {

// Handshake flights are split at this size, like the OpenSSL backend, so a
// certificate chain never needs IP fragmentation.
constexpr unsigned short HANDSHAKE_MTU = 1200U;
// Largest plaintext of one TLS/DTLS record (RFC 6347 4.1.1: 2^14).
constexpr std::size_t MAX_RECORD_PLAINTEXT = 16384U;
// After the handshake wolfSSL also limits each application record to the MTU:
// one datagram, never IP-fragmented (dtls::DATAGRAM_SIZE). A SOME/IP datagram is
// at most 1416 bytes, which fits with AES-GCM (1435) or ChaCha20 (1443), but a
// CBC-SHA256 record carries at most 1407 bytes. The UDP endpoints know that
// limit (dtls::max_message_size) and send larger messages as SOME/IP-TP
// segments; anything still too large is refused by write().
constexpr unsigned short DATA_MTU = static_cast<unsigned short>(dtls::DATAGRAM_SIZE);
// A flight resent only because the peer resent its own goes out at most this
// often; the retransmit timer (1 s, doubling) is not limited.
constexpr auto RESEND_INTERVAL = std::chrono::milliseconds(1000);

constexpr std::uint8_t RECORD_CHANGE_CIPHER_SPEC = 0x14U;
constexpr std::uint8_t RECORD_HANDSHAKE = 0x16U;

bool decode_hex_key(const std::string& _hex, std::vector<unsigned char>& _key) {
    if (_hex.empty() || (_hex.size() % 2U) != 0U || _hex.size() < 32U) {
        return false;
    }
    auto nibble = [](char _c) -> int {
        if (_c >= '0' && _c <= '9') {
            return _c - '0';
        }
        if (_c >= 'a' && _c <= 'f') {
            return _c - 'a' + 10;
        }
        if (_c >= 'A' && _c <= 'F') {
            return _c - 'A' + 10;
        }
        return -1;
    };
    _key.reserve(_hex.size() / 2U);
    for (std::size_t i = 0; i < _hex.size(); i += 2U) {
        const int hi = nibble(_hex[i]);
        const int lo = nibble(_hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            _key.clear();
            return false;
        }
        _key.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

void ensure_library_initialized() {
    static std::once_flag its_once;
    std::call_once(its_once, []() { wolfSSL_Init(); });
}

std::string error_text(int _error) {
    char its_text[WOLFSSL_MAX_ERROR_SZ] = {0};
    wolfSSL_ERR_error_string_n(static_cast<unsigned long>(_error), its_text, sizeof(its_text));
    return its_text;
}

// The OpenSSL backend reports certificate problems with OpenSSL's verify
// strings. Use the same words here so logs, documentation and the negative
// tests do not depend on the backend; wolfSSL's own text is appended.
const char* certificate_reason(int _error) {
    switch (_error) {
    case ASN_NO_SIGNER_E:
        return "unable to get local issuer certificate";
    case ASN_AFTER_DATE_E:
        return "certificate has expired";
    case ASN_BEFORE_DATE_E:
        return "certificate is not yet valid";
    case DOMAIN_NAME_MISMATCH:
        return "hostname mismatch";
    case EXTKEYUSE_AUTH_E:
        return "unsuitable certificate purpose";
    case NO_PEER_CERT:
        return "peer did not return a certificate";
    default:
        return nullptr;
    }
}

const char* handshake_reason(int _error) {
    switch (_error) {
    case MATCH_SUITE_ERROR:
        return "no shared cipher";
    case PSK_KEY_ERROR:
        return "psk identity not found";
    default:
        return certificate_reason(_error);
    }
}

// "ip:port" (as the endpoints build it) -> endpoint; the port follows the last ':'.
bool to_endpoint(const std::string& _address, boost::asio::ip::udp::endpoint& _endpoint) {
    const auto its_colon = _address.rfind(':');
    if (its_colon == std::string::npos) {
        return false;
    }
    boost::system::error_code its_error;
    const auto its_ip = boost::asio::ip::make_address(_address.substr(0, its_colon), its_error);
    if (its_error) {
        return false;
    }
    try {
        const auto its_port = std::stoul(_address.substr(its_colon + 1U));
        if (its_port > 0xFFFFU) {
            return false;
        }
        _endpoint = boost::asio::ip::udp::endpoint(its_ip, static_cast<unsigned short>(its_port));
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

dtls_session* session_of(WOLFSSL* _ssl) {
    return _ssl ? static_cast<dtls_session*>(wolfSSL_GetIOReadCtx(_ssl)) : nullptr;
}

// VSOMEIP_DTLS_STATS=<seconds>: every <seconds>, log where the records' time went,
// summed over all sessions of the process. Off (the default) it costs one test.
//   send     wolfSSL_write: encrypt + MAC of one outgoing record
//   receive  datagram -> plaintext: MAC check + decrypt (wolfSSL_read loop)
//   SA2UL    CIOCCRYPT ioctl, included in send/receive when "accelerator": "sa2ul"
const long g_stats_period_s = [] {
    const char* its_value = std::getenv("VSOMEIP_DTLS_STATS");
    return its_value ? std::strtol(its_value, nullptr, 10) : 0L;
}();

struct stats_t {
    std::atomic<std::uint64_t> sent_{0}, send_ns_{0}, send_cpu_ns_{0};
    std::atomic<std::uint64_t> received_{0}, receive_ns_{0}, receive_cpu_ns_{0};
    std::atomic<std::int64_t> last_report_ns_{0};
    std::atomic<std::uint64_t> sa2ul_calls_{0}, sa2ul_ns_{0}; // values at the last report
};
stats_t g_stats;

bool stats_enabled() {
    return g_stats_period_s > 0;
}

std::int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// CPU time of the calling thread: wall time minus this is time spent waiting
// (for the CPU on a loaded board, or for the SA2UL's DMA).
std::int64_t thread_cpu_ns() {
    timespec its_time{};
    ::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &its_time);
    return static_cast<std::int64_t>(its_time.tv_sec) * 1000000000LL + its_time.tv_nsec;
}

double per_item_us(std::uint64_t _ns, std::uint64_t _count) {
    return _count ? static_cast<double>(_ns) / static_cast<double>(_count) / 1000.0 : 0.0;
}

void report_stats() {
    const std::int64_t its_now = now_ns();
    std::int64_t its_last = g_stats.last_report_ns_.load();
    if (its_last == 0) {
        g_stats.last_report_ns_.compare_exchange_strong(its_last, its_now);
        return;
    }
    if (its_now - its_last < g_stats_period_s * 1000000000LL || !g_stats.last_report_ns_.compare_exchange_strong(its_last, its_now)) {
        return;
    }
    const auto sent = g_stats.sent_.exchange(0), send_ns = g_stats.send_ns_.exchange(0);
    const auto send_cpu_ns = g_stats.send_cpu_ns_.exchange(0);
    const auto received = g_stats.received_.exchange(0), receive_ns = g_stats.receive_ns_.exchange(0);
    const auto receive_cpu_ns = g_stats.receive_cpu_ns_.exchange(0);
    const auto calls_now = dtls_wolfssl::sa2ul_operations(), ns_now = dtls_wolfssl::sa2ul_nanoseconds();
    const auto calls = calls_now - g_stats.sa2ul_calls_.exchange(calls_now), sa2ul_ns = ns_now - g_stats.sa2ul_ns_.exchange(ns_now);
    char its_line[480];
    std::snprintf(its_line, sizeof(its_line),
                  "DTLS stats %.1f s: send %llu records %.1f us each (cpu %.1f) | receive %llu records %.1f us each (cpu %.1f)"
                  " | SA2UL %llu calls %.1f us each (%.2f per record)",
                  static_cast<double>(its_now - its_last) / 1e9, static_cast<unsigned long long>(sent), per_item_us(send_ns, sent),
                  per_item_us(send_cpu_ns, sent), static_cast<unsigned long long>(received), per_item_us(receive_ns, received),
                  per_item_us(receive_cpu_ns, received),
                  static_cast<unsigned long long>(calls), per_item_us(sa2ul_ns, calls),
                  (sent + received) ? static_cast<double>(calls) / static_cast<double>(sent + received) : 0.0);
    VSOMEIP_INFO << its_line;
}

} // namespace

std::shared_ptr<dtls_session> dtls_session::create(boost::asio::io_context& _io, bool _is_client, credentials _credentials,
                                                   send_handler_t _send, plaintext_handler_t _receive) {
    auto result = std::shared_ptr<dtls_session>(
            new dtls_session(_io, _is_client, std::move(_credentials), std::move(_send), std::move(_receive)));
    if (!result->initialize()) {
        return {};
    }
    // Handshake time is measured from here: key and certificate loading excluded.
    result->started_ = std::chrono::steady_clock::now();
    return result;
}

dtls_session::dtls_session(boost::asio::io_context& _io, bool _is_client, credentials _credentials, send_handler_t _send,
                           plaintext_handler_t _receive) :
    retransmit_timer_(_io), is_client_(_is_client), identity_(std::move(_credentials.identity_)),
    resolver_(std::move(_credentials.resolver_)), cipher_(std::move(_credentials.cipher_)),
    accelerator_(std::move(_credentials.accelerator_)), auth_(_credentials.auth_),
    certificate_(std::move(_credentials.certificate_)), private_key_(std::move(_credentials.private_key_)),
    ca_(std::move(_credentials.ca_)), peer_name_(std::move(_credentials.peer_name_)),
    peer_address_(std::move(_credentials.peer_address_)), time_floor_(_credentials.time_floor_), send_(std::move(_send)),
    receive_(std::move(_receive)) {
    if (cipher_.empty()) {
        cipher_ = auth_ == dtls_auth_e::CERTIFICATE ? VSOMEIP_DTLS_DEFAULT_CERT_CIPHER : VSOMEIP_DTLS_DEFAULT_CIPHER;
    }
    // A PSK server resolves the key once it knows which identity the client
    // claims, so it starts without one; a PSK client must carry its key.
    if (auth_ == dtls_auth_e::PSK && is_client_ && !decode_hex_key(_credentials.psk_hex_, psk_)) {
        is_failed_ = true;
    }
    std::fill(_credentials.psk_hex_.begin(), _credentials.psk_hex_.end(), '\0');
}

dtls_session::~dtls_session() {
    boost::system::error_code ignored;
    retransmit_timer_.cancel(ignored);
    if (ssl_) {
        wolfSSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (context_) {
        wolfSSL_CTX_free(context_);
        context_ = nullptr;
    }
    std::fill(psk_.begin(), psk_.end(), 0U);
}

bool dtls_session::initialize() {
    if (is_failed_ || !send_ || !receive_) {
        VSOMEIP_ERROR << "DTLS: invalid PSK configuration (identity or key)";
        is_failed_ = true;
        return false;
    }
    ensure_library_initialized();

    // DTLS 1.2 only, like the OpenSSL backend, so both can talk to each other.
    context_ = wolfSSL_CTX_new(is_client_ ? wolfDTLSv1_2_client_method() : wolfDTLSv1_2_server_method());
    if (!context_) {
        VSOMEIP_ERROR << "DTLS: failed to create wolfSSL context";
        is_failed_ = true;
        return false;
    }
    if (wolfSSL_CTX_set_cipher_list(context_, cipher_.c_str()) != WOLFSSL_SUCCESS) {
        VSOMEIP_ERROR << "DTLS: cipher \"" << cipher_ << "\" is unavailable in this wolfSSL build";
        is_failed_ = true;
        return false;
    }
    if (!attach_device()) {
        is_failed_ = true;
        return false;
    }
    // Ephemeral groups for the ECDHE suites, preferred first.
    wolfSSL_CTX_UseSupportedCurve(context_, WOLFSSL_ECC_X25519);
    wolfSSL_CTX_UseSupportedCurve(context_, WOLFSSL_ECC_SECP256R1);

    // Our transport: wolfSSL reads and writes the datagram queues only.
    wolfSSL_CTX_SetIORecv(context_, &dtls_session::io_recv);
    wolfSSL_CTX_SetIOSend(context_, &dtls_session::io_send);

    const bool its_mode_ok = auth_ == dtls_auth_e::CERTIFICATE ? initialize_certificate() : initialize_psk();
    if (!its_mode_ok) {
        is_failed_ = true;
        return false;
    }

    ssl_ = wolfSSL_new(context_);
    if (!ssl_) {
        VSOMEIP_ERROR << "DTLS: failed to allocate wolfSSL session";
        is_failed_ = true;
        return false;
    }
    wolfSSL_SetIOReadCtx(ssl_, this);
    wolfSSL_SetIOWriteCtx(ssl_, this);
    wolfSSL_dtls_set_using_nonblock(ssl_, 1);
    if (wolfSSL_dtls_set_mtu(ssl_, HANDSHAKE_MTU) != WOLFSSL_SUCCESS) {
        VSOMEIP_ERROR << "DTLS: cannot set the handshake MTU";
        is_failed_ = true;
        return false;
    }

    if (auth_ == dtls_auth_e::CERTIFICATE) {
        // The chain alone only proves "some ECU of this CA". Pinning the
        // expected SAN name per peer address is what stops one ECU
        // impersonating another (SAN only: WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY).
        if (wolfSSL_check_domain_name(ssl_, peer_name_.c_str()) != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: cannot pin the expected peer name";
            is_failed_ = true;
            return false;
        }
        wolfSSL_SetCertCbCtx(ssl_, this);
    }
    if (!is_client_ && !peer_address_.empty()) {
        // wolfSSL always answers a first ClientHello with a HelloVerifyRequest.
        // Its cookie is an HMAC under a per-session secret over the peer
        // address it was given and the ClientHello, so give it the sender.
        boost::asio::ip::udp::endpoint its_peer;
        if (to_endpoint(peer_address_, its_peer)
            && wolfSSL_dtls_set_peer(ssl_, its_peer.data(), static_cast<unsigned int>(its_peer.size())) != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: cannot bind the cookie to peer " << peer_address_;
            is_failed_ = true;
            return false;
        }
    }
    return true;
}

bool dtls_session::attach_device() {
    dtls_wolfssl::pkcs11_uri its_uri;
    dtls_wolfssl::device_request its_request;
    its_request.sa2ul_ = accelerator_ == "sa2ul";
    if (auth_ == dtls_auth_e::CERTIFICATE && private_key_.rfind("pkcs11:", 0) == 0) {
        std::string its_reason;
        if (!dtls_wolfssl::parse_pkcs11_uri(private_key_, its_uri, its_reason)) {
            VSOMEIP_ERROR << "DTLS: private key " << private_key_ << ": " << its_reason;
            return false;
        }
        its_request.key_ = &its_uri;
    }
    if (!its_request.sa2ul_ && !its_request.key_) {
        return true;
    }

    dtls_wolfssl::device its_device;
    std::string its_reason;
    if (!dtls_wolfssl::acquire_device(its_request, its_device, its_reason)) {
        // Only a missing token key gets here: without it there is no identity.
        VSOMEIP_ERROR << "DTLS: " << its_reason;
        return false;
    }
    if (its_request.sa2ul_) {
        // Said once per process: every session would report the same.
        static std::once_flag its_reported;
        // CBC suites are not always named so: ECDHE-ECDSA-AES128-SHA256 is CBC.
        const bool its_cbc = cipher_.find("AES") != std::string::npos && cipher_.find("GCM") == std::string::npos
                && cipher_.find("CCM") == std::string::npos;
        std::call_once(its_reported, [&its_device, &its_reason, its_cbc, this]() {
            if (!its_device.sa2ul_) {
                VSOMEIP_WARNING << "DTLS: SA2UL accelerator unavailable (" << its_reason << "); AES runs on the CPU";
            } else if (!its_cbc) {
                VSOMEIP_WARNING << "DTLS: the SA2UL accelerates AES-CBC only; cipher " << cipher_ << " runs on the CPU";
            }
        });
    }
    if (its_device.id_ != INVALID_DEVID) {
        if (wolfSSL_CTX_SetDevId(context_, its_device.id_) != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: cannot attach the crypto device to the wolfSSL context";
            return false;
        }
        device_id_ = its_device.id_;
    }
    if (its_request.key_) {
        key_label_ = its_uri.object_;
    }
    return true;
}

bool dtls_session::initialize_psk() {
    const bool its_identity_ok = is_client_ ? (!identity_.empty() && identity_.size() < 128U) : static_cast<bool>(resolver_);
    if (!its_identity_ok) {
        VSOMEIP_ERROR << "DTLS: invalid PSK configuration (identity or key)";
        return false;
    }
    if (is_client_) {
        wolfSSL_CTX_set_psk_client_callback(context_, &dtls_session::client_psk);
    } else {
        wolfSSL_CTX_set_psk_server_callback(context_, &dtls_session::server_psk);
    }
    return true;
}

bool dtls_session::initialize_certificate() {
    if (certificate_.empty() || private_key_.empty() || ca_.empty()) {
        VSOMEIP_ERROR << "DTLS: certificate mode needs a certificate, a private key and a CA";
        return false;
    }
    if (peer_name_.empty()) {
        // Without an expected name any certificate of the CA would be accepted.
        VSOMEIP_ERROR << "DTLS: no expected certificate name configured for peer " << peer_address_;
        return false;
    }

    // A "file:" URI names a plain PEM file; "pkcs11:" a key in a token, which
    // attach_device() has already opened. Other store URIs are refused.
    std::string its_key = private_key_;
    if (its_key.rfind("file:", 0) == 0) {
        its_key.erase(0, 5);
    } else if (key_label_.empty() && its_key.find(':') != std::string::npos && its_key.find('/') > its_key.find(':')) {
        VSOMEIP_ERROR << "DTLS: private key URI " << private_key_
                      << " is not supported by the wolfSSL backend (PEM file, file: or pkcs11:)";
        return false;
    }

    int its_result = wolfSSL_CTX_use_certificate_chain_file(context_, certificate_.c_str());
    if (its_result != WOLFSSL_SUCCESS) {
        VSOMEIP_ERROR << "DTLS: cannot load certificate chain " << certificate_ << ": " << error_text(its_result);
        return false;
    }
    if (!key_label_.empty()) {
        // The key never leaves the token: wolfSSL only keeps its label and asks
        // the device to sign. No key/certificate match check here, it would
        // cost a token signature per session; the CSR was signed by this key.
        if (wolfSSL_CTX_use_PrivateKey_Label(context_, key_label_.c_str(), device_id_) != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: cannot use key \"" << key_label_ << "\" of the token";
            return false;
        }
    } else {
        its_result = wolfSSL_CTX_use_PrivateKey_file(context_, its_key.c_str(), WOLFSSL_FILETYPE_PEM);
        if (its_result != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: cannot load private key " << private_key_ << ": " << error_text(its_result);
            return false;
        }
        if (wolfSSL_CTX_check_private_key(context_) != WOLFSSL_SUCCESS) {
            VSOMEIP_ERROR << "DTLS: private key does not match certificate " << certificate_;
            return false;
        }
    }
    // Untrusted clock (an ECU without RTC boots at 1970): wolfSSL compares validity with
    // "now" and calls every certificate "not yet valid". verify_certificate()
    // then accepts not-before and enforces expiry against the floor instead.
    clock_untrusted_ = static_cast<std::int64_t>(std::time(nullptr)) < time_floor_;
    if (clock_untrusted_) {
        static std::once_flag its_reported;
        const auto its_floor = time_floor_;
        std::call_once(its_reported, [its_floor]() {
            VSOMEIP_WARNING << "DTLS: system clock is before the time floor (" << its_floor
                            << "); certificate expiry is checked against the floor, not-before is not checked";
        });
    }

    // wolfSSL also checks the dates of a trust anchor while loading it, against
    // the same untrusted clock. Let it load then; the CA's expiry is checked
    // against the floor in verify_certificate() like every other certificate.
    its_result = wolfSSL_CTX_load_verify_locations_ex(context_, ca_.c_str(), nullptr,
                                                      clock_untrusted_ ? WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY
                                                                       : WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);
    if (its_result != WOLFSSL_SUCCESS) {
        VSOMEIP_ERROR << "DTLS: cannot load CA " << ca_ << ": " << error_text(its_result);
        return false;
    }

    // Mutual authentication: a server that does not insist on a client
    // certificate authenticates only itself.
    wolfSSL_CTX_set_verify(context_, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           &dtls_session::verify_certificate);
    return true;
}

void dtls_session::log_handshake_failure(int _ssl_error) {
    // Anyone who can send a datagram can cause this line; keep it to one per
    // second so a peer cannot flood the log, and say how many were folded in.
    static std::atomic<std::int64_t> its_last_ms{0};
    static std::atomic<std::uint32_t> its_suppressed{0};
    const auto its_now_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto its_last = its_last_ms.load();
    if (its_now_ms - its_last < 1000 || !its_last_ms.compare_exchange_strong(its_last, its_now_ms)) {
        ++its_suppressed;
        return;
    }
    const auto its_folded = its_suppressed.exchange(0);

    std::string its_reason;
    if (!verify_reason_.empty()) {
        its_reason = "certificate rejected: " + verify_reason_;
    } else if (const char* its_known = handshake_reason(_ssl_error)) {
        its_reason = std::string(its_known) + " (" + error_text(_ssl_error) + ")";
    } else {
        its_reason = error_text(_ssl_error);
    }
    VSOMEIP_WARNING << "DTLS: handshake failed (ssl error " << _ssl_error << "): " << its_reason
                    << (its_folded ? " (+" + std::to_string(its_folded) + " similar in the last second)" : std::string());
}

int dtls_session::verify_certificate(int _preverify, WOLFSSL_X509_STORE_CTX* _context) {
    auto* session = _context ? static_cast<dtls_session*>(_context->userCtx) : nullptr;
    if (!session) {
        return _preverify;
    }
    if (!_preverify) {
        const int its_error = _context->error;
        // Not-before cannot be judged without a trusted clock; anything else
        // (issuer, name, purpose, signature, expiry) stays a rejection.
        if (!(session->clock_untrusted_ && its_error == ASN_BEFORE_DATE_E)) {
            const char* its_known = certificate_reason(its_error);
            session->verify_reason_ = its_known ? its_known : error_text(its_error);
            return 0;
        }
    }
    if (session->clock_untrusted_) {
        WOLFSSL_X509* its_certificate = wolfSSL_X509_STORE_CTX_get_current_cert(_context);
        time_t its_floor = static_cast<time_t>(session->time_floor_);
        if (!its_certificate) {
            session->verify_reason_ = "no certificate to check against the time floor";
            return 0;
        }
        if (wolfSSL_X509_cmp_time(wolfSSL_X509_get_notAfter(its_certificate), &its_floor) < 0) {
            session->verify_reason_ = "certificate has expired";
            return 0;
        }
    }
    return 1;
}

void dtls_session::start() {
    std::vector<datagram_t> outgoing;
    std::vector<datagram_t> plaintext;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (is_failed_ || is_ready_) {
            return;
        }
        drive_locked(outgoing, plaintext);
        note_sent_locked(outgoing);
    }
    flush(std::move(outgoing), std::move(plaintext));
}

void dtls_session::feed(const std::uint8_t* _data, std::size_t _size) {
    std::vector<datagram_t> plaintext;
    feed(_data, _size, plaintext);
    for (auto& message : plaintext) {
        receive_(std::move(message));
    }
}

void dtls_session::feed(const std::uint8_t* _data, std::size_t _size, std::vector<datagram_t>& _plaintext) {
    if (!_data || _size == 0U) {
        return;
    }
    std::vector<datagram_t> outgoing;
    std::vector<datagram_t> plaintext;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (is_failed_) {
            return;
        }
        incoming_.emplace_back(_data, _data + _size);
        const bool its_timed = stats_enabled() && is_ready_;
        const std::int64_t its_start = its_timed ? now_ns() : 0;
        const std::int64_t its_cpu_start = its_timed ? thread_cpu_ns() : 0;
        drive_locked(outgoing, plaintext);
        if (its_timed && !plaintext.empty()) {
            g_stats.receive_ns_ += static_cast<std::uint64_t>(now_ns() - its_start);
            g_stats.receive_cpu_ns_ += static_cast<std::uint64_t>(thread_cpu_ns() - its_cpu_start);
            g_stats.received_ += plaintext.size();
        }
        if (!outgoing.empty() && is_resend_locked(outgoing)) {
            const auto its_now = std::chrono::steady_clock::now();
            if (its_now - last_resend_ < RESEND_INTERVAL) {
                outgoing.clear();  // as if lost; the peer's timer recovers it
            } else {
                last_resend_ = its_now;
            }
        }
        note_sent_locked(outgoing);
    }
    flush(std::move(outgoing), {});
    if (!plaintext.empty()) {
        if (stats_enabled()) {
            report_stats();
        }
        if (_plaintext.empty()) {
            _plaintext = std::move(plaintext);
        } else {
            std::move(plaintext.begin(), plaintext.end(), std::back_inserter(_plaintext));
        }
    }
}

// True when every record is a handshake message or ChangeCipherSpec that was
// sent before. New flights, application data and alerts are never resends.
bool dtls_session::is_resend_locked(const std::vector<datagram_t>& _outgoing) const {
    bool its_any = false;
    for (const auto& its_datagram : _outgoing) {
        std::size_t its_offset = 0;
        while (its_offset + VSOMEIP_DTLS_RECORD_HEADER_SIZE <= its_datagram.size()) {
            const std::uint8_t* its_record = its_datagram.data() + its_offset;
            const std::size_t its_length = static_cast<std::size_t>(its_record[11] << 8 | its_record[12]);
            const unsigned its_epoch = static_cast<unsigned>(its_record[3] << 8 | its_record[4]);
            if (its_record[0] == RECORD_CHANGE_CIPHER_SPEC || (its_record[0] == RECORD_HANDSHAKE && its_epoch > 0U)) {
                // ChangeCipherSpec and the encrypted Finished after it
                if (!sent_change_cipher_spec_) {
                    return false;
                }
            } else if (its_record[0] == RECORD_HANDSHAKE && its_length >= 6U) {
                // handshake header: type(1) length(3) message_seq(2)
                const int its_seq = its_record[VSOMEIP_DTLS_RECORD_HEADER_SIZE + 4U] << 8
                        | its_record[VSOMEIP_DTLS_RECORD_HEADER_SIZE + 5U];
                if (its_seq > sent_message_seq_) {
                    return false;
                }
            } else {
                return false;
            }
            its_any = true;
            its_offset += VSOMEIP_DTLS_RECORD_HEADER_SIZE + its_length;
        }
    }
    return its_any;
}

void dtls_session::note_sent_locked(const std::vector<datagram_t>& _outgoing) {
    for (const auto& its_datagram : _outgoing) {
        std::size_t its_offset = 0;
        while (its_offset + VSOMEIP_DTLS_RECORD_HEADER_SIZE <= its_datagram.size()) {
            const std::uint8_t* its_record = its_datagram.data() + its_offset;
            const std::size_t its_length = static_cast<std::size_t>(its_record[11] << 8 | its_record[12]);
            const unsigned its_epoch = static_cast<unsigned>(its_record[3] << 8 | its_record[4]);
            if (its_record[0] == RECORD_CHANGE_CIPHER_SPEC) {
                sent_change_cipher_spec_ = true;
            } else if (its_record[0] == RECORD_HANDSHAKE && its_epoch == 0U && its_length >= 6U) {
                const int its_seq = its_record[VSOMEIP_DTLS_RECORD_HEADER_SIZE + 4U] << 8
                        | its_record[VSOMEIP_DTLS_RECORD_HEADER_SIZE + 5U];
                sent_message_seq_ = std::max(sent_message_seq_, its_seq);
            }
            its_offset += VSOMEIP_DTLS_RECORD_HEADER_SIZE + its_length;
        }
    }
}

bool dtls_session::write(const std::uint8_t* _data, std::size_t _size, send_completion_t _completion) {
    if (!_data || _size == 0U) {
        return false;
    }
    std::vector<datagram_t> outgoing;
    bool result = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_ready_ || is_failed_) {
            return false;
        }
        result = write_locked(_data, _size, outgoing);
    }
    flush(std::move(outgoing), {}, std::move(_completion));
    return result;
}

bool dtls_session::seal(const std::uint8_t* _data, std::size_t _size, std::vector<datagram_t>& _records) {
    if (!_data || _size == 0U) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_ready_ || is_failed_) {
        return false;
    }
    return write_locked(_data, _size, _records);
}

bool dtls_session::write_locked(const std::uint8_t* _data, std::size_t _size, std::vector<datagram_t>& _records) {
    // One SOME/IP message is one record in one datagram. wolfSSL refuses a
    // message whose record would exceed DATA_MTU (DTLS_SIZE_ERROR) instead
    // of splitting it; that drops this message only, the session stays.
    // (wolfSSL_GetMaxOutputSize() assumes worst-case CBC padding and would
    // refuse messages that do fit, so the exact check is left to the write.)
    const std::int64_t its_start = stats_enabled() ? now_ns() : 0;
    const std::int64_t its_cpu_start = its_start != 0 ? thread_cpu_ns() : 0;
    const int its_written = wolfSSL_write(ssl_, _data, static_cast<int>(_size));
    const bool result = its_written == static_cast<int>(_size);
    if (result && its_start != 0) {
        g_stats.send_ns_ += static_cast<std::uint64_t>(now_ns() - its_start);
        g_stats.send_cpu_ns_ += static_cast<std::uint64_t>(thread_cpu_ns() - its_cpu_start);
        ++g_stats.sent_;
    }
    if (!result) {
        const int error = wolfSSL_get_error(ssl_, its_written);
        if (error == DTLS_SIZE_ERROR) {
            static std::atomic<std::int64_t> its_last_s{0};
            const auto its_now_s = std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::steady_clock::now().time_since_epoch())
                                           .count();
            if (its_last_s.exchange(its_now_s) != its_now_s) {
                // The endpoints already segment such messages for methods with
                // SOME/IP-TP, so this one belongs to a method without it.
                const char* its_cipher = wolfSSL_get_cipher_name(ssl_);
                VSOMEIP_ERROR << "DTLS: dropped a message of " << _size << " bytes: one " << DATA_MTU
                              << "-byte datagram with " << its_cipher << " carries at most "
                              << dtls::max_record_payload(its_cipher ? its_cipher : "")
                              << "; enable SOME/IP-TP for this method or keep its messages smaller";
            }
        } else if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
            is_failed_ = true;
            VSOMEIP_ERROR << "DTLS: write failed: " << error_text(error);
        }
    }
    while (!outgoing_.empty()) {
        _records.emplace_back(std::move(outgoing_.front()));
        outgoing_.pop_front();
    }
    arm_retransmit_locked();
    return result;
}

bool dtls_session::is_ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_ready_;
}

bool dtls_session::is_failed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_failed_;
}

void dtls_session::drive_locked(std::vector<datagram_t>& _outgoing, std::vector<datagram_t>& _plaintext) {
    if (!is_ready_) {
        const int handshake_result = is_client_ ? wolfSSL_connect(ssl_) : wolfSSL_accept(ssl_);
        if (handshake_result == WOLFSSL_SUCCESS) {
            is_ready_ = true;
            // Handshake flights were split at 1200; application records may
            // now use the full datagram so one message stays one record.
            wolfSSL_dtls_set_mtu(ssl_, DATA_MTU);
            if (auth_ == dtls_auth_e::CERTIFICATE) {
                VSOMEIP_INFO << "DTLS: certificate handshake completed in " << handshake_ms() << " ms, peer " << peer_name_
                             << ", cipher " << wolfSSL_get_cipher_name(ssl_) << " (wolfSSL)";
            } else {
                VSOMEIP_INFO << "DTLS: PSK handshake completed in " << handshake_ms() << " ms, cipher "
                             << wolfSSL_get_cipher_name(ssl_) << " (wolfSSL)";
            }
        } else {
            const int error = wolfSSL_get_error(ssl_, handshake_result);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                log_handshake_failure(error);
            }
        }
    }

    if (is_ready_ && !is_failed_) {
        if (read_buffer_.size() < MAX_RECORD_PLAINTEXT) {
            read_buffer_.resize(MAX_RECORD_PLAINTEXT);
        }
        for (;;) {
            const int received = wolfSSL_read(ssl_, read_buffer_.data(), static_cast<int>(read_buffer_.size()));
            if (received > 0) {
                _plaintext.emplace_back(read_buffer_.begin(), read_buffer_.begin() + received);
                continue;
            }
            const int error = wolfSSL_get_error(ssl_, received);
            if (error == WOLFSSL_ERROR_ZERO_RETURN) {
                is_failed_ = true;
            } else if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                VSOMEIP_WARNING << "DTLS: record authentication/decryption failed: " << error_text(error);
            }
            break;
        }
    }

    while (!outgoing_.empty()) {
        _outgoing.emplace_back(std::move(outgoing_.front()));
        outgoing_.pop_front();
    }
    arm_retransmit_locked();
}

void dtls_session::flush(std::vector<datagram_t>&& _outgoing, std::vector<datagram_t>&& _plaintext, send_completion_t _completion) {
    if (_completion && _outgoing.empty()) {
        _completion(false);
    }
    auto pending = std::make_shared<std::atomic_size_t>(_completion ? _outgoing.size() : 0U);
    auto all_sent = std::make_shared<std::atomic_bool>(true);
    auto completion = std::make_shared<send_completion_t>(std::move(_completion));
    for (auto& datagram : _outgoing) {
        send_completion_t sent;
        if (*completion) {
            sent = [pending, all_sent, completion](bool ok) {
                if (!ok) {
                    all_sent->store(false);
                }
                if (pending->fetch_sub(1U) == 1U && *completion) {
                    (*completion)(all_sent->load());
                }
            };
        }
        send_(std::move(datagram), std::move(sent));
    }
    for (auto& message : _plaintext) {
        receive_(std::move(message));
    }
}

void dtls_session::arm_retransmit_locked() {
    // Only an unfinished handshake needs our timer. After it, wolfSSL resends
    // its last flight by itself when the peer repeats its own.
    if (!ssl_ || is_ready_ || is_failed_) {
        boost::system::error_code ignored;
        retransmit_timer_.cancel(ignored);
        return;
    }
    int its_seconds = wolfSSL_dtls_get_current_timeout(ssl_);
    if (its_seconds <= 0) {
        its_seconds = 1;
    }
    retransmit_timer_.expires_after(std::chrono::seconds(its_seconds));
    std::weak_ptr<dtls_session> weak_self = shared_from_this();
    retransmit_timer_.async_wait([weak_self](const boost::system::error_code& error) {
        if (auto self = weak_self.lock()) {
            self->on_retransmit(error);
        }
    });
}

void dtls_session::on_retransmit(const boost::system::error_code& _error) {
    if (_error == boost::asio::error::operation_aborted) {
        return;
    }
    std::vector<datagram_t> outgoing;
    std::vector<datagram_t> plaintext;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (is_failed_ || !ssl_ || is_ready_) {
            return;
        }
        // Resends the last flight and doubles the timeout; fails once wolfSSL
        // has given up on the peer.
        const int its_timeout = wolfSSL_dtls_got_timeout(ssl_);
        if (its_timeout != WOLFSSL_SUCCESS) {
            const int error = wolfSSL_get_error(ssl_, its_timeout);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                VSOMEIP_WARNING << "DTLS: retransmit timer failed: " << error_text(error);
            }
        }
        if (!is_ready_ && !stall_reported_
            && std::chrono::steady_clock::now() - started_ > std::chrono::seconds(VSOMEIP_DTLS_STALL_WARNING_S)) {
            stall_reported_ = true;
            VSOMEIP_WARNING << "DTLS: handshake not completed after " << VSOMEIP_DTLS_STALL_WARNING_S
                            << " s; the peer most likely uses a different key or identity"
                            << " (records under a wrong key are dropped without an error)";
        }
        drive_locked(outgoing, plaintext);
        note_sent_locked(outgoing);
    }
    flush(std::move(outgoing), std::move(plaintext));
}

unsigned int dtls_session::client_psk(WOLFSSL* _ssl, const char*, char* _identity, unsigned int _identity_max,
                                      unsigned char* _psk, unsigned int _psk_max) {
    auto* session = session_of(_ssl);
    if (!session || session->identity_.size() + 1U > _identity_max || session->psk_.size() > _psk_max) {
        return 0U;
    }
    std::copy(session->identity_.begin(), session->identity_.end(), _identity);
    _identity[session->identity_.size()] = '\0';
    std::copy(session->psk_.begin(), session->psk_.end(), _psk);
    return static_cast<unsigned int>(session->psk_.size());
}

unsigned int dtls_session::server_psk(WOLFSSL* _ssl, const char* _identity, unsigned char* _psk, unsigned int _psk_max) {
    auto* session = session_of(_ssl);
    if (!session || !_identity || !session->resolver_) {
        return 0U;
    }
    // The identity arrives from the network, so bound it before it is used as a
    // lookup key, and never log it back verbatim.
    const std::string its_identity(_identity, ::strnlen(_identity, 128U));
    if (its_identity.empty() || its_identity.size() >= 128U) {
        return 0U;
    }

    std::string its_hex = session->resolver_(its_identity);
    if (its_hex.empty()) {
        VSOMEIP_WARNING << "DTLS: no key configured for the identity a peer presented";
        return 0U;
    }
    std::vector<unsigned char> its_key;
    const bool its_decoded = decode_hex_key(its_hex, its_key);
    std::fill(its_hex.begin(), its_hex.end(), '\0');
    if (!its_decoded || its_key.size() > _psk_max) {
        std::fill(its_key.begin(), its_key.end(), 0U);
        return 0U;
    }
    session->identity_ = its_identity;
    session->psk_ = its_key;
    std::copy(its_key.begin(), its_key.end(), _psk);
    const auto its_size = static_cast<unsigned int>(its_key.size());
    std::fill(its_key.begin(), its_key.end(), 0U);
    return its_size;
}

int dtls_session::io_recv(WOLFSSL*, char* _buffer, int _size, void* _context) {
    auto* session = static_cast<dtls_session*>(_context);
    if (!session || _size <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (session->incoming_.empty()) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    datagram_t its_datagram = std::move(session->incoming_.front());
    session->incoming_.pop_front();
    if (its_datagram.size() > static_cast<std::size_t>(_size)) {
        // A DTLS record is never split across reads; a truncated one would only
        // fail authentication. Drop it whole (wolfSSL reads MTU + 500 bytes).
        VSOMEIP_WARNING << "DTLS: dropped a " << its_datagram.size() << " byte datagram larger than the read buffer";
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    std::memcpy(_buffer, its_datagram.data(), its_datagram.size());
    return static_cast<int>(its_datagram.size());
}

int dtls_session::io_send(WOLFSSL*, char* _buffer, int _size, void* _context) {
    auto* session = static_cast<dtls_session*>(_context);
    if (!session || _size <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(_buffer);
    session->outgoing_.emplace_back(begin, begin + static_cast<std::size_t>(_size));
    return _size;
}

} // namespace vsomeip_v3
