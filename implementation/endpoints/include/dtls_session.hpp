// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DTLS_SESSION_HPP_
#define VSOMEIP_V3_DTLS_SESSION_HPP_

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

// Exactly one TLS library backs dtls_session, chosen at build time with the
// CMake option VSOMEIP_DTLS_BACKEND (openssl | wolfssl). Only the private
// members below differ; the public interface and the endpoints do not change.
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
typedef struct WOLFSSL WOLFSSL;
typedef struct WOLFSSL_CTX WOLFSSL_CTX;
typedef struct WOLFSSL_X509_STORE_CTX WOLFSSL_X509_STORE_CTX;
#else
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;
typedef struct x509_store_ctx_st X509_STORE_CTX;
#endif

namespace vsomeip_v3 {

// DTLS record framing constants needed by the endpoints to recognise a peer that
// starts a new handshake on an address/port that already has a session.
constexpr std::size_t VSOMEIP_DTLS_RECORD_HEADER_SIZE = 13U;
constexpr std::uint8_t VSOMEIP_DTLS_CONTENT_TYPE_HANDSHAKE = 0x16U;
constexpr std::uint8_t VSOMEIP_DTLS_HANDSHAKE_CLIENT_HELLO = 0x01U;

// Default cipher. PSK alone has no forward secrecy: whoever learns the key can
// decrypt any traffic recorded earlier. ECDHE-PSK-CHACHA20-POLY1305 adds an
// ephemeral key exchange and is the only AEAD ECDHE-PSK suite OpenSSL offers
// (RFC 8442 AES-GCM variants are not implemented there).
constexpr const char* VSOMEIP_DTLS_DEFAULT_CIPHER = "PSK-AES128-GCM-SHA256";

// A healthy handshake takes milliseconds; one still open after this long is
// reported, because a key mismatch produces no error of its own.
constexpr int VSOMEIP_DTLS_STALL_WARNING_S = 5;

// Default for certificate mode: ECDHE gives forward secrecy, ECDSA authenticates,
// and unlike ECDHE-PSK it can use AES-GCM, which ARMv8 accelerates in hardware.
constexpr const char* VSOMEIP_DTLS_DEFAULT_CERT_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256";

// ECUs often start without trusted time (no RTC, no time sync yet; such an ECU
// boots at 1970-01-01). Below this floor the clock is not trusted: certificate
// expiry is then checked against the floor instead of "now", and not-before
// cannot be checked at all. Set it to the firmware release date; it can be
// overridden with "time-floor" in the configuration. 2026-10-01T00:00:00Z.
constexpr std::int64_t VSOMEIP_DTLS_DEFAULT_TIME_FLOOR = 1790812800;

// How a peer proves who it is.
enum class dtls_auth_e : std::uint8_t {
    PSK,          // both peers hold the same symmetric key
    CERTIFICATE   // each peer holds its own private key and an X.509 chain to a common CA
};

// One DTLS association for one UDP peer. The endpoints own datagram routing;
// this class owns the TLS library handshake, record protection and retransmit timer.
class dtls_session : public std::enable_shared_from_this<dtls_session> {
public:
    using datagram_t = std::vector<std::uint8_t>;
    using send_completion_t = std::function<void(bool)>;
    using send_handler_t = std::function<void(datagram_t, send_completion_t)>;
    using plaintext_handler_t = std::function<void(datagram_t)>;
    // Server side: hands back the hex key configured for the identity a client
    // presented, or an empty string when that identity is unknown. This is what
    // makes per-peer keys possible without the session knowing the key store.
    using psk_resolver_t = std::function<std::string(const std::string&)>;

    struct credentials {
        dtls_auth_e auth_{dtls_auth_e::PSK};
        std::string cipher_;       // empty: the default of the mode

        // PSK mode
        std::string identity_;     // identity this node presents (client side)
        std::string psk_hex_;      // key for that identity (client side)
        psk_resolver_t resolver_;  // identity -> key (server side)

        // Certificate mode
        std::string certificate_;  // PEM chain of this node, leaf first
        std::string private_key_;  // PEM file, or (OpenSSL backend) an OSSL_STORE URI such as pkcs11:...
        std::string ca_;           // PEM trust anchors the peer chain must end in
        std::string peer_name_;    // DNS name the peer certificate must carry in its SAN
        std::string peer_address_; // binds the server cookie to the sender address
        std::int64_t time_floor_{VSOMEIP_DTLS_DEFAULT_TIME_FLOOR};
    };

    static std::shared_ptr<dtls_session> create(boost::asio::io_context& _io, bool _is_client, credentials _credentials,
                                                send_handler_t _send, plaintext_handler_t _receive);
    ~dtls_session();

    dtls_session(const dtls_session&) = delete;
    dtls_session& operator=(const dtls_session&) = delete;

    void start();
    void feed(const std::uint8_t* _data, std::size_t _size);
    bool write(const std::uint8_t* _data, std::size_t _size, send_completion_t _completion);
    bool is_ready() const;
    bool is_failed() const;

private:
    dtls_session(boost::asio::io_context& _io, bool _is_client, credentials _credentials, send_handler_t _send,
                 plaintext_handler_t _receive);

    bool initialize();
    bool initialize_psk();
    bool initialize_certificate();
    void log_handshake_failure(int _ssl_error);
    void drive_locked(std::vector<datagram_t>& _outgoing, std::vector<datagram_t>& _plaintext);
    void flush(std::vector<datagram_t>&& _outgoing, std::vector<datagram_t>&& _plaintext, send_completion_t _completion = {});
    void arm_retransmit_locked();
    void on_retransmit(const boost::system::error_code& _error);
    // Milliseconds since started_, formatted with microsecond resolution.
    std::string handshake_ms() const {
        const auto its_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_).count();
        char its_text[32];
        std::snprintf(its_text, sizeof(its_text), "%.3f", static_cast<double>(its_us) / 1000.0);
        return its_text;
    }
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
    static unsigned int client_psk(WOLFSSL* _ssl, const char* _hint, char* _identity, unsigned int _identity_max,
                                   unsigned char* _psk, unsigned int _psk_max);
    static unsigned int server_psk(WOLFSSL* _ssl, const char* _identity, unsigned char* _psk, unsigned int _psk_max);
    static int verify_certificate(int _preverify, WOLFSSL_X509_STORE_CTX* _context);
    // Custom transport: wolfSSL reads and writes our datagram queues, never a socket.
    static int io_recv(WOLFSSL* _ssl, char* _buffer, int _size, void* _context);
    static int io_send(WOLFSSL* _ssl, char* _buffer, int _size, void* _context);
    bool is_resend_locked(const std::vector<datagram_t>& _outgoing) const;
    void note_sent_locked(const std::vector<datagram_t>& _outgoing);
#else
    static unsigned int client_psk(SSL* _ssl, const char* _hint, char* _identity, unsigned int _identity_max, unsigned char* _psk,
                                   unsigned int _psk_max);
    static unsigned int server_psk(SSL* _ssl, const char* _identity, unsigned char* _psk, unsigned int _psk_max);
    static int generate_cookie(SSL* _ssl, unsigned char* _cookie, unsigned int* _length);
    static int verify_certificate(int _preverify, X509_STORE_CTX* _context);
    static int verify_cookie(SSL* _ssl, const unsigned char* _cookie, unsigned int _length);

    static int bio_create(BIO* _bio);
    static int bio_destroy(BIO* _bio);
    static int bio_read(BIO* _bio, char* _output, int _output_size);
    static int bio_write(BIO* _bio, const char* _input, int _input_size);
    static long bio_ctrl(BIO* _bio, int _command, long _number, void* _pointer);
    static BIO* make_bio_method();
#endif

    mutable std::mutex mutex_;
    boost::asio::steady_timer retransmit_timer_;
    bool is_client_;
    bool is_ready_{false};
    bool is_failed_{false};
    std::string identity_;
    std::vector<unsigned char> psk_;
    psk_resolver_t resolver_;
    std::string cipher_;
    dtls_auth_e auth_;
    std::string certificate_;
    std::string private_key_;
    std::string ca_;
    std::string peer_name_;
    std::string peer_address_;
    std::int64_t time_floor_;
    bool clock_untrusted_{false};
    // A record protected with a different key is dropped silently (RFC 6347
    // 4.1.2.7), so a key mismatch shows up only as a handshake that never ends.
    // Remember when it started so that can be reported once.
    std::chrono::steady_clock::time_point started_{std::chrono::steady_clock::now()};
    bool stall_reported_{false};
    send_handler_t send_;
    plaintext_handler_t receive_;
    std::deque<datagram_t> incoming_;
    std::deque<datagram_t> outgoing_;
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
    WOLFSSL_CTX* context_{nullptr};
    WOLFSSL* ssl_{nullptr};
    // wolfSSL reports a rejected certificate only as a handshake error; the
    // verify callback keeps the reason for log_handshake_failure().
    std::string verify_reason_;
    // wolfSSL resends its last flight whenever the peer resends one. Two peers
    // that cannot finish (wrong key) then answer each other at line rate. What
    // was sent already is remembered so such resends can be limited (feed()).
    int sent_message_seq_{-1};
    bool sent_change_cipher_spec_{false};
    std::chrono::steady_clock::time_point last_resend_{};
#else
    SSL_CTX* context_{nullptr};
    SSL* ssl_{nullptr};
    BIO* bio_{nullptr};
#endif
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DTLS_SESSION_HPP_
