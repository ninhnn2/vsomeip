// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/dtls_session.hpp"

#include <algorithm>
#include <iterator>
#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <limits>
#include <mutex>

#include <boost/asio/error.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {
namespace {

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

// The first OpenSSL error on the queue as text; empties the queue.
std::string ssl_error_text() {
    char its_text[256] = {0};
    const unsigned long its_error = ERR_get_error();
    if (its_error) {
        ERR_error_string_n(its_error, its_text, sizeof(its_text));
    }
    ERR_clear_error();
    return its_text;
}

// Loads the private key through OSSL_STORE, so the same configuration value
// can name a PEM file today and an HSM object ("pkcs11:...") once a PKCS#11
// provider is installed. The key never has to leave the store in the latter case.
EVP_PKEY* load_private_key(const std::string& _location) {
    OSSL_STORE_CTX* its_store = OSSL_STORE_open(_location.c_str(), nullptr, nullptr, nullptr, nullptr);
    if (!its_store) {
        return nullptr;
    }
    EVP_PKEY* its_key = nullptr;
    while (!its_key && !OSSL_STORE_eof(its_store)) {
        OSSL_STORE_INFO* its_info = OSSL_STORE_load(its_store);
        if (!its_info) {
            continue;
        }
        if (OSSL_STORE_INFO_get_type(its_info) == OSSL_STORE_INFO_PKEY) {
            its_key = OSSL_STORE_INFO_get1_PKEY(its_info);
        }
        OSSL_STORE_INFO_free(its_info);
    }
    OSSL_STORE_close(its_store);
    return its_key;
}

// Process-wide secret for the stateless DTLS cookie (RFC 6347 4.2.1). A fresh
// secret per process means cookies do not survive a restart, which is fine:
// the client simply gets a new HelloVerifyRequest.
const std::vector<unsigned char>& cookie_secret() {
    static const std::vector<unsigned char> its_secret = [] {
        std::vector<unsigned char> its_bytes(32U);
        if (RAND_bytes(its_bytes.data(), static_cast<int>(its_bytes.size())) != 1) {
            its_bytes.clear();
        }
        return its_bytes;
    }();
    return its_secret;
}

bool cookie_for(const std::string& _peer, unsigned char* _out, std::size_t _out_max, std::size_t& _length) {
    const auto& its_secret = cookie_secret();
    if (its_secret.empty() || _peer.empty()) {
        return false;
    }
    return EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, its_secret.data(), its_secret.size(),
                     reinterpret_cast<const unsigned char*>(_peer.data()), _peer.size(), _out, _out_max, &_length)
            != nullptr;
}

} // namespace

std::shared_ptr<dtls_session> dtls_session::create(boost::asio::io_context& _io, bool _is_client, credentials _credentials,
                                                   send_handler_t _send, plaintext_handler_t _receive) {
    if (_credentials.stream_) {
        // TLS over TCP is implemented for the wolfSSL backend only.
        VSOMEIP_ERROR << "TLS: reliable (TCP) endpoints need vsomeip built with VSOMEIP_DTLS_BACKEND=wolfssl";
        return {};
    }
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
        SSL_free(ssl_); // also frees the BIO
        ssl_ = nullptr;
        bio_ = nullptr;
    }
    if (context_) {
        SSL_CTX_free(context_);
    }
    std::fill(psk_.begin(), psk_.end(), 0U);
}

BIO* dtls_session::make_bio_method() {
    static BIO_METHOD* method = [] {
        BIO_METHOD* result = BIO_meth_new(BIO_TYPE_DGRAM, "vsomeip DTLS datagram BIO");
        if (result) {
            BIO_meth_set_create(result, &dtls_session::bio_create);
            BIO_meth_set_destroy(result, &dtls_session::bio_destroy);
            BIO_meth_set_read(result, &dtls_session::bio_read);
            BIO_meth_set_write(result, &dtls_session::bio_write);
            BIO_meth_set_ctrl(result, &dtls_session::bio_ctrl);
        }
        return result;
    }();
    return method ? BIO_new(method) : nullptr;
}

bool dtls_session::initialize() {
    if (is_failed_ || !send_ || !receive_) {
        VSOMEIP_ERROR << "DTLS: invalid PSK configuration (identity or key)";
        is_failed_ = true;
        return false;
    }
    if (!accelerator_.empty()) {
        static std::once_flag its_reported;
        std::call_once(its_reported, [this]() {
            VSOMEIP_WARNING << "DTLS: accelerator \"" << accelerator_ << "\" is supported by the wolfSSL backend only;"
                            << " the OpenSSL backend runs AES on the CPU (or through its devcrypto engine)";
        });
    }
    context_ = SSL_CTX_new(DTLS_method());
    if (!context_) {
        VSOMEIP_ERROR << "DTLS: failed to create OpenSSL context";
        is_failed_ = true;
        return false;
    }

    SSL_CTX_set_min_proto_version(context_, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(context_, DTLS1_2_VERSION);
    SSL_CTX_set_read_ahead(context_, 1);
    SSL_CTX_set_options(context_, SSL_OP_NO_QUERY_MTU);
    if (SSL_CTX_set_cipher_list(context_, cipher_.c_str()) != 1) {
        VSOMEIP_ERROR << "DTLS: cipher \"" << cipher_ << "\" is unavailable in this OpenSSL build";
        is_failed_ = true;
        return false;
    }
    const bool its_mode_ok = auth_ == dtls_auth_e::CERTIFICATE ? initialize_certificate() : initialize_psk();
    if (!its_mode_ok) {
        is_failed_ = true;
        return false;
    }

    ssl_ = SSL_new(context_);
    bio_ = make_bio_method();
    if (!ssl_ || !bio_) {
        VSOMEIP_ERROR << "DTLS: failed to allocate OpenSSL session";
        is_failed_ = true;
        return false;
    }
    BIO_set_data(bio_, this);
    BIO_set_init(bio_, 1);
    SSL_set_bio(ssl_, bio_, bio_);
    SSL_set_app_data(ssl_, this);
    SSL_set_mtu(ssl_, 1200U);
    if (auth_ == dtls_auth_e::CERTIFICATE) {
        // The chain alone only proves "some ECU of this CA". Pinning the expected
        // SAN name per peer address is what stops one ECU impersonating another.
        X509_VERIFY_PARAM* its_param = SSL_get0_param(ssl_);
        X509_VERIFY_PARAM_set_hostflags(its_param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (X509_VERIFY_PARAM_set1_host(its_param, peer_name_.c_str(), peer_name_.size()) != 1) {
            VSOMEIP_ERROR << "DTLS: cannot pin the expected peer name";
            is_failed_ = true;
            return false;
        }
    }
    if (is_client_) {
        SSL_set_connect_state(ssl_);
    } else {
        SSL_set_accept_state(ssl_);
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
        SSL_CTX_set_psk_client_callback(context_, &dtls_session::client_psk);
    } else {
        SSL_CTX_set_psk_server_callback(context_, &dtls_session::server_psk);
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
    if (SSL_CTX_use_certificate_chain_file(context_, certificate_.c_str()) != 1) {
        VSOMEIP_ERROR << "DTLS: cannot load certificate chain " << certificate_ << ": " << ssl_error_text();
        return false;
    }
    EVP_PKEY* its_key = load_private_key(private_key_);
    if (!its_key) {
        VSOMEIP_ERROR << "DTLS: cannot load private key " << private_key_ << ": " << ssl_error_text();
        return false;
    }
    const bool its_key_loaded = SSL_CTX_use_PrivateKey(context_, its_key) == 1;
    EVP_PKEY_free(its_key);
    if (!its_key_loaded || SSL_CTX_check_private_key(context_) != 1) {
        VSOMEIP_ERROR << "DTLS: private key does not match certificate " << certificate_ << ": " << ssl_error_text();
        return false;
    }
    if (SSL_CTX_load_verify_locations(context_, ca_.c_str(), nullptr) != 1) {
        VSOMEIP_ERROR << "DTLS: cannot load CA " << ca_ << ": " << ssl_error_text();
        return false;
    }
    // Untrusted clock: OpenSSL would compare against 1970 and call every
    // certificate "not yet valid". Switch its own time check off and enforce
    // expiry against the floor in verify_certificate() instead.
    clock_untrusted_ = static_cast<std::int64_t>(std::time(nullptr)) < time_floor_;
    if (clock_untrusted_) {
        X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(context_), X509_V_FLAG_NO_CHECK_TIME);
        static std::once_flag its_reported;
        const auto its_floor = time_floor_;
        std::call_once(its_reported, [its_floor]() {
            VSOMEIP_WARNING << "DTLS: system clock is before the time floor (" << its_floor
                            << "); certificate expiry is checked against the floor, not-before is not checked";
        });
    }
    // Mutual authentication: a server that does not insist on a client
    // certificate authenticates only itself.
    SSL_CTX_set_verify(context_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &dtls_session::verify_certificate);
    SSL_CTX_set1_groups_list(context_, "X25519:P-256");

    if (!is_client_) {
        // A certificate flight is ~1-2 kB; answering an unverified ClientHello
        // with it would let a spoofed sender use this ECU as an amplifier.
        SSL_CTX_set_options(context_, SSL_OP_COOKIE_EXCHANGE);
        SSL_CTX_set_cookie_generate_cb(context_, &dtls_session::generate_cookie);
        SSL_CTX_set_cookie_verify_cb(context_, &dtls_session::verify_cookie);
    }
    return true;
}

void dtls_session::log_handshake_failure(int _ssl_error) {
    std::string its_reason = ssl_error_text();
    // Anyone who can send a datagram can cause this line; keep it to one per
    // second so a peer cannot flood the log, and say how many were folded in.
    static std::atomic<std::int64_t> its_last_ms{0};
    static std::atomic<std::uint32_t> its_suppressed{0};
    const auto its_now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch()).count();
    auto its_last = its_last_ms.load();
    if (its_now_ms - its_last < 1000 || !its_last_ms.compare_exchange_strong(its_last, its_now_ms)) {
        ++its_suppressed;
        return;
    }
    const auto its_folded = its_suppressed.exchange(0);
    if (auth_ == dtls_auth_e::CERTIFICATE && ssl_) {
        const long its_verify = SSL_get_verify_result(ssl_);
        if (its_verify != X509_V_OK) {
            its_reason = std::string("certificate rejected: ") + X509_verify_cert_error_string(its_verify);
        }
    }
    VSOMEIP_WARNING << "DTLS: handshake failed (ssl error " << _ssl_error << ")"
                    << (its_reason.empty() ? std::string() : ": " + its_reason)
                    << (its_folded ? " (+" + std::to_string(its_folded) + " similar in the last second)" : std::string());
}

int dtls_session::verify_certificate(int _preverify, X509_STORE_CTX* _context) {
    if (!_preverify) {
        return 0;  // chain, name or purpose already failed
    }
    auto* its_ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(_context, SSL_get_ex_data_X509_STORE_CTX_idx()));
    auto* session = its_ssl ? static_cast<dtls_session*>(SSL_get_app_data(its_ssl)) : nullptr;
    if (!session || !session->clock_untrusted_) {
        return 1;  // OpenSSL already checked validity against the real clock
    }
    X509* its_certificate = X509_STORE_CTX_get_current_cert(_context);
    time_t its_floor = static_cast<time_t>(session->time_floor_);
    if (its_certificate && X509_cmp_time(X509_get0_notAfter(its_certificate), &its_floor) < 0) {
        X509_STORE_CTX_set_error(_context, X509_V_ERR_CERT_HAS_EXPIRED);
        return 0;
    }
    return 1;
}

int dtls_session::generate_cookie(SSL* _ssl, unsigned char* _cookie, unsigned int* _length) {
    auto* session = static_cast<dtls_session*>(SSL_get_app_data(_ssl));
    std::size_t its_length = 0;
    if (!session || !cookie_for(session->peer_address_, _cookie, DTLS1_COOKIE_LENGTH, its_length)) {
        return 0;
    }
    *_length = static_cast<unsigned int>(its_length);
    return 1;
}

int dtls_session::verify_cookie(SSL* _ssl, const unsigned char* _cookie, unsigned int _length) {
    auto* session = static_cast<dtls_session*>(SSL_get_app_data(_ssl));
    unsigned char its_expected[EVP_MAX_MD_SIZE];
    std::size_t its_length = 0;
    if (!session || !cookie_for(session->peer_address_, its_expected, sizeof(its_expected), its_length)) {
        return 0;
    }
    return its_length == _length && CRYPTO_memcmp(its_expected, _cookie, its_length) == 0 ? 1 : 0;
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
        drive_locked(outgoing, plaintext);
    }
    flush(std::move(outgoing), {});
    if (_plaintext.empty()) {
        _plaintext = std::move(plaintext);
    } else {
        std::move(plaintext.begin(), plaintext.end(), std::back_inserter(_plaintext));
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
    std::size_t written = 0;
    const bool result = SSL_write_ex(ssl_, _data, _size, &written) == 1 && written == _size;
    if (!result) {
        const int error = SSL_get_error(ssl_, 0);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            is_failed_ = true;
            VSOMEIP_ERROR << "DTLS: write failed";
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
        const int handshake_result = SSL_do_handshake(ssl_);
        if (handshake_result == 1) {
            is_ready_ = true;
            if (auth_ == dtls_auth_e::CERTIFICATE) {
                VSOMEIP_INFO << "DTLS: certificate handshake completed in " << handshake_ms() << " ms, peer " << peer_name_
                             << ", cipher " << SSL_get_cipher_name(ssl_) << " (OpenSSL)";
            } else {
                VSOMEIP_INFO << "DTLS: PSK handshake completed in " << handshake_ms() << " ms, cipher " << SSL_get_cipher_name(ssl_)
                             << " (OpenSSL)";
            }
        } else {
            const int error = SSL_get_error(ssl_, handshake_result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                log_handshake_failure(error);
            }
        }
    }

    if (is_ready_ && !is_failed_) {
        for (;;) {
            datagram_t plaintext(65536U);
            std::size_t received = 0;
            const int read_result = SSL_read_ex(ssl_, plaintext.data(), plaintext.size(), &received);
            if (read_result == 1 && received > 0U) {
                plaintext.resize(received);
                _plaintext.emplace_back(std::move(plaintext));
                continue;
            }
            const int error = SSL_get_error(ssl_, read_result);
            if (error == SSL_ERROR_ZERO_RETURN) {
                is_failed_ = true;
            } else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                VSOMEIP_WARNING << "DTLS: record authentication/decryption failed";
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
    timeval timeout{};
    if (!ssl_ || DTLSv1_get_timeout(ssl_, &timeout) != 1) {
        boost::system::error_code ignored;
        retransmit_timer_.cancel(ignored);
        return;
    }
    auto duration = std::chrono::seconds(timeout.tv_sec) + std::chrono::microseconds(timeout.tv_usec);
    if (duration <= std::chrono::steady_clock::duration::zero()) {
        duration = std::chrono::milliseconds(1);
    }
    retransmit_timer_.expires_after(duration);
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
        if (is_failed_ || !ssl_) {
            return;
        }
        if (DTLSv1_handle_timeout(ssl_) < 0) {
            is_failed_ = true;
            VSOMEIP_WARNING << "DTLS: retransmit timer failed";
        }
        if (!is_ready_ && !stall_reported_
            && std::chrono::steady_clock::now() - started_ > std::chrono::seconds(VSOMEIP_DTLS_STALL_WARNING_S)) {
            stall_reported_ = true;
            VSOMEIP_WARNING << "DTLS: handshake not completed after " << VSOMEIP_DTLS_STALL_WARNING_S
                            << " s; the peer most likely uses a different key or identity"
                            << " (records under a wrong key are dropped without an error)";
        }
        drive_locked(outgoing, plaintext);
    }
    flush(std::move(outgoing), std::move(plaintext));
}

unsigned int dtls_session::client_psk(SSL* _ssl, const char*, char* _identity, unsigned int _identity_max, unsigned char* _psk,
                                      unsigned int _psk_max) {
    auto* session = static_cast<dtls_session*>(SSL_get_app_data(_ssl));
    if (!session || session->identity_.size() + 1U > _identity_max || session->psk_.size() > _psk_max) {
        return 0U;
    }
    std::copy(session->identity_.begin(), session->identity_.end(), _identity);
    _identity[session->identity_.size()] = '\0';
    std::copy(session->psk_.begin(), session->psk_.end(), _psk);
    return static_cast<unsigned int>(session->psk_.size());
}

unsigned int dtls_session::server_psk(SSL* _ssl, const char* _identity, unsigned char* _psk, unsigned int _psk_max) {
    auto* session = static_cast<dtls_session*>(SSL_get_app_data(_ssl));
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

int dtls_session::bio_create(BIO* _bio) {
    BIO_set_init(_bio, 1);
    BIO_set_data(_bio, nullptr);
    BIO_set_shutdown(_bio, 0);
    return 1;
}

int dtls_session::bio_destroy(BIO* _bio) {
    if (!_bio) {
        return 0;
    }
    BIO_set_data(_bio, nullptr);
    BIO_set_init(_bio, 0);
    return 1;
}

int dtls_session::bio_read(BIO* _bio, char* _output, int _output_size) {
    if (!_bio || !_output || _output_size <= 0) {
        return 0;
    }
    auto* session = static_cast<dtls_session*>(BIO_get_data(_bio));
    if (!session || session->incoming_.empty()) {
        BIO_set_retry_read(_bio);
        return -1;
    }
    auto& datagram = session->incoming_.front();
    const auto copy_size = std::min(datagram.size(), static_cast<std::size_t>(_output_size));
    std::copy_n(datagram.begin(), copy_size, reinterpret_cast<unsigned char*>(_output));
    session->incoming_.pop_front();
    return static_cast<int>(copy_size);
}

int dtls_session::bio_write(BIO* _bio, const char* _input, int _input_size) {
    if (!_bio || !_input || _input_size <= 0) {
        return 0;
    }
    auto* session = static_cast<dtls_session*>(BIO_get_data(_bio));
    if (!session) {
        return -1;
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(_input);
    session->outgoing_.emplace_back(begin, begin + static_cast<std::size_t>(_input_size));
    return _input_size;
}

long dtls_session::bio_ctrl(BIO* _bio, int _command, long _number, void* _pointer) {
    auto* session = static_cast<dtls_session*>(BIO_get_data(_bio));
    switch (_command) {
    case BIO_CTRL_FLUSH:
        return 1;
    case BIO_CTRL_PENDING:
        return session && !session->incoming_.empty() ? static_cast<long>(session->incoming_.front().size()) : 0;
    case BIO_CTRL_WPENDING:
        return 0;
#ifdef BIO_CTRL_DGRAM_QUERY_MTU
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return 1200;
#endif
#ifdef BIO_CTRL_DGRAM_GET_MTU
    case BIO_CTRL_DGRAM_GET_MTU:
        return 1200;
#endif
#ifdef BIO_CTRL_DGRAM_SET_MTU
    case BIO_CTRL_DGRAM_SET_MTU:
        return _number;
#endif
#ifdef BIO_CTRL_DGRAM_GET_MTU_OVERHEAD
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        return 28;
#endif
#ifdef BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        return 1;
#endif
#ifdef BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP
    case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
        return 0;
#endif
#ifdef BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP
    case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        return 0;
#endif
#ifdef BIO_CTRL_DGRAM_GET_FALLBACK_MTU
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        return 1200;
#endif
#ifdef BIO_CTRL_DGRAM_SET_CONNECTED
    case BIO_CTRL_DGRAM_SET_CONNECTED:
        return 1;
#endif
#ifdef BIO_CTRL_DGRAM_SET_PEER
    case BIO_CTRL_DGRAM_SET_PEER:
        return 1;
#endif
#ifdef BIO_CTRL_DGRAM_GET_PEER
    case BIO_CTRL_DGRAM_GET_PEER:
        if (_pointer) {
            std::memset(_pointer, 0, static_cast<std::size_t>(_number));
        }
        return 0;
#endif
    default:
        return 0;
    }
}

} // namespace vsomeip_v3
