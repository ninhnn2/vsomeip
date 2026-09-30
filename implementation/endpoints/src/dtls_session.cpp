// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/dtls_session.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>

#include <boost/asio/error.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

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

} // namespace

std::shared_ptr<dtls_session> dtls_session::create(boost::asio::io_context& _io, bool _is_client, std::string _identity,
                                                   std::string _psk_hex, send_handler_t _send, plaintext_handler_t _receive) {
    auto result = std::shared_ptr<dtls_session>(
            new dtls_session(_io, _is_client, std::move(_identity), std::move(_psk_hex), std::move(_send), std::move(_receive)));
    if (!result->initialize()) {
        return {};
    }
    return result;
}

dtls_session::dtls_session(boost::asio::io_context& _io, bool _is_client, std::string _identity, std::string _psk_hex, send_handler_t _send,
                           plaintext_handler_t _receive) :
    retransmit_timer_(_io), is_client_(_is_client), identity_(std::move(_identity)), send_(std::move(_send)),
    receive_(std::move(_receive)) {
    if (!decode_hex_key(_psk_hex, psk_)) {
        is_failed_ = true;
    }
    std::fill(_psk_hex.begin(), _psk_hex.end(), '\0');
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
    if (is_failed_ || identity_.empty() || identity_.size() >= 128U || !send_ || !receive_) {
        VSOMEIP_ERROR << "DTLS: invalid PSK configuration (identity or key)";
        is_failed_ = true;
        return false;
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
    if (SSL_CTX_set_cipher_list(context_, "PSK-AES128-GCM-SHA256") != 1) {
        VSOMEIP_ERROR << "DTLS: the selected PSK cipher is unavailable";
        is_failed_ = true;
        return false;
    }
    if (is_client_) {
        SSL_CTX_set_psk_client_callback(context_, &dtls_session::client_psk);
    } else {
        SSL_CTX_set_psk_server_callback(context_, &dtls_session::server_psk);
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
    if (is_client_) {
        SSL_set_connect_state(ssl_);
    } else {
        SSL_set_accept_state(ssl_);
    }
    return true;
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
    flush(std::move(outgoing), std::move(plaintext));
}

bool dtls_session::write(const std::uint8_t* _data, std::size_t _size, send_completion_t _completion) {
    if (!_data || _size == 0U) {
        return false;
    }
    std::vector<datagram_t> outgoing;
    std::vector<datagram_t> plaintext;
    bool result = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_ready_ || is_failed_) {
            return false;
        }
        std::size_t written = 0;
        result = SSL_write_ex(ssl_, _data, _size, &written) == 1 && written == _size;
        if (!result) {
            const int error = SSL_get_error(ssl_, 0);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                VSOMEIP_ERROR << "DTLS: write failed";
            }
        }
        while (!outgoing_.empty()) {
            outgoing.emplace_back(std::move(outgoing_.front()));
            outgoing_.pop_front();
        }
        arm_retransmit_locked();
    }
    flush(std::move(outgoing), std::move(plaintext), std::move(_completion));
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
            VSOMEIP_INFO << "DTLS: PSK handshake completed";
        } else {
            const int error = SSL_get_error(ssl_, handshake_result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                is_failed_ = true;
                VSOMEIP_WARNING << "DTLS: handshake failed";
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
    if (!session || !_identity || session->identity_ != _identity || session->psk_.size() > _psk_max) {
        return 0U;
    }
    std::copy(session->psk_.begin(), session->psk_.end(), _psk);
    return static_cast<unsigned int>(session->psk_.size());
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
