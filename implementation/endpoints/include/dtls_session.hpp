// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DTLS_SESSION_HPP_
#define VSOMEIP_V3_DTLS_SESSION_HPP_

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;

namespace vsomeip_v3 {

// One DTLS association for one UDP peer. The endpoints own datagram routing;
// this class owns the OpenSSL handshake, record protection and retransmit timer.
class dtls_session : public std::enable_shared_from_this<dtls_session> {
public:
    using datagram_t = std::vector<std::uint8_t>;
    using send_completion_t = std::function<void(bool)>;
    using send_handler_t = std::function<void(datagram_t, send_completion_t)>;
    using plaintext_handler_t = std::function<void(datagram_t)>;

    static std::shared_ptr<dtls_session> create(boost::asio::io_context& _io, bool _is_client, std::string _identity, std::string _psk_hex,
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
    dtls_session(boost::asio::io_context& _io, bool _is_client, std::string _identity, std::string _psk_hex, send_handler_t _send,
                 plaintext_handler_t _receive);

    bool initialize();
    void drive_locked(std::vector<datagram_t>& _outgoing, std::vector<datagram_t>& _plaintext);
    void flush(std::vector<datagram_t>&& _outgoing, std::vector<datagram_t>&& _plaintext, send_completion_t _completion = {});
    void arm_retransmit_locked();
    void on_retransmit(const boost::system::error_code& _error);
    static unsigned int client_psk(SSL* _ssl, const char* _hint, char* _identity, unsigned int _identity_max, unsigned char* _psk,
                                   unsigned int _psk_max);
    static unsigned int server_psk(SSL* _ssl, const char* _identity, unsigned char* _psk, unsigned int _psk_max);

    static int bio_create(BIO* _bio);
    static int bio_destroy(BIO* _bio);
    static int bio_read(BIO* _bio, char* _output, int _output_size);
    static int bio_write(BIO* _bio, const char* _input, int _input_size);
    static long bio_ctrl(BIO* _bio, int _command, long _number, void* _pointer);
    static BIO* make_bio_method();

    mutable std::mutex mutex_;
    boost::asio::steady_timer retransmit_timer_;
    bool is_client_;
    bool is_ready_{false};
    bool is_failed_{false};
    std::string identity_;
    std::vector<unsigned char> psk_;
    send_handler_t send_;
    plaintext_handler_t receive_;
    std::deque<datagram_t> incoming_;
    std::deque<datagram_t> outgoing_;
    SSL_CTX* context_{nullptr};
    SSL* ssl_{nullptr};
    BIO* bio_{nullptr};
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DTLS_SESSION_HPP_
