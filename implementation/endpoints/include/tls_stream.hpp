// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TLS_STREAM_HPP_
#define VSOMEIP_V3_TLS_STREAM_HPP_

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/system/error_code.hpp>

#include "dtls_session.hpp"

namespace vsomeip_v3 {

// Ciphertext read size of a TLS connection: one full TLS record (16 KiB of
// plaintext plus header, MAC and padding) per read at most.
constexpr std::size_t VSOMEIP_TLS_READ_SIZE = 16384U + 2048U;

class configuration;

namespace tls {

// Credentials of a TLS connection with the peer at _address: the "dtls"
// credentials (mode, certificate, key, CA, peer names, PSKs, accelerator) with
// the "tls" version and cipher. False when the configuration cannot authenticate
// that peer; the connection must then not carry SOME/IP.
bool make_credentials(const std::shared_ptr<configuration>& _configuration, const std::string& _address, bool _is_client,
                      dtls_session::credentials& _credentials);

// Serialises the writes of one TLS connection. Records must reach the stream in
// the order they were produced, and a socket allows one async write at a time;
// handshake data (session send handler) and application data both go through here.
class writer : public std::enable_shared_from_this<writer> {
public:
    using buffer_t = std::shared_ptr<std::vector<std::uint8_t>>;
    using done_t = std::function<void(const boost::system::error_code&)>;
    // Starts one asynchronous write of the whole buffer and calls the handler once.
    using write_t = std::function<void(const buffer_t&, done_t)>;

    explicit writer(write_t _write) : write_(std::move(_write)) { }

    // _done (may be empty) is called with the result of this write.
    void push(std::vector<std::uint8_t>&& _data, done_t _done);

private:
    void start(const buffer_t& _buffer);
    void on_written(const boost::system::error_code& _error);

    write_t write_;
    std::mutex mutex_;
    std::deque<std::pair<buffer_t, done_t>> queue_;
    bool busy_{false};
};

} // namespace tls
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TLS_STREAM_HPP_
