// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/tls_stream.hpp"

#include <vsomeip/internal/logger.hpp>

#include "../../configuration/include/configuration.hpp"

namespace vsomeip_v3 {
namespace tls {

bool make_credentials(const std::shared_ptr<configuration>& _configuration, const std::string& _address, bool _is_client,
                      dtls_session::credentials& _credentials) {
    _credentials = dtls_session::credentials{};
    _credentials.stream_ = true;
    _credentials.tls_version_ = _configuration->get_tls_version();
    _credentials.cipher_ = _configuration->get_tls_cipher();
    if (_credentials.cipher_.empty() && _credentials.tls_version_ != "1.3") {
        _credentials.cipher_ = _configuration->get_dtls_cipher();
    }
    _credentials.accelerator_ = _configuration->get_dtls_accelerator();
    if (_configuration->is_dtls_certificate_mode()) {
        _credentials.auth_ = dtls_auth_e::CERTIFICATE;
        _credentials.certificate_ = _configuration->get_dtls_certificate();
        _credentials.private_key_ = _configuration->get_dtls_private_key();
        _credentials.ca_ = _configuration->get_dtls_ca();
        if (_configuration->get_dtls_time_floor() > 0) {
            _credentials.time_floor_ = _configuration->get_dtls_time_floor();
        }
        // The peer is known by its address before any certificate is seen, so the
        // name it must prove is fixed up front; an unknown address is refused.
        _credentials.peer_name_ = _configuration->get_dtls_peer_name(_address);
        _credentials.peer_address_ = _address;
        return true;
    }
    if (_is_client) {
        if (!_configuration->get_dtls_peer_credentials(_address, _credentials.identity_, _credentials.psk_hex_)) {
            VSOMEIP_ERROR << "TLS: no key configured for peer " << _address;
            return false;
        }
        return true;
    }
    auto its_weak_configuration = std::weak_ptr<configuration>(_configuration);
    _credentials.resolver_ = [its_weak_configuration](const std::string& _identity) {
        auto its_configuration = its_weak_configuration.lock();
        return its_configuration ? its_configuration->get_dtls_psk_for_identity(_identity) : std::string{};
    };
    return true;
}

void writer::push(std::vector<std::uint8_t>&& _data, done_t _done) {
    auto its_buffer = std::make_shared<std::vector<std::uint8_t>>(std::move(_data));
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        queue_.emplace_back(its_buffer, std::move(_done));
        if (busy_) {
            return;
        }
        busy_ = true;
    }
    start(its_buffer);
}

void writer::start(const buffer_t& _buffer) {
    auto its_self = shared_from_this();
    write_(_buffer, [its_self](const boost::system::error_code& _error) { its_self->on_written(_error); });
}

void writer::on_written(const boost::system::error_code& _error) {
    done_t its_done;
    buffer_t its_next;
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        if (!queue_.empty()) {
            its_done = std::move(queue_.front().second);
            queue_.pop_front();
        }
        if (queue_.empty()) {
            busy_ = false;
        } else {
            its_next = queue_.front().first;
        }
    }
    if (its_done) {
        its_done(_error);
    }
    if (its_next) {
        start(its_next);
    }
}

} // namespace tls
} // namespace vsomeip_v3
