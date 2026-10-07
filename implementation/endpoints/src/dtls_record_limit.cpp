// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/dtls_record_limit.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace vsomeip_v3 {
namespace dtls {

namespace {

constexpr std::size_t RECORD_HEADER = 13U; // DTLS 1.2: type, version, epoch, sequence, length
constexpr std::size_t AEAD_NONCE = 8U;     // explicit nonce of AES-GCM / AES-CCM
constexpr std::size_t AEAD_TAG = 16U;
constexpr std::size_t CCM8_TAG = 8U;

bool contains(const std::string& _name, const char* _part) {
    return _name.find(_part) != std::string::npos;
}

bool ends_with(const std::string& _name, const std::string& _suffix) {
    return _name.size() >= _suffix.size() && _name.compare(_name.size() - _suffix.size(), _suffix.size(), _suffix) == 0;
}

std::size_t floor_to(std::size_t _value, std::size_t _block) {
    return _value - _value % _block;
}

// Block cipher with explicit IV: the larger of the two layouts wins, so take
// the smaller plaintext.
//   MAC-then-encrypt: IV + pad(plaintext + MAC + 1)
//   encrypt-then-MAC: IV + pad(plaintext + 1) + MAC        (RFC 7366)
std::size_t block_payload(std::size_t _datagram, std::size_t _block, std::size_t _mac) {
    const std::size_t its_space = _datagram - RECORD_HEADER - _block;
    const std::size_t its_mte = floor_to(its_space, _block) - _mac - 1U;
    const std::size_t its_etm = floor_to(its_space - _mac, _block) - 1U;
    return std::min(its_mte, its_etm);
}

std::size_t mac_size(const std::string& _name) {
    if (ends_with(_name, "SHA384")) {
        return 48U;
    }
    if (ends_with(_name, "SHA256")) {
        return 32U;
    }
    if (ends_with(_name, "SHA")) {
        return 20U;
    }
    if (ends_with(_name, "MD5")) {
        return 16U;
    }
    return 0U;
}

} // namespace

std::size_t max_record_payload(const std::string& _suite, std::size_t _datagram) {
    std::string its_name(_suite);
    std::transform(its_name.begin(), its_name.end(), its_name.begin(), [](unsigned char c) {
        return static_cast<char>(c == '_' ? '-' : std::toupper(c));
    });

    if (contains(its_name, "CHACHA20") || contains(its_name, "POLY1305")) {
        return _datagram - RECORD_HEADER - AEAD_TAG; // RFC 7905: implicit nonce
    }
    if (contains(its_name, "GCM")) {
        return _datagram - RECORD_HEADER - AEAD_NONCE - AEAD_TAG;
    }
    if (contains(its_name, "CCM8") || contains(its_name, "CCM-8")) {
        return _datagram - RECORD_HEADER - AEAD_NONCE - CCM8_TAG;
    }
    if (contains(its_name, "CCM")) {
        return _datagram - RECORD_HEADER - AEAD_NONCE - AEAD_TAG;
    }

    const std::size_t its_mac = mac_size(its_name);
    if (its_mac == 0U) {
        // Not a suite name ("DEFAULT", "HIGH", ...): assume the worst supported one.
        return block_payload(_datagram, 16U, 48U);
    }
    if (contains(its_name, "NULL")) {
        return _datagram - RECORD_HEADER - its_mac; // integrity only
    }
    const std::size_t its_block = contains(its_name, "DES") ? 8U : 16U;
    return block_payload(_datagram, its_block, its_mac);
}

std::size_t max_message_size(const std::string& _cipher_list, std::size_t _datagram) {
    std::size_t its_min = 0U;
    std::stringstream its_list(_cipher_list);
    std::string its_suite;
    while (std::getline(its_list, its_suite, ':')) {
        its_suite.erase(std::remove_if(its_suite.begin(), its_suite.end(), [](unsigned char c) { return std::isspace(c); }),
                        its_suite.end());
        if (its_suite.empty() || its_suite[0] == '!' || its_suite[0] == '-' || its_suite[0] == '+' || its_suite[0] == '@') {
            continue;
        }
        const std::size_t its_payload = max_record_payload(its_suite, _datagram);
        its_min = its_min == 0U ? its_payload : std::min(its_min, its_payload);
    }
    return its_min == 0U ? max_record_payload("", _datagram) : its_min;
}

} // namespace dtls
} // namespace vsomeip_v3
