// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DTLS_RECORD_LIMIT_HPP_
#define VSOMEIP_V3_DTLS_RECORD_LIMIT_HPP_

#include <cstddef>
#include <string>

namespace vsomeip_v3 {
namespace dtls {

// One SOME/IP datagram becomes one DTLS record in one UDP datagram, and that
// datagram must not need IP fragmentation: Ethernet MTU 1500 - IPv4 20 - UDP 8.
constexpr std::size_t DATAGRAM_SIZE = 1472U;

// Largest plaintext one DTLS 1.2 record of cipher suite _suite (OpenSSL or IANA
// name) can carry in a datagram of _datagram bytes. Block-cipher suites take the
// smaller of MAC-then-encrypt and encrypt-then-MAC, so the result holds whichever
// the peers negotiate. A name that cannot be classified gets the smallest value
// of any supported suite (CBC with SHA-384).
std::size_t max_record_payload(const std::string& _suite, std::size_t _datagram = DATAGRAM_SIZE);

// The smallest max_record_payload() over a ':'-separated cipher list, so the
// limit holds for any suite the handshake may pick. Operators such as "!aNULL"
// or "@STRENGTH" are ignored.
std::size_t max_message_size(const std::string& _cipher_list, std::size_t _datagram = DATAGRAM_SIZE);

} // namespace dtls
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DTLS_RECORD_LIMIT_HPP_
