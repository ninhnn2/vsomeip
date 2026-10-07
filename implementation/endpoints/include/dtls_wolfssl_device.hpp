// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DTLS_WOLFSSL_DEVICE_HPP_
#define VSOMEIP_V3_DTLS_WOLFSSL_DEVICE_HPP_

// wolfSSL crypto-callback device for the DTLS sessions (wolfSSL backend only).
//
// One device can serve two independent features:
//  - AES-CBC record encryption on the SA2UL engine, through /dev/crypto
//    (cryptodev). Every other algorithm stays on the CPU.
//  - ECDSA signatures with a private key that lives in a PKCS#11 token
//    (OP-TEE, TrustKernel, an HSM), so the key never enters the process.
// Devices are created once per process and shared by all sessions that ask for
// the same features; the token is opened and logged in only once.

#include <cstdint>
#include <string>

namespace vsomeip_v3 {
namespace dtls_wolfssl {

// RFC 7512 PKCS#11 URI, e.g.
//   pkcs11:token=vsomeip-dtls;object=dtls-identity;type=private
//          ?module-path=/usr/lib/libckteec.so.0&pin-source=file:/etc/dtls/token.pin
struct pkcs11_uri {
    std::string token_;
    std::string object_;
    std::string module_;
    std::string pin_file_;
};

// False with a reason when the URI is not usable; fields set on success.
bool parse_pkcs11_uri(const std::string& _uri, pkcs11_uri& _parsed, std::string& _reason);

struct device_request {
    bool sa2ul_{false};
    const pkcs11_uri* key_{nullptr};
};

struct device {
    int id_{-2};            // INVALID_DEVID: no device needed
    bool sa2ul_{false};     // AES-CBC really goes to the SA2UL
    bool pkcs11_{false};    // the private key is in a token
};

// Creates or reuses the device for this request. A PKCS#11 failure is an error
// (the key would otherwise be missing); an unavailable SA2UL is not: the
// session then runs AES on the CPU, and _reason says why.
bool acquire_device(const device_request& _request, device& _device, std::string& _reason);

// AES-CBC operations done by the SA2UL since start (for tests and logs).
std::uint64_t sa2ul_operations();
// Time spent in those operations (the CIOCCRYPT ioctl: DMA there and back).
std::uint64_t sa2ul_nanoseconds();

} // namespace dtls_wolfssl
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DTLS_WOLFSSL_DEVICE_HPP_
