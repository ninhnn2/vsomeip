// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/dtls_wolfssl_device.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vsomeip/internal/logger.hpp>

// options.h first: the same feature defines as the library (wolfSSL AGENTS.md).
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#if defined(WOLF_CRYPTO_CB)
#include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#if defined(HAVE_PKCS11)
#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#endif

// SA2UL through cryptodev: needs crypto callbacks with the free hook (to close
// the cryptodev session of an AES object) and the cryptodev header.
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE) && defined(HAVE_AES_CBC) && defined(__linux__) \
        && __has_include(<crypto/cryptodev.h>)
#include <crypto/cryptodev.h>
#define VSOMEIP_DTLS_HAVE_SA2UL 1
#endif
#if defined(WOLF_CRYPTO_CB) && defined(HAVE_PKCS11) && defined(WOLF_PRIVATE_KEY_ID) && defined(HAVE_ECC)
#define VSOMEIP_DTLS_HAVE_PKCS11 1
#endif

namespace vsomeip_v3 {
namespace dtls_wolfssl {
namespace {

std::atomic<std::uint64_t> g_sa2ul_operations{0};
std::atomic<std::uint64_t> g_sa2ul_nanoseconds{0};

int hex_digit(char _c) {
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
}

// RFC 3986 %XX; a malformed escape is kept as it is.
std::string percent_decode(const std::string& _in) {
    std::string out;
    for (std::size_t i = 0; i < _in.size(); ++i) {
        const int hi = (_in[i] == '%' && i + 2 < _in.size()) ? hex_digit(_in[i + 1]) : -1;
        const int lo = hi >= 0 ? hex_digit(_in[i + 2]) : -1;
        if (lo >= 0) {
            out += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else {
            out += _in[i];
        }
    }
    return out;
}

#if defined(VSOMEIP_DTLS_HAVE_SA2UL)

// ---------------------------------------------------------------- SA2UL ----
constexpr std::size_t BLOCK = 16U;
// The SA2UL driver hands requests of 64 KiB and more back to the CPU in the
// kernel; doing those in the process is cheaper than the round trip.
constexpr word32 SA2UL_MAX_REQUEST = 65535U;

// One cryptodev session per AES key, kept in Aes::devCtx until wc_AesFree.
struct aes_session {
    std::uint32_t id_{0};
    std::uint8_t key_[AES_MAX_KEY_SIZE / 8U]{};
    word32 key_size_{0};
};

class cryptodev {
public:
    static cryptodev& get() {
        static cryptodev instance;
        return instance;
    }
    bool ready() const { return fd_ >= 0; }
    const std::string& reason() const { return reason_; }
    int fd() const { return fd_; }

private:
    cryptodev() {
        fd_ = ::open("/dev/crypto", O_RDWR | O_CLOEXEC);
        if (fd_ < 0) {
            reason_ = std::string("/dev/crypto: ") + std::strerror(errno) + " (cryptodev module not loaded?)";
            return;
        }
        // Which kernel driver serves cbc(aes)? Only the SA2UL is wanted: the
        // kernel would otherwise run the CPU implementation behind a syscall.
        std::uint8_t key[16] = {0};
        session_op its_session{};
        its_session.cipher = CRYPTO_AES_CBC;
        its_session.keylen = sizeof(key);
        its_session.key = key;
        if (::ioctl(fd_, CIOCGSESSION, &its_session) != 0) {
            reason_ = std::string("cryptodev has no cbc(aes): ") + std::strerror(errno);
            close();
            return;
        }
        session_info_op its_info{};
        its_info.ses = its_session.ses;
        const bool its_known = ::ioctl(fd_, CIOCGSESSINFO, &its_info) == 0;
        ::ioctl(fd_, CIOCFSESSION, &its_session.ses);
        driver_ = its_known ? its_info.cipher_info.cra_driver_name : "unknown";
        if (driver_.find("sa2ul") == std::string::npos) {
            reason_ = "cbc(aes) in the kernel is " + driver_ + ", not the SA2UL";
            close();
            return;
        }
        VSOMEIP_INFO << "DTLS: AES-CBC records offloaded to " << driver_ << " through /dev/crypto";
    }
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int fd_{-1};
    std::string driver_;
    std::string reason_;
};

aes_session* session_for(Aes* _aes) {
    auto* its_session = static_cast<aes_session*>(_aes->devCtx);
    if (_aes->keylen <= 0) {
        return nullptr;
    }
    const auto its_size = static_cast<word32>(_aes->keylen);  // bytes: 16, 24 or 32
    if (its_size > sizeof(aes_session::key_)) {
        return nullptr;
    }
    if (its_session && its_session->key_size_ == its_size
        && std::memcmp(its_session->key_, _aes->devKey, its_size) == 0) {
        return its_session;
    }
    if (its_session) {  // rekeyed: replace
        ::ioctl(cryptodev::get().fd(), CIOCFSESSION, &its_session->id_);
        delete its_session;
        _aes->devCtx = nullptr;
    }
    auto its_new = std::make_unique<aes_session>();
    std::memcpy(its_new->key_, _aes->devKey, its_size);
    its_new->key_size_ = its_size;
    session_op its_op{};
    its_op.cipher = CRYPTO_AES_CBC;
    its_op.keylen = its_size;
    its_op.key = its_new->key_;
    if (::ioctl(cryptodev::get().fd(), CIOCGSESSION, &its_op) != 0) {
        return nullptr;
    }
    its_new->id_ = its_op.ses;
    _aes->devCtx = its_new.get();
    return its_new.release();
}

void release(Aes* _aes) {
    auto* its_session = static_cast<aes_session*>(_aes->devCtx);
    if (its_session) {
        ::ioctl(cryptodev::get().fd(), CIOCFSESSION, &its_session->id_);
        std::memset(its_session->key_, 0, sizeof(its_session->key_));
        delete its_session;
        _aes->devCtx = nullptr;
    }
}

int aes_cbc(Aes* _aes, byte* _out, const byte* _in, word32 _size, bool _encrypt) {
    if (!_aes || _size == 0U || (_size % BLOCK) != 0U || _size > SA2UL_MAX_REQUEST) {
        return CRYPTOCB_UNAVAILABLE;
    }
    aes_session* its_session = session_for(_aes);
    if (!its_session) {
        return CRYPTOCB_UNAVAILABLE;  // CPU instead
    }
    // CBC chaining is kept in Aes::reg. The next IV is the last ciphertext
    // block; take it here instead of relying on the driver to write it back.
    std::uint8_t its_iv[BLOCK];
    std::uint8_t its_next[BLOCK];
    std::memcpy(its_iv, _aes->reg, BLOCK);
    if (!_encrypt) {
        std::memcpy(its_next, _in + _size - BLOCK, BLOCK);  // before an in-place decrypt overwrites it
    }
    crypt_op its_op{};
    its_op.ses = its_session->id_;
    its_op.op = _encrypt ? COP_ENCRYPT : COP_DECRYPT;
    its_op.len = _size;
    its_op.src = const_cast<std::uint8_t*>(_in);
    its_op.dst = _out;
    its_op.iv = its_iv;
    const auto its_start = std::chrono::steady_clock::now();
    if (::ioctl(cryptodev::get().fd(), CIOCCRYPT, &its_op) != 0) {
        return WC_HW_E;
    }
    g_sa2ul_nanoseconds += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - its_start).count());
    if (_encrypt) {
        std::memcpy(its_next, _out + _size - BLOCK, BLOCK);
    }
    std::memcpy(_aes->reg, its_next, BLOCK);
    ++g_sa2ul_operations;
    return 0;
}
#endif // VSOMEIP_DTLS_HAVE_SA2UL

#if defined(VSOMEIP_DTLS_HAVE_PKCS11)
// --------------------------------------------------------------- PKCS#11 ----
struct token_entry {
    Pkcs11Dev dev_{};
    Pkcs11Token token_{};
    std::string pin_;  // wolfSSL keeps a pointer for re-login: lives as long as the token
    std::mutex mutex_; // one PKCS#11 session, used by one operation at a time
};

bool read_pin(const std::string& _file, std::string& _pin, std::string& _reason) {
    struct stat its_stat{};
    if (::stat(_file.c_str(), &its_stat) != 0 || !S_ISREG(its_stat.st_mode)) {
        _reason = "cannot read PIN file " + _file;
        return false;
    }
    if ((its_stat.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        _reason = "PIN file " + _file + " is accessible by group or others";
        return false;
    }
    std::ifstream its_input(_file);
    std::getline(its_input, _pin);
    while (!_pin.empty() && (_pin.back() == '\r' || _pin.back() == ' ')) {
        _pin.pop_back();
    }
    if (_pin.empty()) {
        _reason = "PIN file " + _file + " is empty";
        return false;
    }
    return true;
}
#endif // VSOMEIP_DTLS_HAVE_PKCS11

#if defined(WOLF_CRYPTO_CB)
struct device_context {
    bool sa2ul_{false};
#if defined(VSOMEIP_DTLS_HAVE_PKCS11)
    token_entry* token_{nullptr};
#endif
};

// Everything not handled here returns CRYPTOCB_UNAVAILABLE: wolfSSL then uses
// its own (CPU) implementation, so the device can be attached to every session.
int callback(int _id, wc_CryptoInfo* _info, void* _context) {
    auto* its_context = static_cast<device_context*>(_context);
    (void)_id;
    if (!_info || !its_context) {
        return CRYPTOCB_UNAVAILABLE;
    }
#if defined(VSOMEIP_DTLS_HAVE_SA2UL)
    if (its_context->sa2ul_) {
        if (_info->algo_type == WC_ALGO_TYPE_CIPHER && _info->cipher.type == WC_CIPHER_AES_CBC) {
            return aes_cbc(_info->cipher.aescbc.aes, _info->cipher.aescbc.out, _info->cipher.aescbc.in,
                           _info->cipher.aescbc.sz, _info->cipher.enc != 0);
        }
        if (_info->algo_type == WC_ALGO_TYPE_FREE && _info->free.algo == WC_ALGO_TYPE_CIPHER
            && _info->free.type == WC_CIPHER_AES && _info->free.obj) {
            release(static_cast<Aes*>(_info->free.obj));
            return CRYPTOCB_UNAVAILABLE;  // wolfSSL still runs its own free (zeroises the key)
        }
    }
#endif
#if defined(VSOMEIP_DTLS_HAVE_PKCS11)
    // Only signatures with the key that is in the token. Ephemeral ECDHE keys,
    // ECDH and peer signature checks stay on the CPU: the token is slow.
    if (its_context->token_ && _info->algo_type == WC_ALGO_TYPE_PK && _info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
        const ecc_key* its_key = _info->pk.eccsign.key;
        if (its_key && (its_key->labelLen > 0 || its_key->idLen > 0)) {
            std::lock_guard<std::mutex> its_lock(its_context->token_->mutex_);
            return wc_Pkcs11_CryptoDevCb(_id, _info, &its_context->token_->token_);
        }
    }
#endif
    return CRYPTOCB_UNAVAILABLE;
}
#endif // WOLF_CRYPTO_CB

} // namespace

bool parse_pkcs11_uri(const std::string& _uri, pkcs11_uri& _parsed, std::string& _reason) {
    if (_uri.rfind("pkcs11:", 0) != 0) {
        _reason = "not a pkcs11: URI";
        return false;
    }
    const std::string its_rest = _uri.substr(7);
    const auto its_query_at = its_rest.find('?');
    const std::string its_path = its_rest.substr(0, its_query_at);
    const std::string its_query = its_query_at == std::string::npos ? std::string() : its_rest.substr(its_query_at + 1);
    _parsed = pkcs11_uri{};

    auto each = [](const std::string& _text, char _separator, auto&& _visit) {
        std::size_t its_start = 0;
        while (its_start <= _text.size()) {
            const auto its_end = std::min(_text.find(_separator, its_start), _text.size());
            const std::string its_item = _text.substr(its_start, its_end - its_start);
            const auto its_equal = its_item.find('=');
            if (!its_item.empty()) {
                _visit(its_item.substr(0, its_equal),
                       its_equal == std::string::npos ? std::string() : its_item.substr(its_equal + 1));
            }
            its_start = its_end + 1;
        }
    };
    bool ok = true;
    each(its_path, ';', [&](const std::string& _name, const std::string& _value) {
        const std::string its_value = percent_decode(_value);
        if (_name == "token") {
            _parsed.token_ = its_value;
        } else if (_name == "object") {
            _parsed.object_ = its_value;
        } else if (_name == "type") {
            if (its_value != "private") {
                _reason = "pkcs11 URI type must be private";
                ok = false;
            }
        } else {
            _reason = "pkcs11 URI attribute \"" + _name + "\" is not supported (use token and object)";
            ok = false;
        }
    });
    each(its_query, '&', [&](const std::string& _name, const std::string& _value) {
        const std::string its_value = percent_decode(_value);
        if (_name == "module-path") {
            _parsed.module_ = its_value;
        } else if (_name == "pin-source") {
            _parsed.pin_file_ = its_value.rfind("file:", 0) == 0 ? its_value.substr(5) : its_value;
        } else if (_name == "pin-value") {
            _reason = "a PIN in the configuration is refused; use pin-source=file:<0600 file>";
            ok = false;
        } else {
            _reason = "pkcs11 URI query \"" + _name + "\" is not supported";
            ok = false;
        }
    });
    if (!ok) {
        return false;
    }
    if (_parsed.token_.empty() || _parsed.object_.empty() || _parsed.module_.empty() || _parsed.pin_file_.empty()) {
        _reason = "pkcs11 URI needs token, object, module-path and pin-source";
        return false;
    }
    return true;
}

bool acquire_device(const device_request& _request, device& _device, std::string& _reason) {
    _device = device{};
    _reason.clear();
#if !defined(WOLF_CRYPTO_CB)
    if (_request.key_) {
        _reason = "this wolfSSL build has no crypto callbacks (--enable-cryptocb): keys in a token are unavailable";
        return false;
    }
    if (_request.sa2ul_) {
        _reason = "this wolfSSL build has no crypto callbacks (--enable-cryptocb)";
    }
    return true;
#else
    static std::mutex its_mutex;
    static std::map<std::string, std::unique_ptr<device_context>> its_devices;
    static std::map<std::string, int> its_ids;
    static int its_next_id = 0x76730001;  // "vs" + n
    std::lock_guard<std::mutex> its_lock(its_mutex);

    bool its_sa2ul = false;
    if (_request.sa2ul_) {
#if defined(VSOMEIP_DTLS_HAVE_SA2UL)
        its_sa2ul = cryptodev::get().ready();
        if (!its_sa2ul) {
            _reason = cryptodev::get().reason();
        }
#else
        _reason = "this wolfSSL/vsomeip build has no SA2UL support (needs --enable-cryptocb "
                  "--enable-cryptocbutils=free and <crypto/cryptodev.h>)";
#endif
    }

    std::string its_token_key;
#if defined(VSOMEIP_DTLS_HAVE_PKCS11)
    static std::map<std::string, std::unique_ptr<token_entry>> its_tokens;
    token_entry* its_token = nullptr;
    if (_request.key_) {
        its_token_key = _request.key_->module_ + "|" + _request.key_->token_ + "|" + _request.key_->pin_file_;
        auto its_found = its_tokens.find(its_token_key);
        if (its_found == its_tokens.end()) {
            auto its_entry = std::make_unique<token_entry>();
            std::string its_why;
            if (!read_pin(_request.key_->pin_file_, its_entry->pin_, its_why)) {
                _reason = its_why;
                return false;
            }
            int its_rc = wc_Pkcs11_Initialize(&its_entry->dev_, _request.key_->module_.c_str(), nullptr);
            if (its_rc != 0) {
                _reason = "cannot load PKCS#11 module " + _request.key_->module_ + " (" + std::to_string(its_rc) + ")";
                return false;
            }
            its_rc = wc_Pkcs11Token_InitName(&its_entry->token_, &its_entry->dev_, _request.key_->token_.c_str(),
                                             static_cast<int>(_request.key_->token_.size()),
                                             reinterpret_cast<const unsigned char*>(its_entry->pin_.data()),
                                             static_cast<int>(its_entry->pin_.size()));
            if (its_rc == 0) {
                // One logged-in session for the life of the process: a handshake
                // then costs one signature, not a login and a key lookup.
                its_rc = wc_Pkcs11Token_Open(&its_entry->token_, 0);
            }
            if (its_rc != 0) {
                wc_Pkcs11_Finalize(&its_entry->dev_);
                _reason = "cannot open PKCS#11 token \"" + _request.key_->token_ + "\" (" + std::to_string(its_rc)
                        + "): wrong token name or PIN?";
                return false;
            }
            VSOMEIP_INFO << "DTLS: PKCS#11 token \"" << _request.key_->token_ << "\" opened ("
                         << _request.key_->module_ << ")";
            its_found = its_tokens.emplace(its_token_key, std::move(its_entry)).first;
        }
        its_token = its_found->second.get();
    }
#else
    if (_request.key_) {
        _reason = "this wolfSSL build has no PKCS#11 support (--enable-pkcs11)";
        return false;
    }
#endif

    if (!its_sa2ul && its_token_key.empty()) {
        return true;  // nothing to attach: plain CPU session
    }
    const std::string its_device_key = std::string(its_sa2ul ? "sa2ul" : "-") + "|" + its_token_key;
    auto its_id = its_ids.find(its_device_key);
    if (its_id == its_ids.end()) {
        auto its_context = std::make_unique<device_context>();
        its_context->sa2ul_ = its_sa2ul;
#if defined(VSOMEIP_DTLS_HAVE_PKCS11)
        its_context->token_ = its_token;
#endif
        const int its_new_id = its_next_id++;
        const int its_rc = wc_CryptoCb_RegisterDevice(its_new_id, &callback, its_context.get());
        if (its_rc != 0) {
            _reason = "cannot register the wolfSSL crypto device (" + std::to_string(its_rc) + ")";
            return false;
        }
        its_devices.emplace(its_device_key, std::move(its_context));
        its_id = its_ids.emplace(its_device_key, its_new_id).first;
    }
    _device.id_ = its_id->second;
    _device.sa2ul_ = its_sa2ul;
    _device.pkcs11_ = !its_token_key.empty();
    return true;
#endif
}

std::uint64_t sa2ul_operations() {
    return g_sa2ul_operations.load();
}

std::uint64_t sa2ul_nanoseconds() {
    return g_sa2ul_nanoseconds.load();
}

} // namespace dtls_wolfssl
} // namespace vsomeip_v3
