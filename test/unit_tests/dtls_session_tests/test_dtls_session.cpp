// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// dtls_session against itself, in one process, with no sockets: a client and a
// server session exchange datagrams through two queues the test controls. The
// same tests run against whichever backend (OpenSSL or wolfSSL) the library was
// built with, so both must behave identically where it matters: what is
// accepted, what is refused, and that one message stays one datagram.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <unistd.h>

#include <boost/asio/io_context.hpp>

#include "../../../implementation/endpoints/include/dtls_record_limit.hpp"
#include "../../../implementation/endpoints/include/dtls_session.hpp"
#include "../../../implementation/endpoints/include/tp.hpp"
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
#include "../../../implementation/endpoints/include/dtls_wolfssl_device.hpp"
#endif

using namespace vsomeip_v3;
using namespace std::chrono_literals;

namespace {

using datagram_t = dtls_session::datagram_t;

const std::string KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const std::string OTHER_KEY = "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const std::string IDENTITY = "lab-peer";

const std::string CLIENT_NAME = "host.ecu.lab";
const std::string SERVER_NAME = "server.ecu.lab";
const std::string CLIENT_ADDRESS = "192.0.2.112:40000";
const std::string SERVER_ADDRESS = "192.0.2.4:31509";

constexpr std::uint8_t CONTENT_HANDSHAKE = 0x16U;
constexpr std::uint8_t CONTENT_APPLICATION_DATA = 0x17U;
constexpr std::uint8_t HANDSHAKE_SERVER_HELLO = 0x02U;
constexpr std::uint8_t HANDSHAKE_HELLO_VERIFY_REQUEST = 0x03U;

std::uint8_t handshake_type(const datagram_t& _datagram) {
    return _datagram.size() > VSOMEIP_DTLS_RECORD_HEADER_SIZE && _datagram[0] == CONTENT_HANDSHAKE
            ? _datagram[VSOMEIP_DTLS_RECORD_HEADER_SIZE]
            : 0U;
}

// OpenSSL packs several records into one datagram, wolfSSL sends one each.
bool carries_change_cipher_spec(const datagram_t& _datagram) {
    std::size_t offset = 0;
    while (offset + VSOMEIP_DTLS_RECORD_HEADER_SIZE <= _datagram.size()) {
        if (_datagram[offset] == 0x14U) {
            return true;
        }
        offset += VSOMEIP_DTLS_RECORD_HEADER_SIZE + static_cast<std::size_t>(_datagram[offset + 11U] << 8 | _datagram[offset + 12U]);
    }
    return false;
}

datagram_t message(std::size_t _size, std::uint8_t _seed) {
    datagram_t result(_size);
    for (std::size_t i = 0; i < _size; ++i) {
        result[i] = static_cast<std::uint8_t>(_seed + i * 7U);
    }
    return result;
}

// A floor after the real clock marks the clock untrusted (as on an ECU that
// boots at 1970). It must also lie after the fixed 2026 dates of the expired
// test certificate, whatever the clock of the machine running the test says.
std::int64_t untrusted_floor() {
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    return std::max(now, VSOMEIP_DTLS_DEFAULT_TIME_FLOOR) + 365LL * 86400LL;
}

bool is_wolfssl() {
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
    return true;
#else
    return false;
#endif
}

// Lab PKI from pki.sh next to this test, valid from yesterday so the tests do not
// depend on the date they run on, plus the negative certificates it makes.
class pki {
public:
    static pki& get() {
        static pki instance(std::time(nullptr) - 86400);
        return instance;
    }
    // Issued after this machine's clock: the situation of an ECU that boots
    // at 1970 and receives certificates from the real present.
    static pki& ahead_of_clock() {
        static pki instance(ahead_start());
        return instance;
    }
    static std::time_t ahead_start() {
        return static_cast<std::time_t>(std::max(static_cast<std::int64_t>(std::time(nullptr)), VSOMEIP_DTLS_DEFAULT_TIME_FLOOR))
                + 30 * 86400;
    }
    bool ok() const { return ok_; }
    std::string path(const std::string& _relative) const { return dir_ + "/" + _relative; }
    std::string node(const std::string& _name, const std::string& _file) const { return path("ecu/" + _name + "/" + _file); }
    std::string bad(const std::string& _kind, const std::string& _file) const {
        return path("negative/" + CLIENT_NAME + "/" + _kind + "/" + _file);
    }

private:
    explicit pki(std::time_t _start) {
        const char* tmp = getenv("TMPDIR");
        std::string its_template = std::string(tmp && tmp[0] ? tmp : "/tmp") + "/dtls-pki.XXXXXX";
        if (!::mkdtemp(its_template.data())) {
            return;
        }
        dir_ = its_template;
        char start[32];
        std::strftime(start, sizeof(start), "%Y%m%d%H%M%SZ", std::gmtime(&_start));
        // Overridable for a test binary run on another machine (the target).
        const char* its_script = getenv("DTLS_TEST_PKI_SCRIPT");
        const std::string script = its_script && its_script[0] ? its_script : DTLS_TEST_PKI_SCRIPT;
        // Both calls need the dates: the negative set includes a rogue CA
        // whose validity must also be relative to this machine's clock.
        const std::string env = "PKI_START=" + std::string(start) + " PKI_LEAF_DAYS=3650 ";
        const std::string command = env + "bash '" + script + "' '" + dir_ + "' " + SERVER_NAME + " " + CLIENT_NAME
                + " >/dev/null 2>&1 && " + env + "bash '" + script + "' '" + dir_ + "' --negative " + CLIENT_NAME + " >/dev/null 2>&1";
        ok_ = std::system(command.c_str()) == 0 && std::filesystem::exists(bad("serveronly", "node.crt"));
    }
    ~pki() {
        if (!dir_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(dir_, ignored);
        }
    }

    std::string dir_;
    bool ok_{false};
};

dtls_session::credentials psk_client(const std::string& _cipher = "", const std::string& _key = KEY,
                                     const std::string& _identity = IDENTITY) {
    dtls_session::credentials result;
    result.auth_ = dtls_auth_e::PSK;
    result.cipher_ = _cipher;
    result.identity_ = _identity;
    result.psk_hex_ = _key;
    return result;
}

dtls_session::credentials psk_server(const std::string& _cipher = "", const std::string& _key = KEY) {
    dtls_session::credentials result;
    result.auth_ = dtls_auth_e::PSK;
    result.cipher_ = _cipher;
    result.resolver_ = [_key](const std::string& _identity) { return _identity == IDENTITY ? _key : std::string(); };
    return result;
}

// Client = host.ecu.lab, server = server.ecu.lab, both from the lab CA.
dtls_session::credentials cert_side(bool _is_client, std::int64_t _time_floor = 0, const pki& its_pki = pki::get()) {
    const std::string& self = _is_client ? CLIENT_NAME : SERVER_NAME;
    dtls_session::credentials result;
    result.auth_ = dtls_auth_e::CERTIFICATE;
    result.certificate_ = its_pki.node(self, "node.crt");
    result.private_key_ = its_pki.node(self, "node.key");
    result.ca_ = its_pki.path("ca.crt");
    result.peer_name_ = _is_client ? SERVER_NAME : CLIENT_NAME;
    result.peer_address_ = _is_client ? SERVER_ADDRESS : CLIENT_ADDRESS;
    result.time_floor_ = _time_floor;
    return result;
}

class dtls_session_test : public ::testing::Test {
protected:
    // Return false to drop the datagram; it may also be modified in place.
    using filter_t = std::function<bool(bool _to_server, std::size_t _index, datagram_t& _datagram)>;

    bool create(dtls_session::credentials _client, dtls_session::credentials _server) {
        client_ = make(true, std::move(_client));
        server_ = make(false, std::move(_server));
        return client_ && server_;
    }

    std::shared_ptr<dtls_session> make(bool _is_client, dtls_session::credentials _credentials) {
        auto& queue = _is_client ? to_server_ : to_client_;
        auto& log = _is_client ? sent_by_client_ : sent_by_server_;
        auto& received = _is_client ? received_by_client_ : received_by_server_;
        return dtls_session::create(
                io_, _is_client, std::move(_credentials),
                [this, &queue, &log, _is_client](datagram_t _datagram, dtls_session::send_completion_t _done) {
                    datagram_t copy = _datagram;
                    log.push_back(_datagram);
                    if (!filter_ || filter_(_is_client, log.size() - 1U, copy)) {
                        queue.push_back(std::move(copy));
                    }
                    if (_done) {
                        _done(true);
                    }
                },
                [&received](datagram_t _plaintext) { received.push_back(std::move(_plaintext)); });
    }

    // Bounded: two sessions that answer each other's every datagram would loop
    // here forever; the cap turns that into a visible datagram count instead.
    void pump() {
        for (int i = 0; i < 200 && (!to_server_.empty() || !to_client_.empty()); ++i) {
            if (!to_server_.empty()) {
                auto d = std::move(to_server_.front());
                to_server_.pop_front();
                server_->feed(d.data(), d.size());
            }
            if (!to_client_.empty()) {
                auto d = std::move(to_client_.front());
                to_client_.pop_front();
                client_->feed(d.data(), d.size());
            }
        }
    }

    // Moves datagrams and runs the retransmit timers until _done or _limit.
    bool run_until(const std::function<bool()>& _done, std::chrono::milliseconds _limit = 5000ms) {
        const auto end = std::chrono::steady_clock::now() + _limit;
        for (;;) {
            pump();
            if (_done()) {
                return true;
            }
            if (std::chrono::steady_clock::now() > end) {
                return false;
            }
            io_.restart();
            io_.run_for(5ms);
            std::this_thread::sleep_for(1ms);
        }
    }

    bool handshake(std::chrono::milliseconds _limit = 5000ms) {
        client_->start();
        return run_until([this] { return client_->is_ready() && server_->is_ready(); }, _limit);
    }

    // Handshake must not complete; true when the given side gave up on its own.
    bool refused(const std::shared_ptr<dtls_session>& _verifier, std::chrono::milliseconds _limit = 3000ms) {
        client_->start();
        run_until([&_verifier] { return _verifier->is_failed(); }, _limit);
        return !(client_->is_ready() && server_->is_ready()) && _verifier->is_failed();
    }

    bool send(const std::shared_ptr<dtls_session>& _from, const datagram_t& _message) {
        return _from->write(_message.data(), _message.size(), [](bool) {});
    }

    boost::asio::io_context io_;
    std::shared_ptr<dtls_session> client_;
    std::shared_ptr<dtls_session> server_;
    std::deque<datagram_t> to_server_;
    std::deque<datagram_t> to_client_;
    std::vector<datagram_t> sent_by_client_;
    std::vector<datagram_t> sent_by_server_;
    std::vector<datagram_t> received_by_client_;
    std::vector<datagram_t> received_by_server_;
    filter_t filter_;
};

#define REQUIRE_PKI()                                                                                                                      \
    if (!pki::get().ok()) {                                                                                                                \
        GTEST_SKIP() << "test PKI could not be generated (needs bash + openssl)";                                                          \
    }

// ---------------------------------------------------------------- PSK -------

TEST_F(dtls_session_test, psk_default_cipher_exchanges_data_both_ways) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    const auto request = message(100, 1);
    const auto response = message(200, 2);
    ASSERT_TRUE(send(client_, request));
    ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
    ASSERT_TRUE(send(server_, response));
    ASSERT_TRUE(run_until([this] { return received_by_client_.size() == 1U; }));
    EXPECT_EQ(received_by_server_[0], request);
    EXPECT_EQ(received_by_client_[0], response);
}

TEST_F(dtls_session_test, ecdhe_psk_chacha20_handshake) {
    ASSERT_TRUE(create(psk_client("ECDHE-PSK-CHACHA20-POLY1305"), psk_server("ECDHE-PSK-CHACHA20-POLY1305")));
    ASSERT_TRUE(handshake());
    ASSERT_TRUE(send(client_, message(64, 3)));
    EXPECT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
}

TEST_F(dtls_session_test, ecdhe_psk_aes128_gcm_needs_wolfssl) {
    // RFC 8442 suite: implemented by wolfSSL, not by OpenSSL 3.
    auto client = psk_client("ECDHE-PSK-AES128-GCM-SHA256");
    if (!is_wolfssl()) {
        EXPECT_EQ(dtls_session::create(io_, true, client, [](datagram_t, dtls_session::send_completion_t) {}, [](datagram_t) {}),
                  nullptr);
        return;
    }
    ASSERT_TRUE(create(client, psk_server("ECDHE-PSK-AES128-GCM-SHA256")));
    ASSERT_TRUE(handshake());
    ASSERT_TRUE(send(server_, message(64, 4)));
    EXPECT_TRUE(run_until([this] { return received_by_client_.size() == 1U; }));
}

TEST_F(dtls_session_test, largest_someip_message_is_one_record_in_one_datagram) {
    for (const char* cipher : {"PSK-AES128-GCM-SHA256", "ECDHE-PSK-CHACHA20-POLY1305"}) {
        SCOPED_TRACE(cipher);
        sent_by_client_.clear();
        received_by_server_.clear();
        ASSERT_TRUE(create(psk_client(cipher), psk_server(cipher)));
        ASSERT_TRUE(handshake());
        const auto before = sent_by_client_.size();
        const auto big = message(1416, 5);  // VSOMEIP_MAX_UDP_MESSAGE_SIZE
        ASSERT_TRUE(send(client_, big));
        ASSERT_EQ(sent_by_client_.size(), before + 1U) << "message split across datagrams";
        EXPECT_EQ(sent_by_client_.back()[0], CONTENT_APPLICATION_DATA);
        EXPECT_LE(sent_by_client_.back().size(), 1472U) << "must fit one Ethernet frame without IP fragmentation";
        ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
        EXPECT_EQ(received_by_server_[0], big);
    }
}

TEST_F(dtls_session_test, oversized_message_is_never_delivered_in_pieces) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    const auto huge = message(4000, 6);
    if (send(client_, huge)) {
        ASSERT_TRUE(run_until([this] { return !received_by_server_.empty(); }));
        ASSERT_EQ(received_by_server_.size(), 1U);
        EXPECT_EQ(received_by_server_[0], huge);
    }
    // Either way the session stays usable.
    ASSERT_TRUE(send(client_, message(10, 7)));
    EXPECT_TRUE(run_until([this] { return !received_by_server_.empty() && received_by_server_.back().size() == 10U; }));
}

std::string trace(const std::vector<datagram_t>& _datagrams) {
    std::string result;
    for (std::size_t i = 0; i < _datagrams.size() && i < 24U; ++i) {
        const auto& d = _datagrams[i];
        result += std::to_string(d.empty() ? 0 : d[0]) + "/" + std::to_string(d.size() > 4 ? (d[3] << 8 | d[4]) : 0) + "/"
                + std::to_string(handshake_type(d)) + "(" + std::to_string(d.size()) + ") ";
    }
    return result;  // content type / epoch / handshake type (size)
}

TEST_F(dtls_session_test, wrong_key_never_completes_and_does_not_storm) {
    ASSERT_TRUE(create(psk_client("", OTHER_KEY), psk_server()));
    client_->start();
    run_until([] { return false; }, 2500ms);
    EXPECT_FALSE(client_->is_ready());
    EXPECT_FALSE(server_->is_ready());
    EXPECT_TRUE(received_by_server_.empty());
    // A mismatch may only cost the normal retransmissions (1 s, 2 s, ...).
    EXPECT_LT(sent_by_client_.size() + sent_by_server_.size(), 40U)
            << "client: " << trace(sent_by_client_) << "\nserver: " << trace(sent_by_server_);
}

TEST_F(dtls_session_test, unknown_identity_is_refused) {
    ASSERT_TRUE(create(psk_client("", KEY, "intruder"), psk_server()));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, cipher_mismatch_is_refused) {
    ASSERT_TRUE(create(psk_client("ECDHE-PSK-CHACHA20-POLY1305"), psk_server("PSK-AES128-GCM-SHA256")));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, invalid_psk_configuration_is_rejected_at_creation) {
    auto nop_send = [](datagram_t, dtls_session::send_completion_t) {};
    auto nop_receive = [](datagram_t) {};
    EXPECT_EQ(dtls_session::create(io_, true, psk_client("", "0011223344556677"), nop_send, nop_receive), nullptr) << "short key";
    EXPECT_EQ(dtls_session::create(io_, true, psk_client("", std::string(64, 'z')), nop_send, nop_receive), nullptr) << "not hex";
    EXPECT_EQ(dtls_session::create(io_, true, psk_client("", KEY, ""), nop_send, nop_receive), nullptr) << "no identity";
    EXPECT_EQ(dtls_session::create(io_, true, psk_client("NO-SUCH-CIPHER"), nop_send, nop_receive), nullptr) << "cipher";
    dtls_session::credentials no_resolver;
    EXPECT_EQ(dtls_session::create(io_, false, no_resolver, nop_send, nop_receive), nullptr) << "server without resolver";
}

// ------------------------------------------------------ record layer -------

TEST_F(dtls_session_test, lost_handshake_flight_is_retransmitted) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    filter_ = [](bool _to_server, std::size_t _index, datagram_t&) { return _to_server || _index != 0U; };
    EXPECT_TRUE(handshake(6000ms));
}

TEST_F(dtls_session_test, handshake_needs_no_timer_when_nothing_is_lost) {
    // Every flight must go out at once; a flight held back would only show up
    // as a handshake that waits for the 1 s retransmit timer.
    ASSERT_TRUE(create(psk_client(), psk_server()));
    client_->start();
    pump();
    EXPECT_TRUE(client_->is_ready() && server_->is_ready());
}

TEST_F(dtls_session_test, certificate_handshake_needs_no_timer_when_nothing_is_lost) {
    REQUIRE_PKI();
    ASSERT_TRUE(create(cert_side(true), cert_side(false)));
    client_->start();
    pump();
    EXPECT_TRUE(client_->is_ready() && server_->is_ready());
}

// The final flight (ChangeCipherSpec + Finished) has no timer of its own: when
// it is lost, the peer resends its flight and that must trigger a resend.
TEST_F(dtls_session_test, lost_final_server_flight_is_recovered) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    int dropped = 0;
    filter_ = [&dropped](bool _to_server, std::size_t, datagram_t& _d) {
        const bool final_flight = carries_change_cipher_spec(_d);
        if (!_to_server && final_flight && dropped < 2) {
            ++dropped;
            return false;
        }
        return true;
    };
    ASSERT_TRUE(handshake(8000ms));
    EXPECT_GE(dropped, 1);
    ASSERT_TRUE(send(server_, message(30, 13)));
    EXPECT_TRUE(run_until([this] { return received_by_client_.size() == 1U; }));
}

TEST_F(dtls_session_test, lost_final_client_flight_is_recovered) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    int dropped = 0;
    filter_ = [&dropped](bool _to_server, std::size_t, datagram_t& _d) {
        const bool final_flight = carries_change_cipher_spec(_d);
        if (_to_server && final_flight && dropped < 2) {
            ++dropped;
            return false;
        }
        return true;
    };
    ASSERT_TRUE(handshake(8000ms));
    EXPECT_GE(dropped, 1);
}

TEST_F(dtls_session_test, replayed_record_is_delivered_once) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    ASSERT_TRUE(send(client_, message(50, 8)));
    const auto record = sent_by_client_.back();
    ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
    server_->feed(record.data(), record.size());
    run_until([] { return false; }, 200ms);
    EXPECT_EQ(received_by_server_.size(), 1U);
    EXPECT_FALSE(server_->is_failed());
}

TEST_F(dtls_session_test, tampered_record_is_dropped_and_session_survives) {
    // RFC 6347 4.1.2.7: an invalid record is discarded, not fatal. Otherwise
    // anyone able to spoof the peer address could tear the session down.
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    bool tamper = true;
    filter_ = [&tamper](bool _to_server, std::size_t, datagram_t& _datagram) {
        if (_to_server && tamper && !_datagram.empty() && _datagram[0] == CONTENT_APPLICATION_DATA) {
            _datagram.back() ^= 0x01U;
            tamper = false;
        }
        return true;
    };
    ASSERT_TRUE(send(client_, message(40, 9)));
    run_until([] { return false; }, 200ms);
    EXPECT_TRUE(received_by_server_.empty());
    EXPECT_FALSE(server_->is_failed());
    const auto good = message(41, 10);
    ASSERT_TRUE(send(client_, good));
    ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
    EXPECT_EQ(received_by_server_[0], good);
}

TEST_F(dtls_session_test, garbage_datagram_does_not_fail_an_established_session) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    const datagram_t garbage(60, 0x17U);
    server_->feed(garbage.data(), garbage.size());
    EXPECT_FALSE(server_->is_failed());
    ASSERT_TRUE(send(client_, message(12, 11)));
    EXPECT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
}

// -------------------------------------------------------- certificate -------

TEST_F(dtls_session_test, certificate_mutual_authentication) {
    REQUIRE_PKI();
    ASSERT_TRUE(create(cert_side(true), cert_side(false)));
    ASSERT_TRUE(handshake());
    // The server first proves the client owns its address (anti-amplification).
    ASSERT_FALSE(sent_by_server_.empty());
    EXPECT_EQ(handshake_type(sent_by_server_[0]), HANDSHAKE_HELLO_VERIFY_REQUEST);
    const auto big = message(1416, 12);
    ASSERT_TRUE(send(server_, big));
    ASSERT_TRUE(run_until([this] { return received_by_client_.size() == 1U; }));
    EXPECT_EQ(received_by_client_[0], big);
}

TEST_F(dtls_session_test, certificate_handshake_flights_fit_1200_byte_datagrams) {
    REQUIRE_PKI();
    ASSERT_TRUE(create(cert_side(true), cert_side(false)));
    ASSERT_TRUE(handshake());
    for (const auto& d : sent_by_server_) {
        if (d[0] == CONTENT_HANDSHAKE) {
            EXPECT_LE(d.size(), 1200U);
        }
    }
    for (const auto& d : sent_by_client_) {
        if (d[0] == CONTENT_HANDSHAKE) {
            EXPECT_LE(d.size(), 1200U);
        }
    }
}

TEST_F(dtls_session_test, cookie_of_one_address_is_not_accepted_for_another) {
    // Allowed answers: a fresh HelloVerifyRequest (wolfSSL) or nothing (OpenSSL).
    // Not allowed: ServerHello and the certificate flight to an unverified address.
    REQUIRE_PKI();
    ASSERT_TRUE(create(cert_side(true), cert_side(false)));
    ASSERT_TRUE(handshake());
    // Second client datagram = ClientHello carrying the cookie for CLIENT_ADDRESS.
    ASSERT_GE(sent_by_client_.size(), 2U);
    const auto hello_with_cookie = sent_by_client_[1];
    auto spoofed = cert_side(false);
    spoofed.peer_address_ = "198.51.100.7:40000";
    std::vector<datagram_t> answers;
    auto other = dtls_session::create(
            io_, false, spoofed, [&answers](datagram_t _d, dtls_session::send_completion_t) { answers.push_back(std::move(_d)); },
            [](datagram_t) {});
    ASSERT_NE(other, nullptr);
    other->feed(hello_with_cookie.data(), hello_with_cookie.size());
    EXPECT_FALSE(other->is_ready());
    for (const auto& a : answers) {
        EXPECT_NE(handshake_type(a), HANDSHAKE_SERVER_HELLO) << "certificate flight sent to an unverified address";
    }
}

TEST_F(dtls_session_test, certificate_from_rogue_ca_is_refused) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("rogue", "node.crt");
    client.private_key_ = pki::get().bad("rogue", "node.key");
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, server_trusting_a_rogue_ca_refuses_the_real_client) {
    REQUIRE_PKI();
    auto server = cert_side(false);
    server.ca_ = pki::get().path("negative/rogue-ca.crt");
    ASSERT_TRUE(create(cert_side(true), server));
    // The server cannot even complete its side; the client refuses the
    // server certificate only if it trusts the rogue CA, which it does not.
    client_->start();
    run_until([this] { return server_->is_failed() || client_->is_failed(); }, 3000ms);
    EXPECT_FALSE(client_->is_ready() && server_->is_ready());
}

TEST_F(dtls_session_test, expired_certificate_is_refused) {
    REQUIRE_PKI();
    // The "expired" certificate of pki.sh is valid 2026-01-01 .. 2026-06-01. On a
    // machine whose (trusted) clock is still before its end it is not expired.
    if (std::time(nullptr) < 1780272000) {
        GTEST_SKIP() << "the clock of this machine is before 2026-06-01, when the test certificate expires";
    }
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("expired", "node.crt");
    client.private_key_ = pki::get().bad("expired", "node.key");
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, not_yet_valid_certificate_is_refused_with_a_trusted_clock) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("future", "node.crt");
    client.private_key_ = pki::get().bad("future", "node.key");
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, untrusted_clock_checks_expiry_against_the_floor) {
    REQUIRE_PKI();
    // Floor in the future = this ECU's clock is not trusted (like an ECU booting at 1970).
    const std::int64_t floor = untrusted_floor();
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("expired", "node.crt");
    client.private_key_ = pki::get().bad("expired", "node.key");
    ASSERT_TRUE(create(client, cert_side(false, floor)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, untrusted_clock_cannot_check_not_before) {
    REQUIRE_PKI();
    // Documented limit: without trusted time a not-yet-valid certificate (2030)
    // is accepted as long as it does not expire before the floor.
    // Only after the clock: the floor must stay inside the CA validity, which
    // on a 1970 board is generated relative to 1970 as well.
    const std::int64_t floor = static_cast<std::int64_t>(std::time(nullptr)) + 365LL * 86400LL;
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("future", "node.crt");
    client.private_key_ = pki::get().bad("future", "node.key");
    ASSERT_TRUE(create(client, cert_side(false, floor)));
    EXPECT_TRUE(handshake());
}

// The embedded ECU case: the clock is far behind the certificates (1970 vs 2026), and
// the floor (firmware date) lies inside their validity. The CA, the peer chain
// and the leaf are all "not yet valid" by the clock and must still be accepted.
TEST_F(dtls_session_test, clock_behind_certificates_like_an_ecu_at_1970) {
    const auto& ahead = pki::ahead_of_clock();
    if (!ahead.ok()) {
        GTEST_SKIP() << "test PKI could not be generated (needs bash + openssl)";
    }
    const std::int64_t floor = static_cast<std::int64_t>(pki::ahead_start()) + 86400;
    ASSERT_TRUE(create(cert_side(true, floor, ahead), cert_side(false, floor, ahead)));
    ASSERT_TRUE(handshake());
    // ... and the usual rejections still hold under that clock.
    auto rogue = cert_side(true, floor, ahead);
    rogue.certificate_ = ahead.bad("rogue", "node.crt");
    rogue.private_key_ = ahead.bad("rogue", "node.key");
    ASSERT_TRUE(create(rogue, cert_side(false, floor, ahead)));
    EXPECT_TRUE(refused(server_));
    auto other = cert_side(true, floor, ahead);
    other.certificate_ = ahead.bad("othername", "node.crt");
    other.private_key_ = ahead.bad("othername", "node.key");
    ASSERT_TRUE(create(other, cert_side(false, floor, ahead)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, valid_certificate_of_another_ecu_is_refused) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("othername", "node.crt");
    client.private_key_ = pki::get().bad("othername", "node.key");
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, client_pins_the_server_name_too) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.peer_name_ = "camera.ecu.lab";
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(client_));
}

TEST_F(dtls_session_test, server_only_certificate_cannot_act_as_client) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.certificate_ = pki::get().bad("serveronly", "node.crt");
    client.private_key_ = pki::get().bad("serveronly", "node.key");
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, psk_client_against_certificate_server_is_refused) {
    REQUIRE_PKI();
    ASSERT_TRUE(create(psk_client(), cert_side(false)));
    EXPECT_TRUE(refused(server_));
}

TEST_F(dtls_session_test, private_key_file_uri_is_accepted) {
    REQUIRE_PKI();
    auto client = cert_side(true);
    client.private_key_ = "file:" + client.private_key_;
    ASSERT_TRUE(create(client, cert_side(false)));
    EXPECT_TRUE(handshake());
}

TEST_F(dtls_session_test, invalid_certificate_configuration_is_rejected_at_creation) {
    REQUIRE_PKI();
    auto nop_send = [](datagram_t, dtls_session::send_completion_t) {};
    auto nop_receive = [](datagram_t) {};
    auto mismatch = cert_side(true);
    mismatch.private_key_ = pki::get().node(SERVER_NAME, "node.key");
    EXPECT_EQ(dtls_session::create(io_, true, mismatch, nop_send, nop_receive), nullptr) << "key does not match certificate";
    auto no_name = cert_side(true);
    no_name.peer_name_.clear();
    EXPECT_EQ(dtls_session::create(io_, true, no_name, nop_send, nop_receive), nullptr) << "no expected peer name";
    auto no_ca = cert_side(true);
    no_ca.ca_.clear();
    EXPECT_EQ(dtls_session::create(io_, true, no_ca, nop_send, nop_receive), nullptr) << "no CA";
    auto missing = cert_side(true);
    missing.certificate_ = pki::get().path("does-not-exist.crt");
    EXPECT_EQ(dtls_session::create(io_, true, missing, nop_send, nop_receive), nullptr) << "missing certificate";
    if (is_wolfssl()) {
        auto tee = cert_side(true);
        tee.private_key_ = "pkcs11:token=ecu;object=dtls-key";
        EXPECT_EQ(dtls_session::create(io_, true, tee, nop_send, nop_receive), nullptr) << "pkcs11 needs the OpenSSL backend";
    }
}

// ------------------------------------------------- accelerator / token -------

dtls_session::credentials with_accelerator(dtls_session::credentials _credentials, const std::string& _accelerator) {
    _credentials.accelerator_ = _accelerator;
    return _credentials;
}

TEST_F(dtls_session_test, sa2ul_accelerator_interoperates_with_cpu_cbc) {
    // Client encrypts AES-CBC on the SA2UL when the machine has one (else on the
    // CPU, with a warning); the server always on the CPU. Records of every size
    // in both directions prove the CBC chaining matches a software peer.
    const char* cipher = "PSK-AES128-CBC-SHA256";
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
    const auto before = dtls_wolfssl::sa2ul_operations();
#endif
    ASSERT_TRUE(create(with_accelerator(psk_client(cipher), "sa2ul"), psk_server(cipher)));
    ASSERT_TRUE(handshake());
    std::size_t expected = 0;
    for (std::size_t size : {1U, 15U, 16U, 17U, 100U, 1024U, 1391U, 1407U}) {
        const auto up = message(size, static_cast<std::uint8_t>(size));
        ASSERT_TRUE(send(client_, up)) << size;
        ASSERT_TRUE(send(server_, up)) << size;
        ++expected;
        ASSERT_TRUE(run_until([this, expected] {
            return received_by_server_.size() == expected && received_by_client_.size() == expected;
        })) << size;
        EXPECT_EQ(received_by_server_.back(), up) << size;
        EXPECT_EQ(received_by_client_.back(), up) << size;
    }
#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
    if (dtls_wolfssl::sa2ul_operations() == before) {
        GTEST_SKIP() << "no SA2UL on this machine: the exchange ran on the CPU (still verified above)";
    }
    EXPECT_GE(dtls_wolfssl::sa2ul_operations() - before, 2U * expected);
#endif
}

TEST_F(dtls_session_test, sa2ul_accelerator_on_both_sides) {
    const char* cipher = "ECDHE-PSK-AES128-CBC-SHA256";
    ASSERT_TRUE(create(with_accelerator(psk_client(cipher), "sa2ul"), with_accelerator(psk_server(cipher), "sa2ul")));
    ASSERT_TRUE(handshake());
    const auto big = message(1407, 21);  // largest CBC-SHA256 message in one frame
    ASSERT_TRUE(send(client_, big));
    ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
    EXPECT_EQ(received_by_server_[0], big);
}

TEST_F(dtls_session_test, cbc_sha256_fits_one_frame_up_to_1407_bytes) {
    // CBC-SHA256 (the suites the SA2UL can run): 1407 bytes is the largest
    // message in a 1472-byte datagram. A larger one is refused, not fragmented,
    // and the session carries on.
    for (const char* cipher : {"PSK-AES128-CBC-SHA256", "ECDHE-PSK-AES128-CBC-SHA256"}) {
        SCOPED_TRACE(cipher);
        sent_by_client_.clear();
        received_by_server_.clear();
        ASSERT_TRUE(create(psk_client(cipher), psk_server(cipher)));
        ASSERT_TRUE(handshake());
        const auto fits = message(1407, 23);
        const auto before = sent_by_client_.size();
        ASSERT_TRUE(send(client_, fits));
        ASSERT_EQ(sent_by_client_.size(), before + 1U);
        EXPECT_LE(sent_by_client_.back().size(), 1472U);
        ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
        EXPECT_EQ(received_by_server_[0], fits);
        if (is_wolfssl()) {
            EXPECT_FALSE(send(client_, message(1416, 24))) << "1485-byte datagram would be IP-fragmented";
            EXPECT_FALSE(client_->is_failed());
        }
        ASSERT_TRUE(send(client_, message(64, 25)));
        EXPECT_TRUE(run_until([this] { return received_by_server_.size() == 2U; }));
    }
}

TEST_F(dtls_session_test, sa2ul_accelerator_with_gcm_still_works) {
    // The SA2UL has no GCM: the option must not break a GCM session.
    ASSERT_TRUE(create(with_accelerator(psk_client(), "sa2ul"), psk_server()));
    ASSERT_TRUE(handshake());
    ASSERT_TRUE(send(client_, message(300, 22)));
    EXPECT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
}

#if defined(VSOMEIP_DTLS_BACKEND_WOLFSSL)
TEST(dtls_pkcs11_uri, parses_rfc7512_uri) {
    dtls_wolfssl::pkcs11_uri uri;
    std::string reason;
    ASSERT_TRUE(dtls_wolfssl::parse_pkcs11_uri(
            "pkcs11:token=vsomeip%2Ddtls;object=dtls-identity;type=private"
            "?module-path=/usr/lib/libckteec.so.0&pin-source=file:/etc/dtls/token.pin",
            uri, reason))
            << reason;
    EXPECT_EQ(uri.token_, "vsomeip-dtls");
    EXPECT_EQ(uri.object_, "dtls-identity");
    EXPECT_EQ(uri.module_, "/usr/lib/libckteec.so.0");
    EXPECT_EQ(uri.pin_file_, "/etc/dtls/token.pin");
}

TEST(dtls_pkcs11_uri, refuses_incomplete_or_unsafe_uris) {
    dtls_wolfssl::pkcs11_uri uri;
    std::string reason;
    EXPECT_FALSE(dtls_wolfssl::parse_pkcs11_uri("pkcs11:token=t;object=o", uri, reason)) << "no module, no pin";
    EXPECT_FALSE(dtls_wolfssl::parse_pkcs11_uri("pkcs11:token=t;object=o?module-path=/m.so&pin-value=1234", uri, reason))
            << "PIN in the configuration";
    EXPECT_NE(reason.find("pin-source"), std::string::npos);
    EXPECT_FALSE(dtls_wolfssl::parse_pkcs11_uri("pkcs11:token=t;object=o;type=public?module-path=/m.so&pin-source=/p",
                                                uri, reason))
            << "public key";
    EXPECT_FALSE(dtls_wolfssl::parse_pkcs11_uri("file:/etc/key.pem", uri, reason));
    EXPECT_TRUE(dtls_wolfssl::parse_pkcs11_uri("pkcs11:object=o;token=t?pin-source=/p&module-path=/m.so%", uri, reason))
            << "malformed escape kept literally: " << reason;
    EXPECT_EQ(uri.module_, "/m.so%");
}

TEST_F(dtls_session_test, token_key_with_unsafe_pin_file_or_missing_module_is_refused) {
    REQUIRE_PKI();
    auto nop_send = [](datagram_t, dtls_session::send_completion_t) {};
    auto nop_receive = [](datagram_t) {};
    const std::string pin = pki::get().path("token.pin");
    {
        std::ofstream(pin) << "1234\n";
    }
    std::filesystem::permissions(pin, std::filesystem::perms::owner_read | std::filesystem::perms::group_read
                                              | std::filesystem::perms::others_read);
    auto open_pin = cert_side(false);
    open_pin.private_key_ = "pkcs11:token=t;object=dtls-identity?module-path=/nonexistent/libp11.so&pin-source=file:" + pin;
    EXPECT_EQ(dtls_session::create(io_, false, open_pin, nop_send, nop_receive), nullptr) << "PIN file readable by others";

    std::filesystem::permissions(pin, std::filesystem::perms::owner_read);
    EXPECT_EQ(dtls_session::create(io_, false, open_pin, nop_send, nop_receive), nullptr) << "module does not exist";
}
#endif

TEST(dtls_record_limit, payload_per_suite) {
    // Block ciphers: explicit IV, MAC and at least one padding byte in 1472 - 13.
    EXPECT_EQ(dtls::max_record_payload("ECDHE-ECDSA-AES128-SHA256"), 1407U);
    EXPECT_EQ(dtls::max_record_payload("PSK-AES128-CBC-SHA256"), 1407U);
    EXPECT_EQ(dtls::max_record_payload("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"), 1407U);
    EXPECT_EQ(dtls::max_record_payload("PSK-AES256-CBC-SHA384"), 1391U);
    EXPECT_EQ(dtls::max_record_payload("ECDHE-ECDSA-AES128-SHA"), 1407U) << "encrypt-then-MAC bound";
    // AEAD: a 1416-byte SOME/IP datagram always fits.
    EXPECT_EQ(dtls::max_record_payload("PSK-AES128-GCM-SHA256"), 1435U);
    EXPECT_EQ(dtls::max_record_payload("ECDHE-ECDSA-AES128-GCM-SHA256"), 1435U);
    EXPECT_EQ(dtls::max_record_payload("PSK-AES128-CCM"), 1435U);
    EXPECT_EQ(dtls::max_record_payload("PSK-AES128-CCM8"), 1443U);
    EXPECT_EQ(dtls::max_record_payload("ECDHE-PSK-CHACHA20-POLY1305"), 1443U);
    EXPECT_EQ(dtls::max_record_payload("PSK-NULL-SHA256"), 1427U);
    // Not a suite: the smallest supported value.
    EXPECT_EQ(dtls::max_record_payload("DEFAULT"), 1391U);
}

TEST(dtls_record_limit, list_takes_the_smallest) {
    EXPECT_EQ(dtls::max_message_size("ECDHE-ECDSA-AES128-GCM-SHA256"), 1435U);
    EXPECT_EQ(dtls::max_message_size("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256"), 1407U);
    EXPECT_EQ(dtls::max_message_size("ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL:@STRENGTH"), 1435U);
    EXPECT_EQ(dtls::max_message_size(""), 1391U);
}

TEST(dtls_record_limit, tp_splits_a_message_between_record_and_udp_limit) {
    // Payload 1400: the datagram (1416) fits UDP but not one CBC-SHA256 record
    // (1407). It must split into segments that each fit a record.
    const std::size_t limit = dtls::max_message_size("ECDHE-ECDSA-AES128-SHA256");
    for (std::size_t payload : {1392U, 1400U}) {
        SCOPED_TRACE(payload);
        datagram_t data = message(VSOMEIP_FULL_HEADER_SIZE + payload, 41);
        data[VSOMEIP_MESSAGE_TYPE_POS] = 0x00; // request
        const auto segments = tp::tp::tp_split_message(data.data(), static_cast<std::uint32_t>(data.size()), 1376);
        ASSERT_EQ(segments.size(), 2U);
        std::size_t carried = 0;
        for (const auto& segment : segments) {
            EXPECT_LE(segment->size(), limit);
            EXPECT_TRUE(tp::tp::tp_flag_is_set((*segment)[VSOMEIP_MESSAGE_TYPE_POS]));
            carried += segment->size() - VSOMEIP_FULL_HEADER_SIZE - VSOMEIP_TP_HEADER_SIZE;
        }
        EXPECT_EQ(carried, payload);
    }
    // Nothing to split: one segment would hold it all.
    const datagram_t small = message(VSOMEIP_FULL_HEADER_SIZE + 1376, 42);
    EXPECT_TRUE(tp::tp::tp_split_message(small.data(), static_cast<std::uint32_t>(small.size()), 1376).empty());
    EXPECT_TRUE(tp::tp::tp_split_message(small.data(), static_cast<std::uint32_t>(small.size()), 0).empty());
}

TEST_F(dtls_session_test, record_limit_matches_the_tls_library) {
    // max_message_size() decides when the endpoints segment. It must equal what
    // the TLS library really fits: a message of the limit goes out in one
    // datagram of at most 1472 bytes, and (wolfSSL, which refuses rather than
    // IP-fragments) one byte more does not.
    for (const char* cipher :
         {"PSK-AES128-CBC-SHA256", "PSK-AES256-CBC-SHA384", "PSK-AES128-GCM-SHA256", "ECDHE-PSK-CHACHA20-POLY1305"}) {
        SCOPED_TRACE(cipher);
        sent_by_client_.clear();
        received_by_server_.clear();
        ASSERT_TRUE(create(psk_client(cipher), psk_server(cipher)));
        ASSERT_TRUE(handshake());
        const std::size_t limit = dtls::max_message_size(cipher);
        const auto fits = message(limit, 43);
        const auto before = sent_by_client_.size();
        ASSERT_TRUE(send(client_, fits));
        ASSERT_EQ(sent_by_client_.size(), before + 1U);
        EXPECT_LE(sent_by_client_.back().size(), dtls::DATAGRAM_SIZE);
        ASSERT_TRUE(run_until([this] { return received_by_server_.size() == 1U; }));
        EXPECT_EQ(received_by_server_[0], fits);
        if (is_wolfssl()) {
            EXPECT_FALSE(send(client_, message(limit + 1U, 44))) << "limit is not tight";
            EXPECT_FALSE(client_->is_failed());
        }
    }
}

// Endpoint fast path: seal() returns the record instead of calling the send
// handler, feed(..., out) returns the plaintext instead of calling the plaintext
// handler. Both must interoperate with the handler-based calls.
TEST_F(dtls_session_test, seal_and_feed_out_bypass_the_handlers) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    const auto sent_before = sent_by_client_.size();

    const auto first = message(1200, 51);
    std::vector<datagram_t> records;
    ASSERT_TRUE(client_->seal(first.data(), first.size(), records));
    ASSERT_EQ(records.size(), 1U);
    EXPECT_LE(records[0].size(), dtls::DATAGRAM_SIZE);
    EXPECT_EQ(sent_by_client_.size(), sent_before) << "seal() must not use the send handler";

    std::vector<datagram_t> plaintext{message(3, 52)}; // existing content is kept
    server_->feed(records[0].data(), records[0].size(), plaintext);
    ASSERT_EQ(plaintext.size(), 2U);
    EXPECT_EQ(plaintext[1], first);
    EXPECT_TRUE(received_by_server_.empty()) << "feed(..., out) must not use the plaintext handler";

    // A sealed record also opens through the handler-based feed(), and a record
    // from write() through feed(..., out).
    const auto second = message(64, 53);
    records.clear();
    ASSERT_TRUE(client_->seal(second.data(), second.size(), records));
    ASSERT_EQ(records.size(), 1U);
    server_->feed(records[0].data(), records[0].size());
    ASSERT_EQ(received_by_server_.size(), 1U);
    EXPECT_EQ(received_by_server_[0], second);

    const auto third = message(700, 54);
    ASSERT_TRUE(send(server_, third));
    ASSERT_FALSE(sent_by_server_.empty());
    std::vector<datagram_t> back;
    client_->feed(sent_by_server_.back().data(), sent_by_server_.back().size(), back);
    ASSERT_EQ(back.size(), 1U);
    EXPECT_EQ(back[0], third);
}

TEST_F(dtls_session_test, seal_before_the_handshake_is_refused) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    const auto data = message(100, 55);
    std::vector<datagram_t> records;
    EXPECT_FALSE(client_->seal(data.data(), data.size(), records));
    EXPECT_TRUE(records.empty());
    EXPECT_FALSE(client_->seal(nullptr, 0, records));
    ASSERT_TRUE(handshake()) << "a refused seal() must not disturb the handshake";
}

TEST_F(dtls_session_test, seal_refuses_a_message_over_the_record_limit) {
    const char* cipher = "PSK-AES128-CBC-SHA256";
    ASSERT_TRUE(create(psk_client(cipher), psk_server(cipher)));
    ASSERT_TRUE(handshake());
    const std::size_t limit = dtls::max_message_size(cipher);
    std::vector<datagram_t> records;
    const auto fits = message(limit, 56);
    ASSERT_TRUE(client_->seal(fits.data(), fits.size(), records));
    ASSERT_EQ(records.size(), 1U);
    EXPECT_LE(records[0].size(), dtls::DATAGRAM_SIZE);
    if (is_wolfssl()) {
        std::vector<datagram_t> refused;
        const auto too_big = message(limit + 1U, 57);
        EXPECT_FALSE(client_->seal(too_big.data(), too_big.size(), refused));
        EXPECT_TRUE(refused.empty());
        EXPECT_FALSE(client_->is_failed()) << "one oversize message must not end the session";
    }
    std::vector<datagram_t> plaintext;
    server_->feed(records[0].data(), records[0].size(), plaintext);
    ASSERT_EQ(plaintext.size(), 1U);
    EXPECT_EQ(plaintext[0], fits);
}

TEST_F(dtls_session_test, sealed_records_keep_their_order_and_detect_tampering) {
    ASSERT_TRUE(create(psk_client(), psk_server()));
    ASSERT_TRUE(handshake());
    std::vector<datagram_t> records;
    for (std::uint8_t i = 0; i < 20U; ++i) {
        const auto data = message(100U + i, i);
        ASSERT_TRUE(client_->seal(data.data(), data.size(), records));
    }
    ASSERT_EQ(records.size(), 20U);
    std::vector<datagram_t> plaintext;
    for (const auto& record : records) {
        server_->feed(record.data(), record.size(), plaintext);
    }
    ASSERT_EQ(plaintext.size(), 20U);
    for (std::uint8_t i = 0; i < 20U; ++i) {
        EXPECT_EQ(plaintext[i], message(100U + i, i));
    }
    // Replayed and tampered records are dropped, not delivered.
    std::vector<datagram_t> none;
    server_->feed(records[3].data(), records[3].size(), none);
    auto tampered = records.back();
    tampered.back() ^= 0x01U;
    server_->feed(tampered.data(), tampered.size(), none);
    EXPECT_TRUE(none.empty());
}

} // namespace

