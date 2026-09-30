// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "dtls-bench-common.hpp"

// Echo / sink service for the DTLS benchmark. It keeps no per-request state, so
// the CPU time it reports on exit is the cost of receiving, dispatching and
// answering the traffic the client generated.
class bench_service {
public:
    explicit bench_service(std::string _name) :
        name_(std::move(_name)), app_(vsomeip::runtime::get()->create_application(name_)) { }

    bool init() {
        if (!app_->init()) {
            std::fprintf(stderr, "[bench-service] init failed\n");
            return false;
        }

        app_->register_message_handler(BENCH_SERVICE_ID, BENCH_INSTANCE_ID, BENCH_ECHO_METHOD,
                                       [this](const std::shared_ptr<vsomeip::message>& _request) { on_echo(_request); });
        app_->register_message_handler(BENCH_SERVICE_ID, BENCH_INSTANCE_ID, BENCH_SINK_METHOD,
                                       [this](const std::shared_ptr<vsomeip::message>& _request) { on_sink(_request); });

        app_->offer_service(BENCH_SERVICE_ID, BENCH_INSTANCE_ID);

        wall_start_ = bench::clock_t_::now();
        cpu_start_ = bench::cpu_seconds();

        std::printf("[bench-service] offering %04x/%04x, echo=%04x sink=%04x\n", BENCH_SERVICE_ID, BENCH_INSTANCE_ID,
                    BENCH_ECHO_METHOD, BENCH_SINK_METHOD);
        std::fflush(stdout);
        return true;
    }

    void start() { app_->start(); }

    void stop() {
        report();
        app_->clear_all_handler();
        app_->stop_offer_service(BENCH_SERVICE_ID, BENCH_INSTANCE_ID);
        app_->stop();
    }

    void report() {
        const double its_wall = bench::wall_seconds(wall_start_, bench::clock_t_::now());
        const double its_cpu = bench::cpu_seconds() - cpu_start_;
        // One machine-readable line, so a test script does not have to parse prose.
        std::printf("SERVICE_STATS requests=%llu bytes_in=%llu bytes_out=%llu wall_s=%.6f cpu_s=%.6f cpu_pct=%.2f\n",
                    static_cast<unsigned long long>(requests_), static_cast<unsigned long long>(bytes_in_),
                    static_cast<unsigned long long>(bytes_out_), its_wall, its_cpu,
                    its_wall > 0.0 ? 100.0 * its_cpu / its_wall : 0.0);
        std::fflush(stdout);
    }

private:
    void on_echo(const std::shared_ptr<vsomeip::message>& _request) {
        auto its_payload = _request->get_payload();
        const std::size_t its_size = its_payload ? its_payload->get_length() : 0U;
        account(its_size, its_size);

        auto its_response = vsomeip::runtime::get()->create_response(_request);
        its_response->set_payload(its_payload);
        app_->send(its_response);
    }

    void on_sink(const std::shared_ptr<vsomeip::message>& _request) {
        auto its_payload = _request->get_payload();
        account(its_payload ? its_payload->get_length() : 0U, ack_.size());

        auto its_response = vsomeip::runtime::get()->create_response(_request);
        auto its_ack = vsomeip::runtime::get()->create_payload();
        its_ack->set_data(ack_.data(), static_cast<vsomeip::length_t>(ack_.size()));
        its_response->set_payload(its_ack);
        app_->send(its_response);
    }

    void account(std::size_t _in, std::size_t _out) {
        ++requests_;
        bytes_in_ += _in;
        bytes_out_ += _out;
    }

    std::string name_;
    std::shared_ptr<vsomeip::application> app_;
    // 8 byte acknowledgement (parentheses: a braced list would build two elements).
    std::vector<vsomeip::byte_t> ack_ = std::vector<vsomeip::byte_t>(8, 0xAB);
    std::uint64_t requests_{0};
    std::uint64_t bytes_in_{0};
    std::uint64_t bytes_out_{0};
    bench::clock_t_::time_point wall_start_{};
    double cpu_start_{0.0};
};

static bench_service* g_service = nullptr;

static void handle_signal(int) {
    if (g_service) {
        g_service->stop();
    }
}

int main(int argc, char** argv) {
    std::string its_name{"bench-service"};
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            its_name = argv[++i];
        }
    }

    bench_service its_service(its_name);
    g_service = &its_service;

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    if (!its_service.init()) {
        return 1;
    }

    its_service.start();
    return 0;
}
