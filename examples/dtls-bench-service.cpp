// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "dtls-bench-common.hpp"

// Echo / sink service for the DTLS benchmark. It keeps no per-request state, so
// the CPU time it reports on exit is the cost of receiving, dispatching and
// answering the traffic the client generated.
//
//   --name N        vsomeip application name (default bench-service)
//   --progress-s P  print a SERVICE_PROGRESS line every P seconds while traffic
//                   is arriving (default 1, 0 turns it off)
class bench_service {
public:
    bench_service(std::string _name, std::uint32_t _progress_s) :
        name_(std::move(_name)), progress_s_(_progress_s),
        app_(vsomeip::runtime::get()->create_application(name_)) { }

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

    void start() {
        if (progress_s_ != 0) {
            progress_ = std::thread([this]() { watch(); });
        }
        app_->start();
        stop_progress();
    }

    void stop() {
        stop_progress();
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
    // Only prints when something arrived, so an idle service stays quiet.
    void watch() {
        std::uint64_t its_last = 0;
        while (!stopping_) {
            for (std::uint32_t i = 0; i < progress_s_ * 10U && !stopping_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            const std::uint64_t its_requests = requests_;
            if (stopping_ || its_requests == its_last) {
                continue;
            }
            std::printf("SERVICE_PROGRESS requests=%llu bytes_in=%llu bytes_out=%llu last_%us=%llu\n",
                        static_cast<unsigned long long>(its_requests), static_cast<unsigned long long>(bytes_in_),
                        static_cast<unsigned long long>(bytes_out_), progress_s_,
                        static_cast<unsigned long long>(its_requests - its_last));
            std::fflush(stdout);
            its_last = its_requests;
        }
    }

    void stop_progress() {
        stopping_ = true;
        if (progress_.joinable()) {
            progress_.join();
        }
    }

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
    std::uint32_t progress_s_{1};
    std::shared_ptr<vsomeip::application> app_;
    // 8 byte acknowledgement (parentheses: a braced list would build two elements).
    std::vector<vsomeip::byte_t> ack_ = std::vector<vsomeip::byte_t>(8, 0xAB);
    std::uint64_t requests_{0};
    std::uint64_t bytes_in_{0};
    std::uint64_t bytes_out_{0};
    std::atomic<bool> stopping_{false};
    std::thread progress_;
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
    std::uint32_t its_progress_s{1};
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            its_name = argv[++i];
        } else if (std::strcmp(argv[i], "--progress-s") == 0 && i + 1 < argc) {
            its_progress_s = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        }
    }

    bench_service its_service(its_name, its_progress_s);
    g_service = &its_service;

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    if (!its_service.init()) {
        return 1;
    }

    its_service.start();
    return 0;
}
