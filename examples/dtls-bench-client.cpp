// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "dtls-bench-common.hpp"

// Benchmark driver for the DTLS transport. One process measures one payload size,
// so the reported CPU time belongs to that size alone.
//
//   --size N        payload bytes per request (default 1400, the AUTOSAR maximum
//                   for a single UDP SOME/IP message)
//   --iters K       number of requests (default 200)
//   --mode M        echo (response carries the same payload, measures round trip)
//                   or sink (response is an 8 byte ack, measures upload throughput)
//   --timeout-ms T  per-request response timeout (default 5000)
//   --warmup W      requests excluded from the statistics (default 5)
//   --label L       free text copied into the result line
class bench_client {
public:
    struct options {
        std::size_t size{1400};
        std::size_t iters{200};
        std::size_t warmup{5};
        std::uint32_t timeout_ms{5000};
        std::string mode{"echo"};
        std::string label{"run"};
    };

    explicit bench_client(options _options) :
        options_(std::move(_options)), app_(vsomeip::runtime::get()->create_application("bench-client")) { }

    bool init() {
        if (!app_->init()) {
            std::fprintf(stderr, "[bench-client] init failed\n");
            return false;
        }

        method_ = options_.mode == "sink" ? BENCH_SINK_METHOD : BENCH_ECHO_METHOD;
        payload_.assign(options_.size, 0x5A);
        rtts_.reserve(options_.iters);

        app_->register_state_handler([this](vsomeip::state_type_e _state) {
            if (_state == vsomeip::state_type_e::ST_REGISTERED) {
                app_->request_service(BENCH_SERVICE_ID, BENCH_INSTANCE_ID);
            }
        });

        app_->register_availability_handler(BENCH_SERVICE_ID, BENCH_INSTANCE_ID,
                                            [this](vsomeip::service_t, vsomeip::instance_t, bool _available) {
                                                if (_available && !available_.exchange(true)) {
                                                    std::lock_guard<std::mutex> its_lock(mutex_);
                                                    condition_.notify_all();
                                                }
                                            });

        app_->register_message_handler(BENCH_SERVICE_ID, BENCH_INSTANCE_ID, vsomeip::ANY_METHOD,
                                       [this](const std::shared_ptr<vsomeip::message>& _response) { on_response(_response); });
        return true;
    }

    int run() {
        std::thread its_sender([this]() { drive(); });
        app_->start();
        if (its_sender.joinable()) {
            its_sender.join();
        }
        return failures_ == options_.iters ? 2 : 0;
    }

private:
    void on_response(const std::shared_ptr<vsomeip::message>& _response) {
        auto its_payload = _response->get_payload();
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            response_bytes_ = its_payload ? its_payload->get_length() : 0U;
            responded_ = true;
        }
        condition_.notify_all();
    }

    void drive() {
        // Wait until the remote service has been discovered.
        {
            std::unique_lock<std::mutex> its_lock(mutex_);
            if (!condition_.wait_for(its_lock, std::chrono::seconds(20), [this]() { return available_.load(); })) {
                std::fprintf(stderr, "[bench-client] service %04x/%04x never became available\n", BENCH_SERVICE_ID,
                             BENCH_INSTANCE_ID);
                app_->stop();
                return;
            }
        }

        auto its_request = vsomeip::runtime::get()->create_request(false); // false: UDP
        its_request->set_service(BENCH_SERVICE_ID);
        its_request->set_instance(BENCH_INSTANCE_ID);
        its_request->set_method(method_);

        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(payload_.data(), static_cast<vsomeip::length_t>(payload_.size()));
        its_request->set_payload(its_payload);

        const std::size_t its_total = options_.iters + options_.warmup;
        double its_cpu_start = 0.0;
        bench::clock_t_::time_point its_wall_start{};

        for (std::size_t i = 0; i < its_total; ++i) {
            const bool its_measured = i >= options_.warmup;
            if (its_measured && i == options_.warmup) {
                its_cpu_start = bench::cpu_seconds();
                its_wall_start = bench::clock_t_::now();
            }

            {
                std::lock_guard<std::mutex> its_lock(mutex_);
                responded_ = false;
                response_bytes_ = 0;
            }

            const auto its_sent = bench::clock_t_::now();
            app_->send(its_request);

            bool its_ok;
            {
                std::unique_lock<std::mutex> its_lock(mutex_);
                its_ok = condition_.wait_for(its_lock, std::chrono::milliseconds(options_.timeout_ms),
                                             [this]() { return responded_; });
            }
            const auto its_received = bench::clock_t_::now();

            if (!its_measured) {
                continue;
            }

            if (its_ok) {
                rtts_.push_back(std::chrono::duration<double, std::micro>(its_received - its_sent).count());
            } else {
                ++failures_;
            }
        }

        const double its_wall = bench::wall_seconds(its_wall_start, bench::clock_t_::now());
        const double its_cpu = bench::cpu_seconds() - its_cpu_start;
        report(its_wall, its_cpu);

        app_->clear_all_handler();
        app_->release_service(BENCH_SERVICE_ID, BENCH_INSTANCE_ID);
        app_->stop();
    }

    static double percentile(std::vector<double>& _sorted, double _p) {
        if (_sorted.empty()) {
            return 0.0;
        }
        const auto its_index = static_cast<std::size_t>(_p * static_cast<double>(_sorted.size() - 1) + 0.5);
        return _sorted[std::min(its_index, _sorted.size() - 1)];
    }

    void report(double _wall, double _cpu) {
        std::vector<double> its_sorted(rtts_);
        std::sort(its_sorted.begin(), its_sorted.end());

        double its_sum = 0.0;
        for (const double its_rtt : its_sorted) {
            its_sum += its_rtt;
        }
        const double its_mean = its_sorted.empty() ? 0.0 : its_sum / static_cast<double>(its_sorted.size());

        // Payload actually carried: echo moves the payload in both directions.
        const double its_factor = method_ == BENCH_ECHO_METHOD ? 2.0 : 1.0;
        const double its_bytes = its_factor * static_cast<double>(options_.size) * static_cast<double>(its_sorted.size());
        const double its_mbps = _wall > 0.0 ? its_bytes / _wall / (1024.0 * 1024.0) : 0.0;

        std::printf("CLIENT_STATS label=%s mode=%s size=%zu iters=%zu ok=%zu fail=%zu "
                    "wall_s=%.6f cpu_s=%.6f cpu_pct=%.2f rtt_mean_us=%.1f rtt_min_us=%.1f rtt_p50_us=%.1f "
                    "rtt_p95_us=%.1f rtt_p99_us=%.1f rtt_max_us=%.1f throughput_MiBps=%.3f\n",
                    options_.label.c_str(), options_.mode.c_str(), options_.size, options_.iters, its_sorted.size(),
                    static_cast<std::size_t>(failures_), _wall, _cpu, _wall > 0.0 ? 100.0 * _cpu / _wall : 0.0, its_mean,
                    its_sorted.empty() ? 0.0 : its_sorted.front(), percentile(its_sorted, 0.50), percentile(its_sorted, 0.95),
                    percentile(its_sorted, 0.99), its_sorted.empty() ? 0.0 : its_sorted.back(), its_mbps);
        std::fflush(stdout);
    }

    options options_;
    std::shared_ptr<vsomeip::application> app_;
    std::vector<vsomeip::byte_t> payload_;
    std::vector<double> rtts_;
    vsomeip::method_t method_{BENCH_ECHO_METHOD};
    std::atomic<bool> available_{false};
    std::mutex mutex_;
    std::condition_variable condition_;
    bool responded_{false};
    std::size_t response_bytes_{0};
    std::atomic<std::size_t> failures_{0};
};

int main(int argc, char** argv) {
    bench_client::options its_options;
    for (int i = 1; i < argc; ++i) {
        const auto has_value = [&](const char* _flag) { return std::strcmp(argv[i], _flag) == 0 && i + 1 < argc; };
        if (has_value("--size")) {
            its_options.size = std::strtoul(argv[++i], nullptr, 10);
        } else if (has_value("--iters")) {
            its_options.iters = std::strtoul(argv[++i], nullptr, 10);
        } else if (has_value("--warmup")) {
            its_options.warmup = std::strtoul(argv[++i], nullptr, 10);
        } else if (has_value("--timeout-ms")) {
            its_options.timeout_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (has_value("--mode")) {
            its_options.mode = argv[++i];
        } else if (has_value("--label")) {
            its_options.label = argv[++i];
        }
    }

    bench_client its_client(std::move(its_options));
    if (!its_client.init()) {
        return 1;
    }

    return its_client.run();
}
