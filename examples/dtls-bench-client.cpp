// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <csignal>
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
//   --reliable      send over TCP (the service must offer a reliable port);
//                   with "tls" in the configuration that is TLS, otherwise plain TCP
//
// It also doubles as a traffic generator for a functional test:
//
//   --iters 0       keep sending until SIGINT/SIGTERM, then report as usual
//   --interval-ms I pause between requests (default 0: send as fast as possible)
//   --progress-s P  print a CLIENT_PROGRESS line every P seconds (default: 1 when
//                   --iters 0, off otherwise)
// Set from the signal handler so --iters 0 can be ended with Ctrl+C and still
// report. volatile sig_atomic_t is what a handler may touch portably.
static volatile std::sig_atomic_t g_stop = 0;

class bench_client {
public:
    struct options {
        std::size_t size{1400};
        std::size_t iters{200};
        std::size_t warmup{5};
        std::uint32_t timeout_ms{5000};
        std::string mode{"echo"};
        std::string label{"run"};
        std::uint32_t interval_ms{0};
        std::uint32_t progress_s{0};
        bool reliable{false};
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
        return (ok_ == 0 && attempts_ > 0) ? 2 : 0;
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

        auto its_request = vsomeip::runtime::get()->create_request(options_.reliable); // true: TCP
        its_request->set_service(BENCH_SERVICE_ID);
        its_request->set_instance(BENCH_INSTANCE_ID);
        its_request->set_method(method_);

        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(payload_.data(), static_cast<vsomeip::length_t>(payload_.size()));
        its_request->set_payload(its_payload);

        // iters 0 = run until a signal arrives; the warmup still applies.
        const bool its_forever = options_.iters == 0;
        const std::size_t its_total = its_forever ? 0 : options_.iters + options_.warmup;
        const auto its_progress_period = std::chrono::seconds(options_.progress_s);
        double its_cpu_start = 0.0;
        bench::clock_t_::time_point its_wall_start{};
        auto its_window_start = bench::clock_t_::now();
        auto its_next_progress = its_window_start + its_progress_period;
        std::vector<double> its_window;

        for (std::size_t i = 0; (its_forever || i < its_total) && g_stop == 0; ++i) {
            const bool its_measured = i >= options_.warmup;
            if (its_measured && i == options_.warmup) {
                its_cpu_start = bench::cpu_seconds();
                its_wall_start = bench::clock_t_::now();
                its_window_start = its_wall_start;
                its_next_progress = its_wall_start + its_progress_period;
            }

            std::size_t its_response_bytes = 0;
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
                its_response_bytes = response_bytes_;
            }
            const auto its_received = bench::clock_t_::now();

            if (its_measured) {
                ++attempts_;
                if (its_ok) {
                    ++ok_;
                    // An echo response must carry exactly what was sent back; a short
                    // one means the payload was truncated somewhere on the way.
                    if (method_ == BENCH_ECHO_METHOD && its_response_bytes != options_.size) {
                        ++short_responses_;
                    }
                    const double its_rtt = std::chrono::duration<double, std::micro>(its_received - its_sent).count();
                    // Cap the sample set so a run of --iters 0 cannot grow without bound.
                    if (rtts_.size() < MAX_SAMPLES) {
                        rtts_.push_back(its_rtt);
                    }
                    if (options_.progress_s != 0) {
                        its_window.push_back(its_rtt);
                    }
                } else {
                    ++failures_;
                }
            }

            if (options_.progress_s != 0 && its_measured && bench::clock_t_::now() >= its_next_progress) {
                progress(its_window, bench::wall_seconds(its_window_start, bench::clock_t_::now()),
                         bench::wall_seconds(its_wall_start, bench::clock_t_::now()));
                its_window.clear();
                its_window_start = bench::clock_t_::now();
                its_next_progress = its_window_start + its_progress_period;
            }

            // Pace the traffic in slices so a signal still ends the run promptly.
            for (std::uint32_t its_left = options_.interval_ms; its_left != 0 && g_stop == 0;) {
                const std::uint32_t its_slice = its_left < 100U ? its_left : 100U;
                std::this_thread::sleep_for(std::chrono::milliseconds(its_slice));
                its_left -= its_slice;
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

    // One line per period while the run is going, so a long run shows that data
    // keeps flowing instead of staying silent until the end.
    void progress(std::vector<double>& _window, double _window_s, double _total_s) {
        std::sort(_window.begin(), _window.end());
        const double its_factor = method_ == BENCH_ECHO_METHOD ? 2.0 : 1.0;
        const double its_bytes = its_factor * static_cast<double>(options_.size) * static_cast<double>(_window.size());
        std::printf("CLIENT_PROGRESS t=%.0fs ok=%zu fail=%zu rate=%.1f/s rtt_p50_us=%.1f throughput_MiBps=%.3f\n",
                    _total_s, static_cast<std::size_t>(ok_), static_cast<std::size_t>(failures_),
                    _window_s > 0.0 ? static_cast<double>(_window.size()) / _window_s : 0.0,
                    percentile(_window, 0.50), _window_s > 0.0 ? its_bytes / _window_s / (1024.0 * 1024.0) : 0.0);
        std::fflush(stdout);
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
        const double its_bytes = its_factor * static_cast<double>(options_.size) * static_cast<double>(ok_);
        const double its_mbps = _wall > 0.0 ? its_bytes / _wall / (1024.0 * 1024.0) : 0.0;

        std::printf("CLIENT_STATS label=%s mode=%s size=%zu iters=%zu ok=%zu fail=%zu "
                    "wall_s=%.6f cpu_s=%.6f cpu_pct=%.2f rtt_mean_us=%.1f rtt_min_us=%.1f rtt_p50_us=%.1f "
                    "rtt_p95_us=%.1f rtt_p99_us=%.1f rtt_max_us=%.1f throughput_MiBps=%.3f short_responses=%zu\n",
                    options_.label.c_str(), options_.mode.c_str(), options_.size,
                    static_cast<std::size_t>(attempts_), static_cast<std::size_t>(ok_),
                    static_cast<std::size_t>(failures_), _wall, _cpu, _wall > 0.0 ? 100.0 * _cpu / _wall : 0.0, its_mean,
                    its_sorted.empty() ? 0.0 : its_sorted.front(), percentile(its_sorted, 0.50), percentile(its_sorted, 0.95),
                    percentile(its_sorted, 0.99), its_sorted.empty() ? 0.0 : its_sorted.back(), its_mbps,
                    static_cast<std::size_t>(short_responses_));
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
    std::atomic<std::size_t> attempts_{0};
    std::atomic<std::size_t> ok_{0};
    std::atomic<std::size_t> short_responses_{0};
    static constexpr std::size_t MAX_SAMPLES = 1000000;
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
        } else if (has_value("--interval-ms")) {
            its_options.interval_ms = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (has_value("--progress-s")) {
            its_options.progress_s = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (std::strcmp(argv[i], "--reliable") == 0) {
            its_options.reliable = true;
        }
    }

    // A run without an iteration count needs a way out and something to watch.
    if (its_options.iters == 0 && its_options.progress_s == 0) {
        its_options.progress_s = 1;
    }
    std::signal(SIGINT, [](int) { g_stop = 1; });
    std::signal(SIGTERM, [](int) { g_stop = 1; });

    bench_client its_client(std::move(its_options));
    if (!its_client.init()) {
        return 1;
    }

    return its_client.run();
}
