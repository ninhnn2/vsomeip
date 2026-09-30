// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <sys/resource.h>

#include <chrono>
#include <cstdint>
#include <string>

// Service used by the DTLS benchmark. ECHO returns a response of the same size,
// so a client can measure round-trip latency; SINK answers with a fixed 8 byte
// acknowledgement, so a client can measure one-way payload throughput.
#define BENCH_SERVICE_ID  0x1234
#define BENCH_INSTANCE_ID 0x5678
#define BENCH_ECHO_METHOD 0x0421
#define BENCH_SINK_METHOD 0x0422

namespace bench {

using clock_t_ = std::chrono::steady_clock;

// Process CPU time, so a measurement can be attributed to one endpoint instead
// of to whatever else the machine was doing.
inline double cpu_seconds() {
    rusage its_usage{};
    if (getrusage(RUSAGE_SELF, &its_usage) != 0) {
        return 0.0;
    }

    const auto to_seconds = [](const timeval& _tv) {
        return static_cast<double>(_tv.tv_sec) + static_cast<double>(_tv.tv_usec) / 1e6;
    };

    return to_seconds(its_usage.ru_utime) + to_seconds(its_usage.ru_stime);
}

inline double wall_seconds(const clock_t_::time_point& _start, const clock_t_::time_point& _end) {
    return std::chrono::duration<double>(_end - _start).count();
}

} // namespace bench
