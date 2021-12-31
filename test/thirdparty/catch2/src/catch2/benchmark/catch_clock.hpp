
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_CLOCK_HPP_INCLUDED
#define CATCH_CLOCK_HPP_INCLUDED

#include <chrono>
#include <ratio>

namespace Catch {
    namespace Benchmark {
        template <typename Clock>
        using ClockDuration = typename Clock::duration;
        template <typename Clock>
        using FloatDuration = std::chrono::duration<double, typename Clock::period>;

        template <typename Clock>
        using TimePoint = typename Clock::time_point;

        using default_clock = std::chrono::steady_clock;

        template <typename Clock>
        struct now {
            TimePoint<Clock> operator()() const {
                return Clock::now();
            }
        };

        using fp_seconds = std::chrono::duration<double, std::ratio<1>>;
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_CLOCK_HPP_INCLUDED
