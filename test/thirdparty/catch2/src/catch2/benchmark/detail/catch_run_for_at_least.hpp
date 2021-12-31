
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_RUN_FOR_AT_LEAST_HPP_INCLUDED
#define CATCH_RUN_FOR_AT_LEAST_HPP_INCLUDED

#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/catch_chronometer.hpp>
#include <catch2/benchmark/detail/catch_measure.hpp>
#include <catch2/benchmark/detail/catch_complete_invoke.hpp>
#include <catch2/benchmark/detail/catch_timing.hpp>
#include <catch2/internal/catch_meta.hpp>

#include <utility>
#include <type_traits>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            template <typename Clock, typename Fun>
            TimingOf<Clock, Fun, int> measure_one(Fun&& fun, int iters, std::false_type) {
                return Detail::measure<Clock>(fun, iters);
            }
            template <typename Clock, typename Fun>
            TimingOf<Clock, Fun, Chronometer> measure_one(Fun&& fun, int iters, std::true_type) {
                Detail::ChronometerModel<Clock> meter;
                auto&& result = Detail::complete_invoke(fun, Chronometer(meter, iters));

                return { meter.elapsed(), std::move(result), iters };
            }

            template <typename Clock, typename Fun>
            using run_for_at_least_argument_t = typename std::conditional<is_callable<Fun(Chronometer)>::value, Chronometer, int>::type;


            [[noreturn]]
            void throw_optimized_away_error();

            template <typename Clock, typename Fun>
            TimingOf<Clock, Fun, run_for_at_least_argument_t<Clock, Fun>> run_for_at_least(ClockDuration<Clock> how_long, int seed, Fun&& fun) {
                auto iters = seed;
                while (iters < (1 << 30)) {
                    auto&& Timing = measure_one<Clock>(fun, iters, is_callable<Fun(Chronometer)>());

                    if (Timing.elapsed >= how_long) {
                        return { Timing.elapsed, std::move(Timing.result), iters };
                    }
                    iters *= 2;
                }
                throw_optimized_away_error();
            }
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_RUN_FOR_AT_LEAST_HPP_INCLUDED
