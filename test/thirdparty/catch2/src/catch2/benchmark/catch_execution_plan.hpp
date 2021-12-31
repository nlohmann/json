
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_EXECUTION_PLAN_HPP_INCLUDED
#define CATCH_EXECUTION_PLAN_HPP_INCLUDED

#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/catch_environment.hpp>
#include <catch2/benchmark/detail/catch_benchmark_function.hpp>
#include <catch2/benchmark/detail/catch_repeat.hpp>
#include <catch2/benchmark/detail/catch_run_for_at_least.hpp>

#include <algorithm>

namespace Catch {
    namespace Benchmark {
        template <typename Duration>
        struct ExecutionPlan {
            int iterations_per_sample;
            Duration estimated_duration;
            Detail::BenchmarkFunction benchmark;
            Duration warmup_time;
            int warmup_iterations;

            template <typename Duration2>
            operator ExecutionPlan<Duration2>() const {
                return { iterations_per_sample, estimated_duration, benchmark, warmup_time, warmup_iterations };
            }

            template <typename Clock>
            std::vector<FloatDuration<Clock>> run(const IConfig &cfg, Environment<FloatDuration<Clock>> env) const {
                // warmup a bit
                Detail::run_for_at_least<Clock>(std::chrono::duration_cast<ClockDuration<Clock>>(warmup_time), warmup_iterations, Detail::repeat(now<Clock>{}));

                std::vector<FloatDuration<Clock>> times;
                times.reserve(cfg.benchmarkSamples());
                std::generate_n(std::back_inserter(times), cfg.benchmarkSamples(), [this, env] {
                    Detail::ChronometerModel<Clock> model;
                    this->benchmark(Chronometer(model, iterations_per_sample));
                    auto sample_time = model.elapsed() - env.clock_cost.mean;
                    if (sample_time < FloatDuration<Clock>::zero()) sample_time = FloatDuration<Clock>::zero();
                    return sample_time / iterations_per_sample;
                });
                return times;
            }
        };
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_EXECUTION_PLAN_HPP_INCLUDED
