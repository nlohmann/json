
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_BENCHMARK_HPP_INCLUDED
#define CATCH_BENCHMARK_HPP_INCLUDED

#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/internal/catch_context.hpp>
#include <catch2/interfaces/catch_interfaces_reporter.hpp>

#include <catch2/benchmark/catch_chronometer.hpp>
#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/catch_environment.hpp>
#include <catch2/benchmark/catch_execution_plan.hpp>
#include <catch2/benchmark/detail/catch_estimate_clock.hpp>
#include <catch2/benchmark/detail/catch_complete_invoke.hpp>
#include <catch2/benchmark/detail/catch_analyse.hpp>
#include <catch2/benchmark/detail/catch_benchmark_function.hpp>
#include <catch2/benchmark/detail/catch_run_for_at_least.hpp>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>
#include <cmath>

namespace Catch {
    namespace Benchmark {
        struct Benchmark {
            Benchmark(std::string&& benchmarkName)
                : name(std::move(benchmarkName)) {}

            template <class FUN>
            Benchmark(std::string&& benchmarkName , FUN &&func)
                : fun(std::move(func)), name(std::move(benchmarkName)) {}

            template <typename Clock>
            ExecutionPlan<FloatDuration<Clock>> prepare(const IConfig &cfg, Environment<FloatDuration<Clock>> env) const {
                auto min_time = env.clock_resolution.mean * Detail::minimum_ticks;
                auto run_time = std::max(min_time, std::chrono::duration_cast<decltype(min_time)>(cfg.benchmarkWarmupTime()));
                auto&& test = Detail::run_for_at_least<Clock>(std::chrono::duration_cast<ClockDuration<Clock>>(run_time), 1, fun);
                int new_iters = static_cast<int>(std::ceil(min_time * test.iterations / test.elapsed));
                return { new_iters, test.elapsed / test.iterations * new_iters * cfg.benchmarkSamples(), fun, std::chrono::duration_cast<FloatDuration<Clock>>(cfg.benchmarkWarmupTime()), Detail::warmup_iterations };
            }

            template <typename Clock = default_clock>
            void run() {
                auto const* cfg = getCurrentContext().getConfig();

                auto env = Detail::measure_environment<Clock>();

                getResultCapture().benchmarkPreparing(name);
                CATCH_TRY{
                    auto plan = user_code([&] {
                        return prepare<Clock>(*cfg, env);
                    });

                    BenchmarkInfo info {
                        name,
                        plan.estimated_duration.count(),
                        plan.iterations_per_sample,
                        cfg->benchmarkSamples(),
                        cfg->benchmarkResamples(),
                        env.clock_resolution.mean.count(),
                        env.clock_cost.mean.count()
                    };

                    getResultCapture().benchmarkStarting(info);

                    auto samples = user_code([&] {
                        return plan.template run<Clock>(*cfg, env);
                    });

                    auto analysis = Detail::analyse(*cfg, env, samples.begin(), samples.end());
                    BenchmarkStats<FloatDuration<Clock>> stats{ info, analysis.samples, analysis.mean, analysis.standard_deviation, analysis.outliers, analysis.outlier_variance };
                    getResultCapture().benchmarkEnded(stats);

                } CATCH_CATCH_ALL{
                    if (translateActiveException() != Detail::benchmarkErrorMsg) // benchmark errors have been reported, otherwise rethrow.
                        std::rethrow_exception(std::current_exception());
                }
            }

            // sets lambda to be used in fun *and* executes benchmark!
            template <typename Fun,
                typename std::enable_if<!Detail::is_related<Fun, Benchmark>::value, int>::type = 0>
                Benchmark & operator=(Fun func) {
                fun = Detail::BenchmarkFunction(func);
                run();
                return *this;
            }

            explicit operator bool() {
                return true;
            }

        private:
            Detail::BenchmarkFunction fun;
            std::string name;
        };
    }
} // namespace Catch

#define INTERNAL_CATCH_GET_1_ARG(arg1, arg2, ...) arg1
#define INTERNAL_CATCH_GET_2_ARG(arg1, arg2, ...) arg2

#define INTERNAL_CATCH_BENCHMARK(BenchmarkName, name, benchmarkIndex)\
    if( Catch::Benchmark::Benchmark BenchmarkName{name} ) \
        BenchmarkName = [&](int benchmarkIndex)

#define INTERNAL_CATCH_BENCHMARK_ADVANCED(BenchmarkName, name)\
    if( Catch::Benchmark::Benchmark BenchmarkName{name} ) \
        BenchmarkName = [&]

#if defined(CATCH_CONFIG_PREFIX_ALL)

#define CATCH_BENCHMARK(...) \
    INTERNAL_CATCH_BENCHMARK(INTERNAL_CATCH_UNIQUE_NAME(____C_A_T_C_H____B_E_N_C_H____), INTERNAL_CATCH_GET_1_ARG(__VA_ARGS__,,), INTERNAL_CATCH_GET_2_ARG(__VA_ARGS__,,))
#define CATCH_BENCHMARK_ADVANCED(name) \
    INTERNAL_CATCH_BENCHMARK_ADVANCED(INTERNAL_CATCH_UNIQUE_NAME(____C_A_T_C_H____B_E_N_C_H____), name)

#else

#define BENCHMARK(...) \
    INTERNAL_CATCH_BENCHMARK(INTERNAL_CATCH_UNIQUE_NAME(____C_A_T_C_H____B_E_N_C_H____), INTERNAL_CATCH_GET_1_ARG(__VA_ARGS__,,), INTERNAL_CATCH_GET_2_ARG(__VA_ARGS__,,))
#define BENCHMARK_ADVANCED(name) \
    INTERNAL_CATCH_BENCHMARK_ADVANCED(INTERNAL_CATCH_UNIQUE_NAME(____C_A_T_C_H____B_E_N_C_H____), name)

#endif

#endif // CATCH_BENCHMARK_HPP_INCLUDED
