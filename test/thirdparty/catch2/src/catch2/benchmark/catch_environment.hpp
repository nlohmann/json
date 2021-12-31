
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_ENVIRONMENT_HPP_INCLUDED
#define CATCH_ENVIRONMENT_HPP_INCLUDED

#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/catch_outlier_classification.hpp>

namespace Catch {
    namespace Benchmark {
        template <typename Duration>
        struct EnvironmentEstimate {
            Duration mean;
            OutlierClassification outliers;

            template <typename Duration2>
            operator EnvironmentEstimate<Duration2>() const {
                return { mean, outliers };
            }
        };
        template <typename Clock>
        struct Environment {
            using clock_type = Clock;
            EnvironmentEstimate<FloatDuration<Clock>> clock_resolution;
            EnvironmentEstimate<FloatDuration<Clock>> clock_cost;
        };
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_ENVIRONMENT_HPP_INCLUDED
