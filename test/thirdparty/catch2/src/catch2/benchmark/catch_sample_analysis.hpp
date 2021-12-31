
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_SAMPLE_ANALYSIS_HPP_INCLUDED
#define CATCH_SAMPLE_ANALYSIS_HPP_INCLUDED

#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/catch_estimate.hpp>
#include <catch2/benchmark/catch_outlier_classification.hpp>

#include <algorithm>
#include <vector>
#include <string>
#include <iterator>

namespace Catch {
    namespace Benchmark {
        template <typename Duration>
        struct SampleAnalysis {
            std::vector<Duration> samples;
            Estimate<Duration> mean;
            Estimate<Duration> standard_deviation;
            OutlierClassification outliers;
            double outlier_variance;

            template <typename Duration2>
            operator SampleAnalysis<Duration2>() const {
                std::vector<Duration2> samples2;
                samples2.reserve(samples.size());
                std::transform(samples.begin(), samples.end(), std::back_inserter(samples2), [](Duration d) { return Duration2(d); });
                return {
                    std::move(samples2),
                    mean,
                    standard_deviation,
                    outliers,
                    outlier_variance,
                };
            }
        };
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_SAMPLE_ANALYSIS_HPP_INCLUDED
