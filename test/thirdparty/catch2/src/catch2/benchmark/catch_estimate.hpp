
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_ESTIMATE_HPP_INCLUDED
#define CATCH_ESTIMATE_HPP_INCLUDED

namespace Catch {
    namespace Benchmark {
        template <typename Duration>
        struct Estimate {
            Duration point;
            Duration lower_bound;
            Duration upper_bound;
            double confidence_interval;

            template <typename Duration2>
            operator Estimate<Duration2>() const {
                return { point, lower_bound, upper_bound, confidence_interval };
            }
        };
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_ESTIMATE_HPP_INCLUDED
