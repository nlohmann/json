
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_TIMING_HPP_INCLUDED
#define CATCH_TIMING_HPP_INCLUDED

#include <catch2/benchmark/catch_clock.hpp>
#include <catch2/benchmark/detail/catch_complete_invoke.hpp>

#include <type_traits>

namespace Catch {
    namespace Benchmark {
        template <typename Duration, typename Result>
        struct Timing {
            Duration elapsed;
            Result result;
            int iterations;
        };
        template <typename Clock, typename Func, typename... Args>
        using TimingOf = Timing<ClockDuration<Clock>, Detail::CompleteType_t<FunctionReturnType<Func, Args...>>>;
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_TIMING_HPP_INCLUDED
