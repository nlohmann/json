
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small benchmarking-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

////////////////////////////////////////////
// vvv formerly catch_chronometer.cpp vvv //
////////////////////////////////////////////

#include <catch2/benchmark/catch_chronometer.hpp>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            ChronometerConcept::~ChronometerConcept() = default;
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch


///////////////////////////////////////////////////
// vvv formerly catch_benchmark_function.cpp vvv //
///////////////////////////////////////////////////

#include <catch2/benchmark/detail/catch_benchmark_function.hpp>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            BenchmarkFunction::callable::~callable() = default;
            } // namespace Detail
    } // namespace Benchmark
} // namespace Catch


////////////////////////////////////////////////
// vvv formerly catch_complete_invoke.cpp vvv //
////////////////////////////////////////////////

#include <catch2/benchmark/detail/catch_complete_invoke.hpp>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            CATCH_INTERNAL_START_WARNINGS_SUPPRESSION
            CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS
            const std::string benchmarkErrorMsg = "a benchmark failed to run successfully";
            CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch




/////////////////////////////////////////////////
// vvv formerly catch_run_for_at_least.cpp vvv //
/////////////////////////////////////////////////

#include <catch2/benchmark/detail/catch_run_for_at_least.hpp>
#include <exception>
#include <catch2/internal/catch_enforce.hpp>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            struct optimized_away_error : std::exception {
                const char* what() const noexcept override;
            };

            const char* optimized_away_error::what() const noexcept {
                return "could not measure benchmark, maybe it was optimized away";
            }

            void throw_optimized_away_error() {
                Catch::throw_exception(optimized_away_error{});
            }

        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch
