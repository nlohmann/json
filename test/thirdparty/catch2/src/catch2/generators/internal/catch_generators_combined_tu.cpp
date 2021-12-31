
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small generator-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

////////////////////////////////////////////////////
// vvv formerly catch_generator_exception.cpp vvv //
////////////////////////////////////////////////////

#include <catch2/generators/catch_generator_exception.hpp>

namespace Catch {

    const char* GeneratorException::what() const noexcept {
        return m_msg;
    }

} // end namespace Catch


///////////////////////////////////////////
// vvv formerly catch_generators.cpp vvv //
///////////////////////////////////////////

#include <catch2/generators/catch_generators.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/generators/catch_generator_exception.hpp>
#include <catch2/interfaces/catch_interfaces_capture.hpp>

namespace Catch {

    IGeneratorTracker::~IGeneratorTracker() = default;

namespace Generators {

namespace Detail {

    [[noreturn]]
    void throw_generator_exception(char const* msg) {
        Catch::throw_exception(GeneratorException{ msg });
    }
} // end namespace Detail

    GeneratorUntypedBase::~GeneratorUntypedBase() = default;

    auto acquireGeneratorTracker(StringRef generatorName, SourceLineInfo const& lineInfo ) -> IGeneratorTracker& {
        return getResultCapture().acquireGeneratorTracker( generatorName, lineInfo );
    }

} // namespace Generators
} // namespace Catch
