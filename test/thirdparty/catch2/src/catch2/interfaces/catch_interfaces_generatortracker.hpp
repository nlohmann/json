
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_INTERFACES_GENERATORTRACKER_HPP_INCLUDED
#define CATCH_INTERFACES_GENERATORTRACKER_HPP_INCLUDED

#include <catch2/internal/catch_unique_ptr.hpp>

namespace Catch {

    namespace Generators {
        class GeneratorUntypedBase {
        public:
            GeneratorUntypedBase() = default;
            // Generation of copy ops is deprecated (and Clang will complain)
            // if there is a user destructor defined
            GeneratorUntypedBase(GeneratorUntypedBase const&) = default;
            GeneratorUntypedBase& operator=(GeneratorUntypedBase const&) = default;

            virtual ~GeneratorUntypedBase(); // = default;

            // Attempts to move the generator to the next element
            //
            // Returns true iff the move succeeded (and a valid element
            // can be retrieved).
            virtual bool next() = 0;
        };
        using GeneratorBasePtr = Catch::Detail::unique_ptr<GeneratorUntypedBase>;

    } // namespace Generators

    struct IGeneratorTracker {
        virtual ~IGeneratorTracker(); // = default;
        virtual auto hasGenerator() const -> bool = 0;
        virtual auto getGenerator() const -> Generators::GeneratorBasePtr const& = 0;
        virtual void setGenerator( Generators::GeneratorBasePtr&& generator ) = 0;
    };

} // namespace Catch

#endif // CATCH_INTERFACES_GENERATORTRACKER_HPP_INCLUDED
