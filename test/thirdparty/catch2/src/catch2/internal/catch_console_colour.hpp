
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_CONSOLE_COLOUR_HPP_INCLUDED
#define CATCH_CONSOLE_COLOUR_HPP_INCLUDED

#include <catch2/internal/catch_common.hpp>

namespace Catch {

    struct Colour {
        enum Code {
            None = 0,

            White,
            Red,
            Green,
            Blue,
            Cyan,
            Yellow,
            Grey,

            Bright = 0x10,

            BrightRed = Bright | Red,
            BrightGreen = Bright | Green,
            LightGrey = Bright | Grey,
            BrightWhite = Bright | White,
            BrightYellow = Bright | Yellow,

            // By intention
            FileName = LightGrey,
            Warning = BrightYellow,
            ResultError = BrightRed,
            ResultSuccess = BrightGreen,
            ResultExpectedFailure = Warning,

            Error = BrightRed,
            Success = Green,

            OriginalExpression = Cyan,
            ReconstructedExpression = BrightYellow,

            SecondaryText = LightGrey,
            Headers = White
        };

        // Use constructed object for RAII guard
        Colour( Code _colourCode );
        Colour( Colour&& other ) noexcept;
        Colour& operator=( Colour&& other ) noexcept;
        ~Colour();

        // Use static method for one-shot changes
        static void use( Code _colourCode );

    private:
        bool m_moved = false;

        friend std::ostream& operator << (std::ostream& os, Colour const&);
    };


} // end namespace Catch

#endif // CATCH_CONSOLE_COLOUR_HPP_INCLUDED
