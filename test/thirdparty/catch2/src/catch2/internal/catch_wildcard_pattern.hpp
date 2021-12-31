
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_WILDCARD_PATTERN_HPP_INCLUDED
#define CATCH_WILDCARD_PATTERN_HPP_INCLUDED

#include <catch2/internal/catch_case_sensitive.hpp>

#include <string>

namespace Catch
{
    class WildcardPattern {
        enum WildcardPosition {
            NoWildcard = 0,
            WildcardAtStart = 1,
            WildcardAtEnd = 2,
            WildcardAtBothEnds = WildcardAtStart | WildcardAtEnd
        };

    public:

        WildcardPattern( std::string const& pattern, CaseSensitive caseSensitivity );
        virtual ~WildcardPattern() = default;
        virtual bool matches( std::string const& str ) const;

    private:
        std::string normaliseString( std::string const& str ) const;
        CaseSensitive m_caseSensitivity;
        WildcardPosition m_wildcard = NoWildcard;
        std::string m_pattern;
    };
}

#endif // CATCH_WILDCARD_PATTERN_HPP_INCLUDED
