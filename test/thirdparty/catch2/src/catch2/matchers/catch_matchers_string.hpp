
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_MATCHERS_STRING_HPP_INCLUDED
#define CATCH_MATCHERS_STRING_HPP_INCLUDED

#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/internal/catch_case_sensitive.hpp>
#include <catch2/internal/catch_stringref.hpp>

#include <string>

namespace Catch {
namespace Matchers {

    struct CasedString {
        CasedString( std::string const& str, CaseSensitive caseSensitivity );
        std::string adjustString( std::string const& str ) const;
        StringRef caseSensitivitySuffix() const;

        CaseSensitive m_caseSensitivity;
        std::string m_str;
    };

    struct StringMatcherBase : MatcherBase<std::string> {
        StringMatcherBase( std::string const& operation, CasedString const& comparator );
        std::string describe() const override;

        CasedString m_comparator;
        std::string m_operation;
    };

    struct StringEqualsMatcher final : StringMatcherBase {
        StringEqualsMatcher( CasedString const& comparator );
        bool match( std::string const& source ) const override;
    };
    struct StringContainsMatcher final : StringMatcherBase {
        StringContainsMatcher( CasedString const& comparator );
        bool match( std::string const& source ) const override;
    };
    struct StartsWithMatcher final : StringMatcherBase {
        StartsWithMatcher( CasedString const& comparator );
        bool match( std::string const& source ) const override;
    };
    struct EndsWithMatcher final : StringMatcherBase {
        EndsWithMatcher( CasedString const& comparator );
        bool match( std::string const& source ) const override;
    };

    struct RegexMatcher final : MatcherBase<std::string> {
        RegexMatcher( std::string regex, CaseSensitive caseSensitivity );
        bool match( std::string const& matchee ) const override;
        std::string describe() const override;

    private:
        std::string m_regex;
        CaseSensitive m_caseSensitivity;
    };

    //! Creates matcher that accepts strings that are exactly equal to `str`
    StringEqualsMatcher Equals( std::string const& str, CaseSensitive caseSensitivity = CaseSensitive::Yes );
    //! Creates matcher that accepts strings that contain `str`
    StringContainsMatcher Contains( std::string const& str, CaseSensitive caseSensitivity = CaseSensitive::Yes );
    //! Creates matcher that accepts strings that _end_ with `str`
    EndsWithMatcher EndsWith( std::string const& str, CaseSensitive caseSensitivity = CaseSensitive::Yes );
    //! Creates matcher that accepts strings that _start_ with `str`
    StartsWithMatcher StartsWith( std::string const& str, CaseSensitive caseSensitivity = CaseSensitive::Yes );
    //! Creates matcher that accepts strings matching `regex`
    RegexMatcher Matches( std::string const& regex, CaseSensitive caseSensitivity = CaseSensitive::Yes );

} // namespace Matchers
} // namespace Catch

#endif // CATCH_MATCHERS_STRING_HPP_INCLUDED
