
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/catch_test_spec.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/catch_test_case_info.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace Catch {

    TestSpec::Pattern::Pattern( std::string const& name )
    : m_name( name )
    {}

    TestSpec::Pattern::~Pattern() = default;

    std::string const& TestSpec::Pattern::name() const {
        return m_name;
    }


    TestSpec::NamePattern::NamePattern( std::string const& name, std::string const& filterString )
    : Pattern( filterString )
    , m_wildcardPattern( toLower( name ), CaseSensitive::No )
    {}

    bool TestSpec::NamePattern::matches( TestCaseInfo const& testCase ) const {
        return m_wildcardPattern.matches( testCase.name );
    }


    TestSpec::TagPattern::TagPattern( std::string const& tag, std::string const& filterString )
    : Pattern( filterString )
    , m_tag( toLower( tag ) )
    {}

    bool TestSpec::TagPattern::matches( TestCaseInfo const& testCase ) const {
        return std::find_if(begin(testCase.tags),
                            end(testCase.tags),
                            [&](Tag const& tag) {
                                return tag.lowerCased == m_tag;
                            }) != end(testCase.tags);
    }

    bool TestSpec::Filter::matches( TestCaseInfo const& testCase ) const {
        bool should_use = !testCase.isHidden();
        for (auto const& pattern : m_required) {
            should_use = true;
            if (!pattern->matches(testCase)) {
                return false;
            }
        }
        for (auto const& pattern : m_forbidden) {
            if (pattern->matches(testCase)) {
                return false;
            }
        }
        return should_use;
    }

    std::string TestSpec::Filter::name() const {
        std::string name;
        for (auto const& p : m_required) {
            name += p->name();
        }
        for (auto const& p : m_forbidden) {
            name += p->name();
        }
        return name;
    }


    bool TestSpec::hasFilters() const {
        return !m_filters.empty();
    }

    bool TestSpec::matches( TestCaseInfo const& testCase ) const {
        return std::any_of( m_filters.begin(), m_filters.end(), [&]( Filter const& f ){ return f.matches( testCase ); } );
    }

    TestSpec::Matches TestSpec::matchesByFilter( std::vector<TestCaseHandle> const& testCases, IConfig const& config ) const
    {
        Matches matches( m_filters.size() );
        std::transform( m_filters.begin(), m_filters.end(), matches.begin(), [&]( Filter const& filter ){
            std::vector<TestCaseHandle const*> currentMatches;
            for( auto const& test : testCases )
                if( isThrowSafe( test, config ) && filter.matches( test.getTestCaseInfo() ) )
                    currentMatches.emplace_back( &test );
            return FilterMatch{ filter.name(), currentMatches };
        } );
        return matches;
    }

    const TestSpec::vectorStrings& TestSpec::getInvalidArgs() const{
        return  (m_invalidArgs);
    }

}
