
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_TEST_SPEC_HPP_INCLUDED
#define CATCH_TEST_SPEC_HPP_INCLUDED

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#endif

#include <catch2/internal/catch_unique_ptr.hpp>
#include <catch2/internal/catch_wildcard_pattern.hpp>

#include <string>
#include <vector>

namespace Catch {

    struct IConfig;
    struct TestCaseInfo;
    class TestCaseHandle;

    class TestSpec {

        class Pattern {
        public:
            explicit Pattern( std::string const& name );
            virtual ~Pattern();
            virtual bool matches( TestCaseInfo const& testCase ) const = 0;
            std::string const& name() const;
        private:
            std::string const m_name;
        };

        class NamePattern : public Pattern {
        public:
            explicit NamePattern( std::string const& name, std::string const& filterString );
            bool matches( TestCaseInfo const& testCase ) const override;
        private:
            WildcardPattern m_wildcardPattern;
        };

        class TagPattern : public Pattern {
        public:
            explicit TagPattern( std::string const& tag, std::string const& filterString );
            bool matches( TestCaseInfo const& testCase ) const override;
        private:
            std::string m_tag;
        };

        struct Filter {
            std::vector<Detail::unique_ptr<Pattern>> m_required;
            std::vector<Detail::unique_ptr<Pattern>> m_forbidden;

            bool matches( TestCaseInfo const& testCase ) const;
            std::string name() const;
        };

    public:
        struct FilterMatch {
            std::string name;
            std::vector<TestCaseHandle const*> tests;
        };
        using Matches = std::vector<FilterMatch>;
        using vectorStrings = std::vector<std::string>;

        bool hasFilters() const;
        bool matches( TestCaseInfo const& testCase ) const;
        Matches matchesByFilter( std::vector<TestCaseHandle> const& testCases, IConfig const& config ) const;
        const vectorStrings & getInvalidArgs() const;

    private:
        std::vector<Filter> m_filters;
        std::vector<std::string> m_invalidArgs;
        friend class TestSpecParser;
    };
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif // CATCH_TEST_SPEC_HPP_INCLUDED
