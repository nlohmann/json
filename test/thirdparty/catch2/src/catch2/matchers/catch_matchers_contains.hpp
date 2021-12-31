
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_MATCHERS_CONTAINS_HPP_INCLUDED
#define CATCH_MATCHERS_CONTAINS_HPP_INCLUDED

#include <catch2/matchers/catch_matchers_templated.hpp>

#include <algorithm>
#include <functional>
#include <utility>

namespace Catch {
    namespace Matchers {
        //! Matcher for checking that an element in range is equal to specific element
        template <typename T, typename Equality>
        class ContainsElementMatcher final : public MatcherGenericBase {
            T m_desired;
            Equality m_eq;
        public:
            template <typename T2, typename Equality2>
            ContainsElementMatcher(T2&& target, Equality2&& predicate):
                m_desired(std::forward<T2>(target)),
                m_eq(std::forward<Equality2>(predicate))
            {}

            std::string describe() const override {
                return "contains element " + Catch::Detail::stringify(m_desired);
            }

            template <typename RangeLike>
            bool match(RangeLike&& rng) const {
                using std::begin; using std::end;

                return end(rng) != std::find_if(begin(rng), end(rng),
                                               [&](auto const& elem) {
                                                    return m_eq(elem, m_desired);
                                               });
            }
        };

        //! Meta-matcher for checking that an element in a range matches a specific matcher
        template <typename Matcher>
        class ContainsMatcherMatcher final : public MatcherGenericBase {
            Matcher m_matcher;
        public:
            // Note that we do a copy+move to avoid having to SFINAE this
            // constructor (and also avoid some perfect forwarding failure
            // cases)
            ContainsMatcherMatcher(Matcher matcher):
                m_matcher(std::move(matcher))
            {}

            template <typename RangeLike>
            bool match(RangeLike&& rng) const {
                using std::begin; using std::endl;
                for (auto&& elem : rng) {
                    if (m_matcher.match(elem)) {
                        return true;
                    }
                }
                return false;
            }

            std::string describe() const override {
                return "contains element matching " + m_matcher.describe();
            }
        };

        /**
         * Creates a matcher that checks whether a range contains a specific element.
         *
         * Uses `std::equal_to` to do the comparison
         */
        template <typename T>
        std::enable_if_t<!Detail::is_matcher<T>::value,
        ContainsElementMatcher<T, std::equal_to<>>> Contains(T&& elem) {
            return { std::forward<T>(elem), std::equal_to<>{} };
        }

        //! Creates a matcher that checks whether a range contains element matching a matcher
        template <typename Matcher>
        std::enable_if_t<Detail::is_matcher<Matcher>::value,
        ContainsMatcherMatcher<Matcher>> Contains(Matcher&& matcher) {
            return { std::forward<Matcher>(matcher) };
        }

        /**
         * Creates a matcher that checks whether a range contains a specific element.
         *
         * Uses `eq` to do the comparisons
         */
        template <typename T, typename Equality>
        ContainsElementMatcher<T, Equality> Contains(T&& elem, Equality&& eq) {
            return { std::forward<T>(elem), std::forward<Equality>(eq) };
        }

    }
}

#endif // CATCH_MATCHERS_CONTAINS_HPP_INCLUDED
