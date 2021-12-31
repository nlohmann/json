
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_REPEAT_HPP_INCLUDED
#define CATCH_REPEAT_HPP_INCLUDED

#include <type_traits>
#include <utility>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            template <typename Fun>
            struct repeater {
                void operator()(int k) const {
                    for (int i = 0; i < k; ++i) {
                        fun();
                    }
                }
                Fun fun;
            };
            template <typename Fun>
            repeater<typename std::decay<Fun>::type> repeat(Fun&& fun) {
                return { std::forward<Fun>(fun) };
            }
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_REPEAT_HPP_INCLUDED
