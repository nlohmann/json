
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_COMPLETE_INVOKE_HPP_INCLUDED
#define CATCH_COMPLETE_INVOKE_HPP_INCLUDED

#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_meta.hpp>
#include <catch2/interfaces/catch_interfaces_capture.hpp>
#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>

#include <type_traits>
#include <utility>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            template <typename T>
            struct CompleteType { using type = T; };
            template <>
            struct CompleteType<void> { struct type {}; };

            template <typename T>
            using CompleteType_t = typename CompleteType<T>::type;

            template <typename Result>
            struct CompleteInvoker {
                template <typename Fun, typename... Args>
                static Result invoke(Fun&& fun, Args&&... args) {
                    return std::forward<Fun>(fun)(std::forward<Args>(args)...);
                }
            };
            template <>
            struct CompleteInvoker<void> {
                template <typename Fun, typename... Args>
                static CompleteType_t<void> invoke(Fun&& fun, Args&&... args) {
                    std::forward<Fun>(fun)(std::forward<Args>(args)...);
                    return {};
                }
            };

            // invoke and not return void :(
            template <typename Fun, typename... Args>
            CompleteType_t<FunctionReturnType<Fun, Args...>> complete_invoke(Fun&& fun, Args&&... args) {
                return CompleteInvoker<FunctionReturnType<Fun, Args...>>::invoke(std::forward<Fun>(fun), std::forward<Args>(args)...);
            }

            extern const std::string benchmarkErrorMsg;
        } // namespace Detail

        template <typename Fun>
        Detail::CompleteType_t<FunctionReturnType<Fun>> user_code(Fun&& fun) {
            CATCH_TRY{
                return Detail::complete_invoke(std::forward<Fun>(fun));
            } CATCH_CATCH_ALL{
                getResultCapture().benchmarkFailed(translateActiveException());
                CATCH_RUNTIME_ERROR(Detail::benchmarkErrorMsg);
            }
        }
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_COMPLETE_INVOKE_HPP_INCLUDED
