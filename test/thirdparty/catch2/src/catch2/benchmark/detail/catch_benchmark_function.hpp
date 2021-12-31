
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
// Adapted from donated nonius code.

#ifndef CATCH_BENCHMARK_FUNCTION_HPP_INCLUDED
#define CATCH_BENCHMARK_FUNCTION_HPP_INCLUDED

#include <catch2/benchmark/catch_chronometer.hpp>
#include <catch2/benchmark/detail/catch_complete_invoke.hpp>
#include <catch2/internal/catch_meta.hpp>
#include <catch2/internal/catch_unique_ptr.hpp>

#include <cassert>
#include <type_traits>
#include <utility>

namespace Catch {
    namespace Benchmark {
        namespace Detail {
            template <typename T>
            using Decay = typename std::decay<T>::type;
            template <typename T, typename U>
            struct is_related
                : std::is_same<Decay<T>, Decay<U>> {};

            /// We need to reinvent std::function because every piece of code that might add overhead
            /// in a measurement context needs to have consistent performance characteristics so that we
            /// can account for it in the measurement.
            /// Implementations of std::function with optimizations that aren't always applicable, like
            /// small buffer optimizations, are not uncommon.
            /// This is effectively an implementation of std::function without any such optimizations;
            /// it may be slow, but it is consistently slow.
            struct BenchmarkFunction {
            private:
                struct callable {
                    virtual void call(Chronometer meter) const = 0;
                    virtual callable* clone() const = 0;
                    virtual ~callable(); // = default;

                    callable() = default;
                    callable(callable const&) = default;
                    callable& operator=(callable const&) = default;
                };
                template <typename Fun>
                struct model : public callable {
                    model(Fun&& fun_) : fun(std::move(fun_)) {}
                    model(Fun const& fun_) : fun(fun_) {}

                    model<Fun>* clone() const override { return new model<Fun>(*this); }

                    void call(Chronometer meter) const override {
                        call(meter, is_callable<Fun(Chronometer)>());
                    }
                    void call(Chronometer meter, std::true_type) const {
                        fun(meter);
                    }
                    void call(Chronometer meter, std::false_type) const {
                        meter.measure(fun);
                    }

                    Fun fun;
                };

                struct do_nothing { void operator()() const {} };

                template <typename T>
                BenchmarkFunction(model<T>* c) : f(c) {}

            public:
                BenchmarkFunction()
                    : f(new model<do_nothing>{ {} }) {}

                template <typename Fun,
                    typename std::enable_if<!is_related<Fun, BenchmarkFunction>::value, int>::type = 0>
                    BenchmarkFunction(Fun&& fun)
                    : f(new model<typename std::decay<Fun>::type>(std::forward<Fun>(fun))) {}

                BenchmarkFunction( BenchmarkFunction&& that ) noexcept:
                    f( std::move( that.f ) ) {}

                BenchmarkFunction(BenchmarkFunction const& that)
                    : f(that.f->clone()) {}

                BenchmarkFunction&
                operator=( BenchmarkFunction&& that ) noexcept {
                    f = std::move( that.f );
                    return *this;
                }

                BenchmarkFunction& operator=(BenchmarkFunction const& that) {
                    f.reset(that.f->clone());
                    return *this;
                }

                void operator()(Chronometer meter) const { f->call(meter); }

            private:
                Catch::Detail::unique_ptr<callable> f;
            };
        } // namespace Detail
    } // namespace Benchmark
} // namespace Catch

#endif // CATCH_BENCHMARK_FUNCTION_HPP_INCLUDED
