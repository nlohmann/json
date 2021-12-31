
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_GENERATORS_HPP_INCLUDED
#define CATCH_GENERATORS_HPP_INCLUDED

#include <catch2/interfaces/catch_interfaces_generatortracker.hpp>
#include <catch2/internal/catch_common.hpp>
#include <catch2/internal/catch_stringref.hpp>

#include <vector>
#include <tuple>
#include <utility>

namespace Catch {

namespace Generators {

namespace Detail {

    //! Throws GeneratorException with the provided message
    [[noreturn]]
    void throw_generator_exception(char const * msg);

} // end namespace detail

    template<typename T>
    struct IGenerator : GeneratorUntypedBase {
        ~IGenerator() override = default;
        IGenerator() = default;
        IGenerator(IGenerator const&) = default;
        IGenerator& operator=(IGenerator const&) = default;


        // Returns the current element of the generator
        //
        // \Precondition The generator is either freshly constructed,
        // or the last call to `next()` returned true
        virtual T const& get() const = 0;
        using type = T;
    };

    template <typename T>
    using GeneratorPtr = Catch::Detail::unique_ptr<IGenerator<T>>;

    template <typename T>
    class GeneratorWrapper final {
        GeneratorPtr<T> m_generator;
    public:
        //! Takes ownership of the passed pointer.
        GeneratorWrapper(IGenerator<T>* generator):
            m_generator(generator) {}
        GeneratorWrapper(GeneratorPtr<T> generator):
            m_generator(std::move(generator)) {}

        T const& get() const {
            return m_generator->get();
        }
        bool next() {
            return m_generator->next();
        }
    };


    template<typename T>
    class SingleValueGenerator final : public IGenerator<T> {
        T m_value;
    public:
        SingleValueGenerator(T&& value):
            m_value(std::forward<T>(value))
        {}

        T const& get() const override {
            return m_value;
        }
        bool next() override {
            return false;
        }
    };

    template<typename T>
    class FixedValuesGenerator final : public IGenerator<T> {
        static_assert(!std::is_same<T, bool>::value,
            "FixedValuesGenerator does not support bools because of std::vector<bool>"
            "specialization, use SingleValue Generator instead.");
        std::vector<T> m_values;
        size_t m_idx = 0;
    public:
        FixedValuesGenerator( std::initializer_list<T> values ) : m_values( values ) {}

        T const& get() const override {
            return m_values[m_idx];
        }
        bool next() override {
            ++m_idx;
            return m_idx < m_values.size();
        }
    };

    template <typename T>
    GeneratorWrapper<T> value(T&& value) {
        return GeneratorWrapper<T>(Catch::Detail::make_unique<SingleValueGenerator<T>>(std::forward<T>(value)));
    }
    template <typename T>
    GeneratorWrapper<T> values(std::initializer_list<T> values) {
        return GeneratorWrapper<T>(Catch::Detail::make_unique<FixedValuesGenerator<T>>(values));
    }

    template<typename T>
    class Generators : public IGenerator<T> {
        std::vector<GeneratorWrapper<T>> m_generators;
        size_t m_current = 0;

        void populate(GeneratorWrapper<T>&& generator) {
            m_generators.emplace_back(std::move(generator));
        }
        void populate(T&& val) {
            m_generators.emplace_back(value(std::forward<T>(val)));
        }
        template<typename U>
        void populate(U&& val) {
            populate(T(std::forward<U>(val)));
        }
        template<typename U, typename... Gs>
        void populate(U&& valueOrGenerator, Gs &&... moreGenerators) {
            populate(std::forward<U>(valueOrGenerator));
            populate(std::forward<Gs>(moreGenerators)...);
        }

    public:
        template <typename... Gs>
        Generators(Gs &&... moreGenerators) {
            m_generators.reserve(sizeof...(Gs));
            populate(std::forward<Gs>(moreGenerators)...);
        }

        T const& get() const override {
            return m_generators[m_current].get();
        }

        bool next() override {
            if (m_current >= m_generators.size()) {
                return false;
            }
            const bool current_status = m_generators[m_current].next();
            if (!current_status) {
                ++m_current;
            }
            return m_current < m_generators.size();
        }
    };


    template<typename... Ts>
    GeneratorWrapper<std::tuple<Ts...>> table( std::initializer_list<std::tuple<std::decay_t<Ts>...>> tuples ) {
        return values<std::tuple<Ts...>>( tuples );
    }

    // Tag type to signal that a generator sequence should convert arguments to a specific type
    template <typename T>
    struct as {};

    template<typename T, typename... Gs>
    auto makeGenerators( GeneratorWrapper<T>&& generator, Gs &&... moreGenerators ) -> Generators<T> {
        return Generators<T>(std::move(generator), std::forward<Gs>(moreGenerators)...);
    }
    template<typename T>
    auto makeGenerators( GeneratorWrapper<T>&& generator ) -> Generators<T> {
        return Generators<T>(std::move(generator));
    }
    template<typename T, typename... Gs>
    auto makeGenerators( T&& val, Gs &&... moreGenerators ) -> Generators<T> {
        return makeGenerators( value( std::forward<T>( val ) ), std::forward<Gs>( moreGenerators )... );
    }
    template<typename T, typename U, typename... Gs>
    auto makeGenerators( as<T>, U&& val, Gs &&... moreGenerators ) -> Generators<T> {
        return makeGenerators( value( T( std::forward<U>( val ) ) ), std::forward<Gs>( moreGenerators )... );
    }

    auto acquireGeneratorTracker( StringRef generatorName, SourceLineInfo const& lineInfo ) -> IGeneratorTracker&;

    template<typename L>
    // Note: The type after -> is weird, because VS2015 cannot parse
    //       the expression used in the typedef inside, when it is in
    //       return type. Yeah.
    auto generate( StringRef generatorName, SourceLineInfo const& lineInfo, L const& generatorExpression ) -> decltype(std::declval<decltype(generatorExpression())>().get()) {
        using UnderlyingType = typename decltype(generatorExpression())::type;

        IGeneratorTracker& tracker = acquireGeneratorTracker( generatorName, lineInfo );
        if (!tracker.hasGenerator()) {
            tracker.setGenerator(Catch::Detail::make_unique<Generators<UnderlyingType>>(generatorExpression()));
        }

        auto const& generator = static_cast<IGenerator<UnderlyingType> const&>( *tracker.getGenerator() );
        return generator.get();
    }

} // namespace Generators
} // namespace Catch

#define GENERATE( ... ) \
    Catch::Generators::generate( INTERNAL_CATCH_STRINGIZE(INTERNAL_CATCH_UNIQUE_NAME(generator)), \
                                 CATCH_INTERNAL_LINEINFO, \
                                 [ ]{ using namespace Catch::Generators; return makeGenerators( __VA_ARGS__ ); } ) //NOLINT(google-build-using-namespace)
#define GENERATE_COPY( ... ) \
    Catch::Generators::generate( INTERNAL_CATCH_STRINGIZE(INTERNAL_CATCH_UNIQUE_NAME(generator)), \
                                 CATCH_INTERNAL_LINEINFO, \
                                 [=]{ using namespace Catch::Generators; return makeGenerators( __VA_ARGS__ ); } ) //NOLINT(google-build-using-namespace)
#define GENERATE_REF( ... ) \
    Catch::Generators::generate( INTERNAL_CATCH_STRINGIZE(INTERNAL_CATCH_UNIQUE_NAME(generator)), \
                                 CATCH_INTERNAL_LINEINFO, \
                                 [&]{ using namespace Catch::Generators; return makeGenerators( __VA_ARGS__ ); } ) //NOLINT(google-build-using-namespace)

#endif // CATCH_GENERATORS_HPP_INCLUDED
