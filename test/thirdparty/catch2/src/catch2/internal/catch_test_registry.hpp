
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_TEST_REGISTRY_HPP_INCLUDED
#define CATCH_TEST_REGISTRY_HPP_INCLUDED

#include <catch2/internal/catch_common.hpp>
#include <catch2/internal/catch_noncopyable.hpp>
#include <catch2/interfaces/catch_interfaces_testcase.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_stringref.hpp>
#include <catch2/internal/catch_unique_ptr.hpp>

// GCC 5 and older do not properly handle disabling unused-variable warning
// with a _Pragma. This means that we have to leak the suppression to the
// user code as well :-(
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ <= 5
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif



namespace Catch {

template<typename C>
class TestInvokerAsMethod : public ITestInvoker {
    void (C::*m_testAsMethod)();
public:
    TestInvokerAsMethod( void (C::*testAsMethod)() ) noexcept : m_testAsMethod( testAsMethod ) {}

    void invoke() const override {
        C obj;
        (obj.*m_testAsMethod)();
    }
};

Detail::unique_ptr<ITestInvoker> makeTestInvoker( void(*testAsFunction)() );

template<typename C>
Detail::unique_ptr<ITestInvoker> makeTestInvoker( void (C::*testAsMethod)() ) {
    return Detail::unique_ptr<ITestInvoker>( new TestInvokerAsMethod<C>(testAsMethod) );
}

struct NameAndTags {
    NameAndTags(StringRef const& name_ = StringRef(),
                StringRef const& tags_ = StringRef()) noexcept:
        name(name_), tags(tags_) {}
    StringRef name;
    StringRef tags;
};

struct AutoReg : Detail::NonCopyable {
    AutoReg( Detail::unique_ptr<ITestInvoker> invoker, SourceLineInfo const& lineInfo, StringRef const& classOrMethod, NameAndTags const& nameAndTags ) noexcept;
};

} // end namespace Catch

#if defined(CATCH_CONFIG_DISABLE)
    #define INTERNAL_CATCH_TESTCASE_NO_REGISTRATION( TestName, ... ) \
        static inline void TestName()
    #define INTERNAL_CATCH_TESTCASE_METHOD_NO_REGISTRATION( TestName, ClassName, ... ) \
        namespace{                        \
            struct TestName : INTERNAL_CATCH_REMOVE_PARENS(ClassName) { \
                void test();              \
            };                            \
        }                                 \
        void TestName::test()
#endif

    ///////////////////////////////////////////////////////////////////////////////
    #define INTERNAL_CATCH_TESTCASE2( TestName, ... ) \
        static void TestName(); \
        CATCH_INTERNAL_START_WARNINGS_SUPPRESSION \
        CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS \
        namespace{ Catch::AutoReg INTERNAL_CATCH_UNIQUE_NAME( autoRegistrar )( Catch::makeTestInvoker( &TestName ), CATCH_INTERNAL_LINEINFO, Catch::StringRef(), Catch::NameAndTags{ __VA_ARGS__ } ); } /* NOLINT */ \
        CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION \
        static void TestName()
    #define INTERNAL_CATCH_TESTCASE( ... ) \
        INTERNAL_CATCH_TESTCASE2( INTERNAL_CATCH_UNIQUE_NAME( ____C_A_T_C_H____T_E_S_T____ ), __VA_ARGS__ )

    ///////////////////////////////////////////////////////////////////////////////
    #define INTERNAL_CATCH_METHOD_AS_TEST_CASE( QualifiedMethod, ... ) \
        CATCH_INTERNAL_START_WARNINGS_SUPPRESSION \
        CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS \
        namespace{ Catch::AutoReg INTERNAL_CATCH_UNIQUE_NAME( autoRegistrar )( Catch::makeTestInvoker( &QualifiedMethod ), CATCH_INTERNAL_LINEINFO, "&" #QualifiedMethod, Catch::NameAndTags{ __VA_ARGS__ } ); } /* NOLINT */ \
        CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION

    ///////////////////////////////////////////////////////////////////////////////
    #define INTERNAL_CATCH_TEST_CASE_METHOD2( TestName, ClassName, ... )\
        CATCH_INTERNAL_START_WARNINGS_SUPPRESSION \
        CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS \
        namespace{ \
            struct TestName : INTERNAL_CATCH_REMOVE_PARENS(ClassName) { \
                void test(); \
            }; \
            Catch::AutoReg INTERNAL_CATCH_UNIQUE_NAME( autoRegistrar ) ( Catch::makeTestInvoker( &TestName::test ), CATCH_INTERNAL_LINEINFO, #ClassName, Catch::NameAndTags{ __VA_ARGS__ } ); /* NOLINT */ \
        } \
        CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION \
        void TestName::test()
    #define INTERNAL_CATCH_TEST_CASE_METHOD( ClassName, ... ) \
        INTERNAL_CATCH_TEST_CASE_METHOD2( INTERNAL_CATCH_UNIQUE_NAME( ____C_A_T_C_H____T_E_S_T____ ), ClassName, __VA_ARGS__ )

    ///////////////////////////////////////////////////////////////////////////////
    #define INTERNAL_CATCH_REGISTER_TESTCASE( Function, ... ) \
        do { \
            CATCH_INTERNAL_START_WARNINGS_SUPPRESSION \
            CATCH_INTERNAL_SUPPRESS_GLOBALS_WARNINGS \
            Catch::AutoReg INTERNAL_CATCH_UNIQUE_NAME( autoRegistrar )( Catch::makeTestInvoker( Function ), CATCH_INTERNAL_LINEINFO, Catch::StringRef(), Catch::NameAndTags{ __VA_ARGS__ } ); /* NOLINT */ \
            CATCH_INTERNAL_STOP_WARNINGS_SUPPRESSION \
        } while(false)


#endif // CATCH_TEST_REGISTRY_HPP_INCLUDED
