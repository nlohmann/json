
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_TEST_CASE_REGISTRY_IMPL_HPP_INCLUDED
#define CATCH_TEST_CASE_REGISTRY_IMPL_HPP_INCLUDED

#include <catch2/internal/catch_test_registry.hpp>
#include <catch2/interfaces/catch_interfaces_config.hpp>

#include <vector>

namespace Catch {

    class TestCaseHandle;
    struct IConfig;
    class TestSpec;

    std::vector<TestCaseHandle> sortTests( IConfig const& config, std::vector<TestCaseHandle> const& unsortedTestCases );

    bool isThrowSafe( TestCaseHandle const& testCase, IConfig const& config );
    bool matchTest( TestCaseHandle const& testCase, TestSpec const& testSpec, IConfig const& config );

    void enforceNoDuplicateTestCases( std::vector<TestCaseHandle> const& functions );

    std::vector<TestCaseHandle> filterTests( std::vector<TestCaseHandle> const& testCases, TestSpec const& testSpec, IConfig const& config );
    std::vector<TestCaseHandle> const& getAllTestCasesSorted( IConfig const& config );

    class TestRegistry : public ITestCaseRegistry {
    public:
        ~TestRegistry() override = default;

        void registerTest( Detail::unique_ptr<TestCaseInfo> testInfo, Detail::unique_ptr<ITestInvoker> testInvoker );

        std::vector<TestCaseInfo*> const& getAllInfos() const override;
        std::vector<TestCaseHandle> const& getAllTests() const override;
        std::vector<TestCaseHandle> const& getAllTestsSorted( IConfig const& config ) const override;

    private:
        std::vector<Detail::unique_ptr<TestCaseInfo>> m_owned_test_infos;
        // Keeps a materialized vector for `getAllInfos`.
        // We should get rid of that eventually (see interface note)
        std::vector<TestCaseInfo*> m_viewed_test_infos;

        std::vector<Detail::unique_ptr<ITestInvoker>> m_invokers;
        std::vector<TestCaseHandle> m_handles;
        mutable TestRunOrder m_currentSortOrder = TestRunOrder::Declared;
        mutable std::vector<TestCaseHandle> m_sortedFunctions;
    };

    ///////////////////////////////////////////////////////////////////////////

    class TestInvokerAsFunction final : public ITestInvoker {
        using TestType = void(*)();
        TestType m_testAsFunction;
    public:
        TestInvokerAsFunction(TestType testAsFunction) noexcept:
            m_testAsFunction(testAsFunction) {}

        void invoke() const override;
    };


    std::string extractClassName( StringRef const& classOrQualifiedMethodName );

    ///////////////////////////////////////////////////////////////////////////


} // end namespace Catch


#endif // CATCH_TEST_CASE_REGISTRY_IMPL_HPP_INCLUDED
