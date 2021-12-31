
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_INTERFACES_TESTCASE_HPP_INCLUDED
#define CATCH_INTERFACES_TESTCASE_HPP_INCLUDED

#include <vector>

namespace Catch {

    class TestSpec;
    struct TestCaseInfo;

    struct ITestInvoker {
        virtual void invoke () const = 0;
        virtual ~ITestInvoker();
    };

    class TestCaseHandle;
    struct IConfig;

    struct ITestCaseRegistry {
        virtual ~ITestCaseRegistry();
        // TODO: this exists only for adding filenames to test cases -- let's expose this in a saner way later
        virtual std::vector<TestCaseInfo* > const& getAllInfos() const = 0;
        virtual std::vector<TestCaseHandle> const& getAllTests() const = 0;
        virtual std::vector<TestCaseHandle> const& getAllTestsSorted( IConfig const& config ) const = 0;
    };

    bool isThrowSafe( TestCaseHandle const& testCase, IConfig const& config );
    bool matchTest( TestCaseHandle const& testCase, TestSpec const& testSpec, IConfig const& config );
    std::vector<TestCaseHandle> filterTests( std::vector<TestCaseHandle> const& testCases, TestSpec const& testSpec, IConfig const& config );
    std::vector<TestCaseHandle> const& getAllTestCasesSorted( IConfig const& config );

}

#endif // CATCH_INTERFACES_TESTCASE_HPP_INCLUDED
