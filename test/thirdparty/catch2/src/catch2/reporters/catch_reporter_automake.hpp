
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_REPORTER_AUTOMAKE_HPP_INCLUDED
#define CATCH_REPORTER_AUTOMAKE_HPP_INCLUDED

#include <catch2/reporters/catch_reporter_streaming_base.hpp>

namespace Catch {

    struct AutomakeReporter : StreamingReporterBase {
        AutomakeReporter( ReporterConfig const& _config )
          :   StreamingReporterBase( _config )
        {}

        ~AutomakeReporter() override;

        static std::string getDescription() {
            using namespace std::string_literals;
            return "Reports test results in the format of Automake .trs files"s;
        }

        void assertionStarting( AssertionInfo const& ) override {}

        bool assertionEnded( AssertionStats const& /*_assertionStats*/ ) override { return true; }

        void testCaseEnded(TestCaseStats const& _testCaseStats) override;

        void skipTest(TestCaseInfo const& testInfo) override;

    };

} // end namespace Catch

#endif // CATCH_REPORTER_AUTOMAKE_HPP_INCLUDED
