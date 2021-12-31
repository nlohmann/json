
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_REPORTER_JUNIT_HPP_INCLUDED
#define CATCH_REPORTER_JUNIT_HPP_INCLUDED


#include <catch2/reporters/catch_reporter_cumulative_base.hpp>
#include <catch2/internal/catch_xmlwriter.hpp>
#include <catch2/catch_timer.hpp>

namespace Catch {

    class JunitReporter : public CumulativeReporterBase {
    public:
        JunitReporter(ReporterConfig const& _config);

        ~JunitReporter() override;

        static std::string getDescription();

        void noMatchingTestCases(std::string const& /*spec*/) override;

        void testRunStarting(TestRunInfo const& runInfo) override;

        void testGroupStarting(GroupInfo const& groupInfo) override;

        void testCaseStarting(TestCaseInfo const& testCaseInfo) override;
        bool assertionEnded(AssertionStats const& assertionStats) override;

        void testCaseEnded(TestCaseStats const& testCaseStats) override;

        void testGroupEnded(TestGroupStats const& testGroupStats) override;

        void testRunEndedCumulative() override;

        void writeGroup(TestGroupNode const& groupNode, double suiteTime);

        void writeTestCase(TestCaseNode const& testCaseNode);

        void writeSection(std::string const& className,
                          std::string const& rootName,
                          SectionNode const& sectionNode);

        void writeAssertions(SectionNode const& sectionNode);
        void writeAssertion(AssertionStats const& stats);

        XmlWriter xml;
        Timer suiteTimer;
        std::string stdOutForSuite;
        std::string stdErrForSuite;
        unsigned int unexpectedExceptions = 0;
        bool m_okToFail = false;
    };

} // end namespace Catch

#endif // CATCH_REPORTER_JUNIT_HPP_INCLUDED
