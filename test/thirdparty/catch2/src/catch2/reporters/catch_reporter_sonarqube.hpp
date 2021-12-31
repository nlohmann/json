
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_REPORTER_SONARQUBE_HPP_INCLUDED
#define CATCH_REPORTER_SONARQUBE_HPP_INCLUDED

#include <catch2/reporters/catch_reporter_cumulative_base.hpp>

#include <catch2/internal/catch_xmlwriter.hpp>

namespace Catch {

    struct SonarQubeReporter : CumulativeReporterBase {

        SonarQubeReporter(ReporterConfig const& config)
        : CumulativeReporterBase(config)
        , xml(config.stream()) {
            m_preferences.shouldRedirectStdOut = true;
            m_preferences.shouldReportAllAssertions = true;
        }

        ~SonarQubeReporter() override;

        static std::string getDescription() {
            using namespace std::string_literals;
            return "Reports test results in the Generic Test Data SonarQube XML format"s;
        }

        void noMatchingTestCases(std::string const& /*spec*/) override {}

        void testRunStarting(TestRunInfo const& testRunInfo) override;

        void testGroupEnded(TestGroupStats const& testGroupStats) override;

        void testRunEndedCumulative() override {
            xml.endElement();
        }

        void writeGroup(TestGroupNode const& groupNode);

        void writeTestFile(std::string const& filename, TestGroupNode::ChildNodes const& testCaseNodes);

        void writeTestCase(TestCaseNode const& testCaseNode);

        void writeSection(std::string const& rootName, SectionNode const& sectionNode, bool okToFail);

        void writeAssertions(SectionNode const& sectionNode, bool okToFail);

        void writeAssertion(AssertionStats const& stats, bool okToFail);

    private:
        XmlWriter xml;
    };


} // end namespace Catch

#endif // CATCH_REPORTER_SONARQUBE_HPP_INCLUDED
