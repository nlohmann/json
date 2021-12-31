
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_teamcity.hpp>

#include <catch2/reporters/catch_reporter_helpers.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_textflow.hpp>
#include <catch2/catch_test_case_info.hpp>

#include <cassert>

namespace Catch {

    namespace {
        // if string has a : in first line will set indent to follow it on
        // subsequent lines
        void printHeaderString(std::ostream& os, std::string const& _string, std::size_t indent = 0) {
            std::size_t i = _string.find(": ");
            if (i != std::string::npos)
                i += 2;
            else
                i = 0;
            os << TextFlow::Column(_string)
                  .indent(indent + i)
                  .initialIndent(indent) << '\n';
        }

        std::string escape(std::string const& str) {
            std::string escaped = str;
            replaceInPlace(escaped, "|", "||");
            replaceInPlace(escaped, "'", "|'");
            replaceInPlace(escaped, "\n", "|n");
            replaceInPlace(escaped, "\r", "|r");
            replaceInPlace(escaped, "[", "|[");
            replaceInPlace(escaped, "]", "|]");
            return escaped;
        }
    } // end anonymous namespace


    TeamCityReporter::~TeamCityReporter() {}

    void TeamCityReporter::testGroupStarting(GroupInfo const& groupInfo) {
        StreamingReporterBase::testGroupStarting(groupInfo);
        stream << "##teamcity[testSuiteStarted name='"
            << escape(groupInfo.name) << "']\n";
    }

    void TeamCityReporter::testGroupEnded(TestGroupStats const& testGroupStats) {
        StreamingReporterBase::testGroupEnded(testGroupStats);
        stream << "##teamcity[testSuiteFinished name='"
            << escape(testGroupStats.groupInfo.name) << "']\n";
    }

    bool TeamCityReporter::assertionEnded(AssertionStats const& assertionStats) {
        AssertionResult const& result = assertionStats.assertionResult;
        if (!result.isOk()) {

            ReusableStringStream msg;
            if (!m_headerPrintedForThisSection)
                printSectionHeader(msg.get());
            m_headerPrintedForThisSection = true;

            msg << result.getSourceInfo() << '\n';

            switch (result.getResultType()) {
            case ResultWas::ExpressionFailed:
                msg << "expression failed";
                break;
            case ResultWas::ThrewException:
                msg << "unexpected exception";
                break;
            case ResultWas::FatalErrorCondition:
                msg << "fatal error condition";
                break;
            case ResultWas::DidntThrowException:
                msg << "no exception was thrown where one was expected";
                break;
            case ResultWas::ExplicitFailure:
                msg << "explicit failure";
                break;

                // We shouldn't get here because of the isOk() test
            case ResultWas::Ok:
            case ResultWas::Info:
            case ResultWas::Warning:
                CATCH_ERROR("Internal error in TeamCity reporter");
                // These cases are here to prevent compiler warnings
            case ResultWas::Unknown:
            case ResultWas::FailureBit:
            case ResultWas::Exception:
                CATCH_ERROR("Not implemented");
            }
            if (assertionStats.infoMessages.size() == 1)
                msg << " with message:";
            if (assertionStats.infoMessages.size() > 1)
                msg << " with messages:";
            for (auto const& messageInfo : assertionStats.infoMessages)
                msg << "\n  \"" << messageInfo.message << '"';


            if (result.hasExpression()) {
                msg <<
                    "\n  " << result.getExpressionInMacro() << "\n"
                    "with expansion:\n"
                    "  " << result.getExpandedExpression() << '\n';
            }

            if (currentTestCaseInfo->okToFail()) {
                msg << "- failure ignore as test marked as 'ok to fail'\n";
                stream << "##teamcity[testIgnored"
                    << " name='" << escape(currentTestCaseInfo->name) << '\''
                    << " message='" << escape(msg.str()) << '\''
                    << "]\n";
            } else {
                stream << "##teamcity[testFailed"
                    << " name='" << escape(currentTestCaseInfo->name) << '\''
                    << " message='" << escape(msg.str()) << '\''
                    << "]\n";
            }
        }
        stream.flush();
        return true;
    }

    void TeamCityReporter::testCaseStarting(TestCaseInfo const& testInfo) {
        m_testTimer.start();
        StreamingReporterBase::testCaseStarting(testInfo);
        stream << "##teamcity[testStarted name='"
            << escape(testInfo.name) << "']\n";
        stream.flush();
    }

    void TeamCityReporter::testCaseEnded(TestCaseStats const& testCaseStats) {
        StreamingReporterBase::testCaseEnded(testCaseStats);
        auto const& testCaseInfo = *testCaseStats.testInfo;
        if (!testCaseStats.stdOut.empty())
            stream << "##teamcity[testStdOut name='"
            << escape(testCaseInfo.name)
            << "' out='" << escape(testCaseStats.stdOut) << "']\n";
        if (!testCaseStats.stdErr.empty())
            stream << "##teamcity[testStdErr name='"
            << escape(testCaseInfo.name)
            << "' out='" << escape(testCaseStats.stdErr) << "']\n";
        stream << "##teamcity[testFinished name='"
            << escape(testCaseInfo.name) << "' duration='"
            << m_testTimer.getElapsedMilliseconds() << "']\n";
        stream.flush();
    }

    void TeamCityReporter::printSectionHeader(std::ostream& os) {
        assert(!m_sectionStack.empty());

        if (m_sectionStack.size() > 1) {
            os << lineOfChars('-') << '\n';

            std::vector<SectionInfo>::const_iterator
                it = m_sectionStack.begin() + 1, // Skip first section (test case)
                itEnd = m_sectionStack.end();
            for (; it != itEnd; ++it)
                printHeaderString(os, it->name);
            os << lineOfChars('-') << '\n';
        }

        SourceLineInfo lineInfo = m_sectionStack.front().lineInfo;

        os << lineInfo << '\n';
        os << lineOfChars('.') << "\n\n";
    }

} // end namespace Catch
