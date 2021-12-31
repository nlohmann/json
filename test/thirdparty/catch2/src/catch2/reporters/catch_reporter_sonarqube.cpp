
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_sonarqube.hpp>

#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/catch_test_case_info.hpp>

#include <map>

namespace Catch {

    SonarQubeReporter::~SonarQubeReporter() {}

    void SonarQubeReporter::testRunStarting(TestRunInfo const& testRunInfo) {
        CumulativeReporterBase::testRunStarting(testRunInfo);
        xml.startElement("testExecutions");
        xml.writeAttribute("version", '1');
    }

    void SonarQubeReporter::testGroupEnded(TestGroupStats const& testGroupStats) {
        CumulativeReporterBase::testGroupEnded(testGroupStats);
        writeGroup(*m_testGroups.back());
    }

    void SonarQubeReporter::writeGroup(TestGroupNode const& groupNode) {
        std::map<std::string, TestGroupNode::ChildNodes> testsPerFile;
        for (auto const& child : groupNode.children)
            testsPerFile[child->value.testInfo->lineInfo.file].push_back(child);

        for (auto const& kv : testsPerFile)
            writeTestFile(kv.first, kv.second);
    }

    void SonarQubeReporter::writeTestFile(std::string const& filename, TestGroupNode::ChildNodes const& testCaseNodes) {
        XmlWriter::ScopedElement e = xml.scopedElement("file");
        xml.writeAttribute("path", filename);

        for (auto const& child : testCaseNodes)
            writeTestCase(*child);
    }

    void SonarQubeReporter::writeTestCase(TestCaseNode const& testCaseNode) {
        // All test cases have exactly one section - which represents the
        // test case itself. That section may have 0-n nested sections
        assert(testCaseNode.children.size() == 1);
        SectionNode const& rootSection = *testCaseNode.children.front();
        writeSection("", rootSection, testCaseNode.value.testInfo->okToFail());
    }

    void SonarQubeReporter::writeSection(std::string const& rootName, SectionNode const& sectionNode, bool okToFail) {
        std::string name = trim(sectionNode.stats.sectionInfo.name);
        if (!rootName.empty())
            name = rootName + '/' + name;

        if (!sectionNode.assertions.empty() || !sectionNode.stdOut.empty() || !sectionNode.stdErr.empty()) {
            XmlWriter::ScopedElement e = xml.scopedElement("testCase");
            xml.writeAttribute("name", name);
            xml.writeAttribute("duration", static_cast<long>(sectionNode.stats.durationInSeconds * 1000));

            writeAssertions(sectionNode, okToFail);
        }

        for (auto const& childNode : sectionNode.childSections)
            writeSection(name, *childNode, okToFail);
    }

    void SonarQubeReporter::writeAssertions(SectionNode const& sectionNode, bool okToFail) {
        for (auto const& assertion : sectionNode.assertions)
            writeAssertion(assertion, okToFail);
    }

    void SonarQubeReporter::writeAssertion(AssertionStats const& stats, bool okToFail) {
        AssertionResult const& result = stats.assertionResult;
        if (!result.isOk()) {
            std::string elementName;
            if (okToFail) {
                elementName = "skipped";
            } else {
                switch (result.getResultType()) {
                case ResultWas::ThrewException:
                case ResultWas::FatalErrorCondition:
                    elementName = "error";
                    break;
                case ResultWas::ExplicitFailure:
                    elementName = "failure";
                    break;
                case ResultWas::ExpressionFailed:
                    elementName = "failure";
                    break;
                case ResultWas::DidntThrowException:
                    elementName = "failure";
                    break;

                    // We should never see these here:
                case ResultWas::Info:
                case ResultWas::Warning:
                case ResultWas::Ok:
                case ResultWas::Unknown:
                case ResultWas::FailureBit:
                case ResultWas::Exception:
                    elementName = "internalError";
                    break;
                }
            }

            XmlWriter::ScopedElement e = xml.scopedElement(elementName);

            ReusableStringStream messageRss;
            messageRss << result.getTestMacroName() << "(" << result.getExpression() << ")";
            xml.writeAttribute("message", messageRss.str());

            ReusableStringStream textRss;
            if (stats.totals.assertions.total() > 0) {
                textRss << "FAILED:\n";
                if (result.hasExpression()) {
                    textRss << "\t" << result.getExpressionInMacro() << "\n";
                }
                if (result.hasExpandedExpression()) {
                    textRss << "with expansion:\n\t" << result.getExpandedExpression() << "\n";
                }
            }

            if (!result.getMessage().empty())
                textRss << result.getMessage() << "\n";

            for (auto const& msg : stats.infoMessages)
                if (msg.type == ResultWas::Info)
                    textRss << msg.message << "\n";

            textRss << "at " << result.getSourceInfo();
            xml.writeText(textRss.str(), XmlFormatting::Newline);
        }
    }

} // end namespace Catch
