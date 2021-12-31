
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_REPORTER_XML_HPP_INCLUDED
#define CATCH_REPORTER_XML_HPP_INCLUDED

#include <catch2/reporters/catch_reporter_streaming_base.hpp>

#include <catch2/internal/catch_xmlwriter.hpp>
#include <catch2/catch_timer.hpp>


namespace Catch {
    class XmlReporter : public StreamingReporterBase {
    public:
        XmlReporter(ReporterConfig const& _config);

        ~XmlReporter() override;

        static std::string getDescription();

        virtual std::string getStylesheetRef() const;

        void writeSourceInfo(SourceLineInfo const& sourceInfo);

    public: // StreamingReporterBase

        void noMatchingTestCases(std::string const& s) override;

        void testRunStarting(TestRunInfo const& testInfo) override;

        void testGroupStarting(GroupInfo const& groupInfo) override;

        void testCaseStarting(TestCaseInfo const& testInfo) override;

        void sectionStarting(SectionInfo const& sectionInfo) override;

        void assertionStarting(AssertionInfo const&) override;

        bool assertionEnded(AssertionStats const& assertionStats) override;

        void sectionEnded(SectionStats const& sectionStats) override;

        void testCaseEnded(TestCaseStats const& testCaseStats) override;

        void testGroupEnded(TestGroupStats const& testGroupStats) override;

        void testRunEnded(TestRunStats const& testRunStats) override;

        void benchmarkPreparing(std::string const& name) override;
        void benchmarkStarting(BenchmarkInfo const&) override;
        void benchmarkEnded(BenchmarkStats<> const&) override;
        void benchmarkFailed(std::string const&) override;

        void listReporters(std::vector<ReporterDescription> const& descriptions, IConfig const& config) override;
        void listTests(std::vector<TestCaseHandle> const& tests, IConfig const& config) override;
        void listTags(std::vector<TagInfo> const& tags, IConfig const& config) override;

    private:
        Timer m_testCaseTimer;
        XmlWriter m_xml;
        int m_sectionDepth = 0;
    };

} // end namespace Catch

#endif // CATCH_REPORTER_XML_HPP_INCLUDED
