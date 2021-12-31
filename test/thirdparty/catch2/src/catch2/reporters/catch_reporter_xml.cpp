
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_xml.hpp>

#include <catch2/reporters/catch_reporter_helpers.hpp>
#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/catch_test_spec.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/internal/catch_list.hpp>
#include <catch2/catch_test_case_info.hpp>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4061) // Not all labels are EXPLICITLY handled in switch
                              // Note that 4062 (not all labels are handled
                              // and default is missing) is enabled
#endif

namespace Catch {
    XmlReporter::XmlReporter( ReporterConfig const& _config )
    :   StreamingReporterBase( _config ),
        m_xml(_config.stream())
    {
        m_preferences.shouldRedirectStdOut = true;
        m_preferences.shouldReportAllAssertions = true;
    }

    XmlReporter::~XmlReporter() = default;

    std::string XmlReporter::getDescription() {
        return "Reports test results as an XML document";
    }

    std::string XmlReporter::getStylesheetRef() const {
        return std::string();
    }

    void XmlReporter::writeSourceInfo( SourceLineInfo const& sourceInfo ) {
        m_xml
            .writeAttribute( "filename", sourceInfo.file )
            .writeAttribute( "line", sourceInfo.line );
    }

    void XmlReporter::noMatchingTestCases( std::string const& s ) {
        StreamingReporterBase::noMatchingTestCases( s );
    }

    void XmlReporter::testRunStarting( TestRunInfo const& testInfo ) {
        StreamingReporterBase::testRunStarting( testInfo );
        std::string stylesheetRef = getStylesheetRef();
        if( !stylesheetRef.empty() )
            m_xml.writeStylesheetRef( stylesheetRef );
        m_xml.startElement( "Catch" );
        if( !m_config->name().empty() )
            m_xml.writeAttribute( "name", m_config->name() );
        if (m_config->testSpec().hasFilters())
            m_xml.writeAttribute( "filters", serializeFilters( m_config->getTestsOrTags() ) );
        if( m_config->rngSeed() != 0 )
            m_xml.scopedElement( "Randomness" )
                .writeAttribute( "seed", m_config->rngSeed() );
    }

    void XmlReporter::testGroupStarting( GroupInfo const& groupInfo ) {
        StreamingReporterBase::testGroupStarting( groupInfo );
        m_xml.startElement( "Group" )
            .writeAttribute( "name", groupInfo.name );
    }

    void XmlReporter::testCaseStarting( TestCaseInfo const& testInfo ) {
        StreamingReporterBase::testCaseStarting(testInfo);
        m_xml.startElement( "TestCase" )
            .writeAttribute( "name", trim( testInfo.name ) )
            .writeAttribute( "tags", testInfo.tagsAsString() );

        writeSourceInfo( testInfo.lineInfo );

        if ( m_config->showDurations() == ShowDurations::Always )
            m_testCaseTimer.start();
        m_xml.ensureTagClosed();
    }

    void XmlReporter::sectionStarting( SectionInfo const& sectionInfo ) {
        StreamingReporterBase::sectionStarting( sectionInfo );
        if( m_sectionDepth++ > 0 ) {
            m_xml.startElement( "Section" )
                .writeAttribute( "name", trim( sectionInfo.name ) );
            writeSourceInfo( sectionInfo.lineInfo );
            m_xml.ensureTagClosed();
        }
    }

    void XmlReporter::assertionStarting( AssertionInfo const& ) { }

    bool XmlReporter::assertionEnded( AssertionStats const& assertionStats ) {

        AssertionResult const& result = assertionStats.assertionResult;

        bool includeResults = m_config->includeSuccessfulResults() || !result.isOk();

        if( includeResults || result.getResultType() == ResultWas::Warning ) {
            // Print any info messages in <Info> tags.
            for( auto const& msg : assertionStats.infoMessages ) {
                if( msg.type == ResultWas::Info && includeResults ) {
                    m_xml.scopedElement( "Info" )
                            .writeText( msg.message );
                } else if ( msg.type == ResultWas::Warning ) {
                    m_xml.scopedElement( "Warning" )
                            .writeText( msg.message );
                }
            }
        }

        // Drop out if result was successful but we're not printing them.
        if( !includeResults && result.getResultType() != ResultWas::Warning )
            return true;


        // Print the expression if there is one.
        if( result.hasExpression() ) {
            m_xml.startElement( "Expression" )
                .writeAttribute( "success", result.succeeded() )
                .writeAttribute( "type", result.getTestMacroName() );

            writeSourceInfo( result.getSourceInfo() );

            m_xml.scopedElement( "Original" )
                .writeText( result.getExpression() );
            m_xml.scopedElement( "Expanded" )
                .writeText( result.getExpandedExpression() );
        }

        // And... Print a result applicable to each result type.
        switch( result.getResultType() ) {
            case ResultWas::ThrewException:
                m_xml.startElement( "Exception" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            case ResultWas::FatalErrorCondition:
                m_xml.startElement( "FatalErrorCondition" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            case ResultWas::Info:
                m_xml.scopedElement( "Info" )
                    .writeText( result.getMessage() );
                break;
            case ResultWas::Warning:
                // Warning will already have been written
                break;
            case ResultWas::ExplicitFailure:
                m_xml.startElement( "Failure" );
                writeSourceInfo( result.getSourceInfo() );
                m_xml.writeText( result.getMessage() );
                m_xml.endElement();
                break;
            default:
                break;
        }

        if( result.hasExpression() )
            m_xml.endElement();

        return true;
    }

    void XmlReporter::sectionEnded( SectionStats const& sectionStats ) {
        StreamingReporterBase::sectionEnded( sectionStats );
        if( --m_sectionDepth > 0 ) {
            XmlWriter::ScopedElement e = m_xml.scopedElement( "OverallResults" );
            e.writeAttribute( "successes", sectionStats.assertions.passed );
            e.writeAttribute( "failures", sectionStats.assertions.failed );
            e.writeAttribute( "expectedFailures", sectionStats.assertions.failedButOk );

            if ( m_config->showDurations() == ShowDurations::Always )
                e.writeAttribute( "durationInSeconds", sectionStats.durationInSeconds );

            m_xml.endElement();
        }
    }

    void XmlReporter::testCaseEnded( TestCaseStats const& testCaseStats ) {
        StreamingReporterBase::testCaseEnded( testCaseStats );
        XmlWriter::ScopedElement e = m_xml.scopedElement( "OverallResult" );
        e.writeAttribute( "success", testCaseStats.totals.assertions.allOk() );

        if ( m_config->showDurations() == ShowDurations::Always )
            e.writeAttribute( "durationInSeconds", m_testCaseTimer.getElapsedSeconds() );

        if( !testCaseStats.stdOut.empty() )
            m_xml.scopedElement( "StdOut" ).writeText( trim( testCaseStats.stdOut ), XmlFormatting::Newline );
        if( !testCaseStats.stdErr.empty() )
            m_xml.scopedElement( "StdErr" ).writeText( trim( testCaseStats.stdErr ), XmlFormatting::Newline );

        m_xml.endElement();
    }

    void XmlReporter::testGroupEnded( TestGroupStats const& testGroupStats ) {
        StreamingReporterBase::testGroupEnded( testGroupStats );
        // TODO: Check testGroupStats.aborting and act accordingly.
        m_xml.scopedElement( "OverallResults" )
            .writeAttribute( "successes", testGroupStats.totals.assertions.passed )
            .writeAttribute( "failures", testGroupStats.totals.assertions.failed )
            .writeAttribute( "expectedFailures", testGroupStats.totals.assertions.failedButOk );
        m_xml.scopedElement( "OverallResultsCases")
            .writeAttribute( "successes", testGroupStats.totals.testCases.passed )
            .writeAttribute( "failures", testGroupStats.totals.testCases.failed )
            .writeAttribute( "expectedFailures", testGroupStats.totals.testCases.failedButOk );
        m_xml.endElement();
    }

    void XmlReporter::testRunEnded( TestRunStats const& testRunStats ) {
        StreamingReporterBase::testRunEnded( testRunStats );
        m_xml.scopedElement( "OverallResults" )
            .writeAttribute( "successes", testRunStats.totals.assertions.passed )
            .writeAttribute( "failures", testRunStats.totals.assertions.failed )
            .writeAttribute( "expectedFailures", testRunStats.totals.assertions.failedButOk );
        m_xml.scopedElement( "OverallResultsCases")
            .writeAttribute( "successes", testRunStats.totals.testCases.passed )
            .writeAttribute( "failures", testRunStats.totals.testCases.failed )
            .writeAttribute( "expectedFailures", testRunStats.totals.testCases.failedButOk );
        m_xml.endElement();
    }

    void XmlReporter::benchmarkPreparing(std::string const& name) {
        m_xml.startElement("BenchmarkResults")
            .writeAttribute("name", name);
    }

    void XmlReporter::benchmarkStarting(BenchmarkInfo const &info) {
        m_xml.writeAttribute("samples", info.samples)
            .writeAttribute("resamples", info.resamples)
            .writeAttribute("iterations", info.iterations)
            .writeAttribute("clockResolution", info.clockResolution)
            .writeAttribute("estimatedDuration", info.estimatedDuration)
            .writeComment("All values in nano seconds");
    }

    void XmlReporter::benchmarkEnded(BenchmarkStats<> const& benchmarkStats) {
        m_xml.startElement("mean")
            .writeAttribute("value", benchmarkStats.mean.point.count())
            .writeAttribute("lowerBound", benchmarkStats.mean.lower_bound.count())
            .writeAttribute("upperBound", benchmarkStats.mean.upper_bound.count())
            .writeAttribute("ci", benchmarkStats.mean.confidence_interval);
        m_xml.endElement();
        m_xml.startElement("standardDeviation")
            .writeAttribute("value", benchmarkStats.standardDeviation.point.count())
            .writeAttribute("lowerBound", benchmarkStats.standardDeviation.lower_bound.count())
            .writeAttribute("upperBound", benchmarkStats.standardDeviation.upper_bound.count())
            .writeAttribute("ci", benchmarkStats.standardDeviation.confidence_interval);
        m_xml.endElement();
        m_xml.startElement("outliers")
            .writeAttribute("variance", benchmarkStats.outlierVariance)
            .writeAttribute("lowMild", benchmarkStats.outliers.low_mild)
            .writeAttribute("lowSevere", benchmarkStats.outliers.low_severe)
            .writeAttribute("highMild", benchmarkStats.outliers.high_mild)
            .writeAttribute("highSevere", benchmarkStats.outliers.high_severe);
        m_xml.endElement();
        m_xml.endElement();
    }

    void XmlReporter::benchmarkFailed(std::string const &error) {
        m_xml.scopedElement("failed").
            writeAttribute("message", error);
        m_xml.endElement();
    }

    void XmlReporter::listReporters(std::vector<ReporterDescription> const& descriptions, IConfig const&) {
        auto outerTag = m_xml.scopedElement("AvailableReporters");
        for (auto const& reporter : descriptions) {
            auto inner = m_xml.scopedElement("Reporter");
            m_xml.startElement("Name", XmlFormatting::Indent)
                 .writeText(reporter.name, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Description", XmlFormatting::Indent)
                 .writeText(reporter.description, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
        }
    }

    void XmlReporter::listTests(std::vector<TestCaseHandle> const& tests, IConfig const&) {
        auto outerTag = m_xml.scopedElement("MatchingTests");
        for (auto const& test : tests) {
            auto innerTag = m_xml.scopedElement("TestCase");
            auto const& testInfo = test.getTestCaseInfo();
            m_xml.startElement("Name", XmlFormatting::Indent)
                 .writeText(testInfo.name, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("ClassName", XmlFormatting::Indent)
                 .writeText(testInfo.className, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Tags", XmlFormatting::Indent)
                 .writeText(testInfo.tagsAsString(), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);

            auto sourceTag = m_xml.scopedElement("SourceInfo");
            m_xml.startElement("File", XmlFormatting::Indent)
                 .writeText(testInfo.lineInfo.file, XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            m_xml.startElement("Line", XmlFormatting::Indent)
                 .writeText(std::to_string(testInfo.lineInfo.line), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
        }
    }

    void XmlReporter::listTags(std::vector<TagInfo> const& tags, IConfig const&) {
        auto outerTag = m_xml.scopedElement("TagsFromMatchingTests");
        for (auto const& tag : tags) {
            auto innerTag = m_xml.scopedElement("Tag");
            m_xml.startElement("Count", XmlFormatting::Indent)
                 .writeText(std::to_string(tag.count), XmlFormatting::None)
                 .endElement(XmlFormatting::Newline);
            auto aliasTag = m_xml.scopedElement("Aliases");
            for (auto const& alias : tag.spellings) {
                m_xml.startElement("Alias", XmlFormatting::Indent)
                     .writeText(static_cast<std::string>(alias), XmlFormatting::None)
                     .endElement(XmlFormatting::Newline);
            }
        }
    }

} // end namespace Catch

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
