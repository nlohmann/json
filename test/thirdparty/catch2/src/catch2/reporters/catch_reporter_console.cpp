
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_console.hpp>

#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/catch_test_spec.hpp>
#include <catch2/internal/catch_console_colour.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/catch_version.hpp>
#include <catch2/internal/catch_textflow.hpp>
#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_stringref.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/internal/catch_console_width.hpp>
#include <catch2/reporters/catch_reporter_helpers.hpp>

#include <cfloat>
#include <cstdio>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4061) // Not all labels are EXPLICITLY handled in switch
 // Note that 4062 (not all labels are handled and default is missing) is enabled
#endif

#if defined(__clang__)
#  pragma clang diagnostic push
// For simplicity, benchmarking-only helpers are always enabled
#  pragma clang diagnostic ignored "-Wunused-function"
#endif



namespace Catch {

namespace {

// Formatter impl for ConsoleReporter
class ConsoleAssertionPrinter {
public:
    ConsoleAssertionPrinter& operator= (ConsoleAssertionPrinter const&) = delete;
    ConsoleAssertionPrinter(ConsoleAssertionPrinter const&) = delete;
    ConsoleAssertionPrinter(std::ostream& _stream, AssertionStats const& _stats, bool _printInfoMessages)
        : stream(_stream),
        stats(_stats),
        result(_stats.assertionResult),
        colour(Colour::None),
        message(result.getMessage()),
        messages(_stats.infoMessages),
        printInfoMessages(_printInfoMessages) {
        switch (result.getResultType()) {
        case ResultWas::Ok:
            colour = Colour::Success;
            passOrFail = "PASSED";
            //if( result.hasMessage() )
            if (_stats.infoMessages.size() == 1)
                messageLabel = "with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "with messages";
            break;
        case ResultWas::ExpressionFailed:
            if (result.isOk()) {
                colour = Colour::Success;
                passOrFail = "FAILED - but was ok";
            } else {
                colour = Colour::Error;
                passOrFail = "FAILED";
            }
            if (_stats.infoMessages.size() == 1)
                messageLabel = "with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "with messages";
            break;
        case ResultWas::ThrewException:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "due to unexpected exception with ";
            if (_stats.infoMessages.size() == 1)
                messageLabel += "message";
            if (_stats.infoMessages.size() > 1)
                messageLabel += "messages";
            break;
        case ResultWas::FatalErrorCondition:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "due to a fatal error condition";
            break;
        case ResultWas::DidntThrowException:
            colour = Colour::Error;
            passOrFail = "FAILED";
            messageLabel = "because no exception was thrown where one was expected";
            break;
        case ResultWas::Info:
            messageLabel = "info";
            break;
        case ResultWas::Warning:
            messageLabel = "warning";
            break;
        case ResultWas::ExplicitFailure:
            passOrFail = "FAILED";
            colour = Colour::Error;
            if (_stats.infoMessages.size() == 1)
                messageLabel = "explicitly with message";
            if (_stats.infoMessages.size() > 1)
                messageLabel = "explicitly with messages";
            break;
            // These cases are here to prevent compiler warnings
        case ResultWas::Unknown:
        case ResultWas::FailureBit:
        case ResultWas::Exception:
            passOrFail = "** internal error **";
            colour = Colour::Error;
            break;
        }
    }

    void print() const {
        printSourceInfo();
        if (stats.totals.assertions.total() > 0) {
            printResultType();
            printOriginalExpression();
            printReconstructedExpression();
        } else {
            stream << '\n';
        }
        printMessage();
    }

private:
    void printResultType() const {
        if (!passOrFail.empty()) {
            Colour colourGuard(colour);
            stream << passOrFail << ":\n";
        }
    }
    void printOriginalExpression() const {
        if (result.hasExpression()) {
            Colour colourGuard(Colour::OriginalExpression);
            stream << "  ";
            stream << result.getExpressionInMacro();
            stream << '\n';
        }
    }
    void printReconstructedExpression() const {
        if (result.hasExpandedExpression()) {
            stream << "with expansion:\n";
            Colour colourGuard(Colour::ReconstructedExpression);
            stream << TextFlow::Column(result.getExpandedExpression()).indent(2) << '\n';
        }
    }
    void printMessage() const {
        if (!messageLabel.empty())
            stream << messageLabel << ':' << '\n';
        for (auto const& msg : messages) {
            // If this assertion is a warning ignore any INFO messages
            if (printInfoMessages || msg.type != ResultWas::Info)
                stream << TextFlow::Column(msg.message).indent(2) << '\n';
        }
    }
    void printSourceInfo() const {
        Colour colourGuard(Colour::FileName);
        stream << result.getSourceInfo() << ": ";
    }

    std::ostream& stream;
    AssertionStats const& stats;
    AssertionResult const& result;
    Colour::Code colour;
    std::string passOrFail;
    std::string messageLabel;
    std::string message;
    std::vector<MessageInfo> messages;
    bool printInfoMessages;
};

std::size_t makeRatio(std::size_t number, std::size_t total) {
    std::size_t ratio = total > 0 ? CATCH_CONFIG_CONSOLE_WIDTH * number / total : 0;
    return (ratio == 0 && number > 0) ? 1 : ratio;
}

std::size_t& findMax(std::size_t& i, std::size_t& j, std::size_t& k) {
    if (i > j && i > k)
        return i;
    else if (j > k)
        return j;
    else
        return k;
}

enum class Justification { Left, Right };

struct ColumnInfo {
    std::string name;
    int width;
    Justification justification;
};
struct ColumnBreak {};
struct RowBreak {};

class Duration {
    enum class Unit {
        Auto,
        Nanoseconds,
        Microseconds,
        Milliseconds,
        Seconds,
        Minutes
    };
    static const uint64_t s_nanosecondsInAMicrosecond = 1000;
    static const uint64_t s_nanosecondsInAMillisecond = 1000 * s_nanosecondsInAMicrosecond;
    static const uint64_t s_nanosecondsInASecond = 1000 * s_nanosecondsInAMillisecond;
    static const uint64_t s_nanosecondsInAMinute = 60 * s_nanosecondsInASecond;

    double m_inNanoseconds;
    Unit m_units;

public:
    explicit Duration(double inNanoseconds, Unit units = Unit::Auto)
        : m_inNanoseconds(inNanoseconds),
        m_units(units) {
        if (m_units == Unit::Auto) {
            if (m_inNanoseconds < s_nanosecondsInAMicrosecond)
                m_units = Unit::Nanoseconds;
            else if (m_inNanoseconds < s_nanosecondsInAMillisecond)
                m_units = Unit::Microseconds;
            else if (m_inNanoseconds < s_nanosecondsInASecond)
                m_units = Unit::Milliseconds;
            else if (m_inNanoseconds < s_nanosecondsInAMinute)
                m_units = Unit::Seconds;
            else
                m_units = Unit::Minutes;
        }

    }

    auto value() const -> double {
        switch (m_units) {
        case Unit::Microseconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMicrosecond);
        case Unit::Milliseconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMillisecond);
        case Unit::Seconds:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInASecond);
        case Unit::Minutes:
            return m_inNanoseconds / static_cast<double>(s_nanosecondsInAMinute);
        default:
            return m_inNanoseconds;
        }
    }
    StringRef unitsAsString() const {
        switch (m_units) {
        case Unit::Nanoseconds:
            return "ns"_sr;
        case Unit::Microseconds:
            return "us"_sr;
        case Unit::Milliseconds:
            return "ms"_sr;
        case Unit::Seconds:
            return "s"_sr;
        case Unit::Minutes:
            return "m"_sr;
        default:
            return "** internal error **"_sr;
        }

    }
    friend auto operator << (std::ostream& os, Duration const& duration) -> std::ostream& {
        return os << duration.value() << ' ' << duration.unitsAsString();
    }
};
} // end anon namespace

class TablePrinter {
    std::ostream& m_os;
    std::vector<ColumnInfo> m_columnInfos;
    ReusableStringStream m_oss;
    int m_currentColumn = -1;
    bool m_isOpen = false;

public:
    TablePrinter( std::ostream& os, std::vector<ColumnInfo> columnInfos )
    :   m_os( os ),
        m_columnInfos( std::move( columnInfos ) ) {}

    auto columnInfos() const -> std::vector<ColumnInfo> const& {
        return m_columnInfos;
    }

    void open() {
        if (!m_isOpen) {
            m_isOpen = true;
            *this << RowBreak();

			TextFlow::Columns headerCols;
			auto spacer = TextFlow::Spacer(2);
			for (auto const& info : m_columnInfos) {
				headerCols += TextFlow::Column(info.name).width(static_cast<std::size_t>(info.width - 2));
				headerCols += spacer;
			}
			m_os << headerCols << '\n';

            m_os << lineOfChars('-') << '\n';
        }
    }
    void close() {
        if (m_isOpen) {
            *this << RowBreak();
            m_os << std::endl;
            m_isOpen = false;
        }
    }

    template<typename T>
    friend TablePrinter& operator << (TablePrinter& tp, T const& value) {
        tp.m_oss << value;
        return tp;
    }

    friend TablePrinter& operator << (TablePrinter& tp, ColumnBreak) {
        auto colStr = tp.m_oss.str();
        const auto strSize = colStr.size();
        tp.m_oss.str("");
        tp.open();
        if (tp.m_currentColumn == static_cast<int>(tp.m_columnInfos.size() - 1)) {
            tp.m_currentColumn = -1;
            tp.m_os << '\n';
        }
        tp.m_currentColumn++;

        auto colInfo = tp.m_columnInfos[tp.m_currentColumn];
        auto padding = (strSize + 1 < static_cast<std::size_t>(colInfo.width))
            ? std::string(colInfo.width - (strSize + 1), ' ')
            : std::string();
        if (colInfo.justification == Justification::Left)
            tp.m_os << colStr << padding << ' ';
        else
            tp.m_os << padding << colStr << ' ';
        return tp;
    }

    friend TablePrinter& operator << (TablePrinter& tp, RowBreak) {
        if (tp.m_currentColumn > 0) {
            tp.m_os << '\n';
            tp.m_currentColumn = -1;
        }
        return tp;
    }
};

ConsoleReporter::ConsoleReporter(ReporterConfig const& config)
    : StreamingReporterBase(config),
    m_tablePrinter(new TablePrinter(config.stream(),
        [&config]() -> std::vector<ColumnInfo> {
        if (config.fullConfig()->benchmarkNoAnalysis())
        {
            return{
                { "benchmark name", CATCH_CONFIG_CONSOLE_WIDTH - 43, Justification::Left },
                { "     samples", 14, Justification::Right },
                { "  iterations", 14, Justification::Right },
                { "        mean", 14, Justification::Right }
            };
        }
        else
        {
            return{
                { "benchmark name", CATCH_CONFIG_CONSOLE_WIDTH - 43, Justification::Left },
                { "samples      mean       std dev", 14, Justification::Right },
                { "iterations   low mean   low std dev", 14, Justification::Right },
                { "estimated    high mean  high std dev", 14, Justification::Right }
            };
        }
    }())) {}
ConsoleReporter::~ConsoleReporter() = default;

std::string ConsoleReporter::getDescription() {
    return "Reports test results as plain lines of text";
}

void ConsoleReporter::noMatchingTestCases(std::string const& spec) {
    stream << "No test cases matched '" << spec << '\'' << std::endl;
}

void ConsoleReporter::reportInvalidArguments(std::string const&arg){
    stream << "Invalid Filter: " << arg << std::endl;
}

void ConsoleReporter::assertionStarting(AssertionInfo const&) {}

bool ConsoleReporter::assertionEnded(AssertionStats const& _assertionStats) {
    AssertionResult const& result = _assertionStats.assertionResult;

    bool includeResults = m_config->includeSuccessfulResults() || !result.isOk();

    // Drop out if result was successful but we're not printing them.
    if (!includeResults && result.getResultType() != ResultWas::Warning)
        return false;

    lazyPrint();

    ConsoleAssertionPrinter printer(stream, _assertionStats, includeResults);
    printer.print();
    stream << std::endl;
    return true;
}

void ConsoleReporter::sectionStarting(SectionInfo const& _sectionInfo) {
    m_tablePrinter->close();
    m_headerPrinted = false;
    StreamingReporterBase::sectionStarting(_sectionInfo);
}
void ConsoleReporter::sectionEnded(SectionStats const& _sectionStats) {
    m_tablePrinter->close();
    if (_sectionStats.missingAssertions) {
        lazyPrint();
        Colour colour(Colour::ResultError);
        if (m_sectionStack.size() > 1)
            stream << "\nNo assertions in section";
        else
            stream << "\nNo assertions in test case";
        stream << " '" << _sectionStats.sectionInfo.name << "'\n" << std::endl;
    }
    double dur = _sectionStats.durationInSeconds;
    if (shouldShowDuration(*m_config, dur)) {
        stream << getFormattedDuration(dur) << " s: " << _sectionStats.sectionInfo.name << std::endl;
    }
    if (m_headerPrinted) {
        m_headerPrinted = false;
    }
    StreamingReporterBase::sectionEnded(_sectionStats);
}

void ConsoleReporter::benchmarkPreparing(std::string const& name) {
	lazyPrintWithoutClosingBenchmarkTable();

	auto nameCol = TextFlow::Column(name).width(static_cast<std::size_t>(m_tablePrinter->columnInfos()[0].width - 2));

	bool firstLine = true;
	for (auto line : nameCol) {
		if (!firstLine)
			(*m_tablePrinter) << ColumnBreak() << ColumnBreak() << ColumnBreak();
		else
			firstLine = false;

		(*m_tablePrinter) << line << ColumnBreak();
	}
}

void ConsoleReporter::benchmarkStarting(BenchmarkInfo const& info) {
    (*m_tablePrinter) << info.samples << ColumnBreak()
        << info.iterations << ColumnBreak();
    if (!m_config->benchmarkNoAnalysis())
        (*m_tablePrinter) << Duration(info.estimatedDuration) << ColumnBreak();
}
void ConsoleReporter::benchmarkEnded(BenchmarkStats<> const& stats) {
    if (m_config->benchmarkNoAnalysis())
    {
        (*m_tablePrinter) << Duration(stats.mean.point.count()) << ColumnBreak();
    }
    else
    {
        (*m_tablePrinter) << ColumnBreak()
            << Duration(stats.mean.point.count()) << ColumnBreak()
            << Duration(stats.mean.lower_bound.count()) << ColumnBreak()
            << Duration(stats.mean.upper_bound.count()) << ColumnBreak() << ColumnBreak()
            << Duration(stats.standardDeviation.point.count()) << ColumnBreak()
            << Duration(stats.standardDeviation.lower_bound.count()) << ColumnBreak()
            << Duration(stats.standardDeviation.upper_bound.count()) << ColumnBreak() << ColumnBreak() << ColumnBreak() << ColumnBreak() << ColumnBreak();
    }
}

void ConsoleReporter::benchmarkFailed(std::string const& error) {
	Colour colour(Colour::Red);
    (*m_tablePrinter)
        << "Benchmark failed (" << error << ')'
        << ColumnBreak() << RowBreak();
}

void ConsoleReporter::testCaseEnded(TestCaseStats const& _testCaseStats) {
    m_tablePrinter->close();
    StreamingReporterBase::testCaseEnded(_testCaseStats);
    m_headerPrinted = false;
}
void ConsoleReporter::testGroupEnded(TestGroupStats const& _testGroupStats) {
    if (currentGroupInfo.used) {
        printSummaryDivider();
        stream << "Summary for group '" << _testGroupStats.groupInfo.name << "':\n";
        printTotals(_testGroupStats.totals);
        stream << '\n' << std::endl;
    }
    StreamingReporterBase::testGroupEnded(_testGroupStats);
}
void ConsoleReporter::testRunEnded(TestRunStats const& _testRunStats) {
    printTotalsDivider(_testRunStats.totals);
    printTotals(_testRunStats.totals);
    stream << std::endl;
    StreamingReporterBase::testRunEnded(_testRunStats);
}
void ConsoleReporter::testRunStarting(TestRunInfo const& _testInfo) {
    StreamingReporterBase::testRunStarting(_testInfo);
    printTestFilters();
}

void ConsoleReporter::lazyPrint() {

    m_tablePrinter->close();
    lazyPrintWithoutClosingBenchmarkTable();
}

void ConsoleReporter::lazyPrintWithoutClosingBenchmarkTable() {

    if (!currentTestRunInfo.used)
        lazyPrintRunInfo();
    if (!currentGroupInfo.used)
        lazyPrintGroupInfo();

    if (!m_headerPrinted) {
        printTestCaseAndSectionHeader();
        m_headerPrinted = true;
    }
}
void ConsoleReporter::lazyPrintRunInfo() {
    stream << '\n' << lineOfChars('~') << '\n';
    Colour colour(Colour::SecondaryText);
    stream << currentTestRunInfo->name
        << " is a Catch v" << libraryVersion() << " host application.\n"
        << "Run with -? for options\n\n";

    if (m_config->rngSeed() != 0)
        stream << "Randomness seeded to: " << m_config->rngSeed() << "\n\n";

    currentTestRunInfo.used = true;
}
void ConsoleReporter::lazyPrintGroupInfo() {
    if (!currentGroupInfo->name.empty() && currentGroupInfo->groupsCounts > 1) {
        printClosedHeader("Group: " + currentGroupInfo->name);
        currentGroupInfo.used = true;
    }
}
void ConsoleReporter::printTestCaseAndSectionHeader() {
    assert(!m_sectionStack.empty());
    printOpenHeader(currentTestCaseInfo->name);

    if (m_sectionStack.size() > 1) {
        Colour colourGuard(Colour::Headers);

        auto
            it = m_sectionStack.begin() + 1, // Skip first section (test case)
            itEnd = m_sectionStack.end();
        for (; it != itEnd; ++it)
            printHeaderString(it->name, 2);
    }

    SourceLineInfo lineInfo = m_sectionStack.back().lineInfo;


    stream << lineOfChars('-') << '\n';
    Colour colourGuard(Colour::FileName);
    stream << lineInfo << '\n';
    stream << lineOfChars('.') << '\n' << std::endl;
}

void ConsoleReporter::printClosedHeader(std::string const& _name) {
    printOpenHeader(_name);
    stream << lineOfChars('.') << '\n';
}
void ConsoleReporter::printOpenHeader(std::string const& _name) {
    stream << lineOfChars('-') << '\n';
    {
        Colour colourGuard(Colour::Headers);
        printHeaderString(_name);
    }
}

// if string has a : in first line will set indent to follow it on
// subsequent lines
void ConsoleReporter::printHeaderString(std::string const& _string, std::size_t indent) {
    std::size_t i = _string.find(": ");
    if (i != std::string::npos)
        i += 2;
    else
        i = 0;
    stream << TextFlow::Column(_string).indent(indent + i).initialIndent(indent) << '\n';
}

struct SummaryColumn {

    SummaryColumn( std::string _label, Colour::Code _colour )
    :   label( std::move( _label ) ),
        colour( _colour ) {}
    SummaryColumn addRow( std::size_t count ) {
        ReusableStringStream rss;
        rss << count;
        std::string row = rss.str();
        for (auto& oldRow : rows) {
            while (oldRow.size() < row.size())
                oldRow = ' ' + oldRow;
            while (oldRow.size() > row.size())
                row = ' ' + row;
        }
        rows.push_back(row);
        return *this;
    }

    std::string label;
    Colour::Code colour;
    std::vector<std::string> rows;

};

void ConsoleReporter::printTotals( Totals const& totals ) {
    if (totals.testCases.total() == 0) {
        stream << Colour(Colour::Warning) << "No tests ran\n";
    } else if (totals.assertions.total() > 0 && totals.testCases.allPassed()) {
        stream << Colour(Colour::ResultSuccess) << "All tests passed";
        stream << " ("
            << pluralise(totals.assertions.passed, "assertion") << " in "
            << pluralise(totals.testCases.passed, "test case") << ')'
            << '\n';
    } else {

        std::vector<SummaryColumn> columns;
        columns.push_back(SummaryColumn("", Colour::None)
                          .addRow(totals.testCases.total())
                          .addRow(totals.assertions.total()));
        columns.push_back(SummaryColumn("passed", Colour::Success)
                          .addRow(totals.testCases.passed)
                          .addRow(totals.assertions.passed));
        columns.push_back(SummaryColumn("failed", Colour::ResultError)
                          .addRow(totals.testCases.failed)
                          .addRow(totals.assertions.failed));
        columns.push_back(SummaryColumn("failed as expected", Colour::ResultExpectedFailure)
                          .addRow(totals.testCases.failedButOk)
                          .addRow(totals.assertions.failedButOk));

        printSummaryRow("test cases", columns, 0);
        printSummaryRow("assertions", columns, 1);
    }
}
void ConsoleReporter::printSummaryRow(std::string const& label, std::vector<SummaryColumn> const& cols, std::size_t row) {
    for (auto col : cols) {
        std::string value = col.rows[row];
        if (col.label.empty()) {
            stream << label << ": ";
            if (value != "0")
                stream << value;
            else
                stream << Colour(Colour::Warning) << "- none -";
        } else if (value != "0") {
            stream << Colour(Colour::LightGrey) << " | ";
            stream << Colour(col.colour)
                << value << ' ' << col.label;
        }
    }
    stream << '\n';
}

void ConsoleReporter::printTotalsDivider(Totals const& totals) {
    if (totals.testCases.total() > 0) {
        std::size_t failedRatio = makeRatio(totals.testCases.failed, totals.testCases.total());
        std::size_t failedButOkRatio = makeRatio(totals.testCases.failedButOk, totals.testCases.total());
        std::size_t passedRatio = makeRatio(totals.testCases.passed, totals.testCases.total());
        while (failedRatio + failedButOkRatio + passedRatio < CATCH_CONFIG_CONSOLE_WIDTH - 1)
            findMax(failedRatio, failedButOkRatio, passedRatio)++;
        while (failedRatio + failedButOkRatio + passedRatio > CATCH_CONFIG_CONSOLE_WIDTH - 1)
            findMax(failedRatio, failedButOkRatio, passedRatio)--;

        stream << Colour(Colour::Error) << std::string(failedRatio, '=');
        stream << Colour(Colour::ResultExpectedFailure) << std::string(failedButOkRatio, '=');
        if (totals.testCases.allPassed())
            stream << Colour(Colour::ResultSuccess) << std::string(passedRatio, '=');
        else
            stream << Colour(Colour::Success) << std::string(passedRatio, '=');
    } else {
        stream << Colour(Colour::Warning) << std::string(CATCH_CONFIG_CONSOLE_WIDTH - 1, '=');
    }
    stream << '\n';
}
void ConsoleReporter::printSummaryDivider() {
    stream << lineOfChars('-') << '\n';
}

void ConsoleReporter::printTestFilters() {
    if (m_config->testSpec().hasFilters()) {
        Colour guard(Colour::BrightYellow);
        stream << "Filters: " << serializeFilters(m_config->getTestsOrTags()) << '\n';
    }
}

} // end namespace Catch

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif
