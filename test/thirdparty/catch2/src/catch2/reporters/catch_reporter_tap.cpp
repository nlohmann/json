
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/reporters/catch_reporter_tap.hpp>
#include <catch2/internal/catch_console_colour.hpp>
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/catch_test_case_info.hpp>

#include <algorithm>
#include <ostream>

namespace Catch {

    namespace {
        // Yes, this has to be outside the class and namespaced by naming.
        // Making older compiler happy is hard.
        static constexpr StringRef tapFailedString = "not ok"_sr;
        static constexpr StringRef tapPassedString = "ok"_sr;

        class TapAssertionPrinter {
        public:
            TapAssertionPrinter& operator= (TapAssertionPrinter const&) = delete;
            TapAssertionPrinter(TapAssertionPrinter const&) = delete;
            TapAssertionPrinter(std::ostream& _stream, AssertionStats const& _stats, std::size_t _counter)
                : stream(_stream)
                , result(_stats.assertionResult)
                , messages(_stats.infoMessages)
                , itMessage(_stats.infoMessages.begin())
                , printInfoMessages(true)
                , counter(_counter) {}

            void print() {
                itMessage = messages.begin();

                switch (result.getResultType()) {
                case ResultWas::Ok:
                    printResultType(tapPassedString);
                    printOriginalExpression();
                    printReconstructedExpression();
                    if (!result.hasExpression())
                        printRemainingMessages(Colour::None);
                    else
                        printRemainingMessages();
                    break;
                case ResultWas::ExpressionFailed:
                    if (result.isOk()) {
                        printResultType(tapPassedString);
                    } else {
                        printResultType(tapFailedString);
                    }
                    printOriginalExpression();
                    printReconstructedExpression();
                    if (result.isOk()) {
                        printIssue(" # TODO");
                    }
                    printRemainingMessages();
                    break;
                case ResultWas::ThrewException:
                    printResultType(tapFailedString);
                    printIssue("unexpected exception with message:"_sr);
                    printMessage();
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::FatalErrorCondition:
                    printResultType(tapFailedString);
                    printIssue("fatal error condition with message:"_sr);
                    printMessage();
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::DidntThrowException:
                    printResultType(tapFailedString);
                    printIssue("expected exception, got none"_sr);
                    printExpressionWas();
                    printRemainingMessages();
                    break;
                case ResultWas::Info:
                    printResultType("info"_sr);
                    printMessage();
                    printRemainingMessages();
                    break;
                case ResultWas::Warning:
                    printResultType("warning"_sr);
                    printMessage();
                    printRemainingMessages();
                    break;
                case ResultWas::ExplicitFailure:
                    printResultType(tapFailedString);
                    printIssue("explicitly"_sr);
                    printRemainingMessages(Colour::None);
                    break;
                    // These cases are here to prevent compiler warnings
                case ResultWas::Unknown:
                case ResultWas::FailureBit:
                case ResultWas::Exception:
                    printResultType("** internal error **"_sr);
                    break;
                }
            }

        private:
            static Colour::Code dimColour() { return Colour::FileName; }

            void printSourceInfo() const {
                Colour colourGuard(dimColour());
                stream << result.getSourceInfo() << ':';
            }

            void printResultType(StringRef passOrFail) const {
                if (!passOrFail.empty()) {
                    stream << passOrFail << ' ' << counter << " -";
                }
            }

            void printIssue(StringRef issue) const {
                stream << ' ' << issue;
            }

            void printExpressionWas() {
                if (result.hasExpression()) {
                    stream << ';';
                    {
                        Colour colour(dimColour());
                        stream << " expression was:";
                    }
                    printOriginalExpression();
                }
            }

            void printOriginalExpression() const {
                if (result.hasExpression()) {
                    stream << ' ' << result.getExpression();
                }
            }

            void printReconstructedExpression() const {
                if (result.hasExpandedExpression()) {
                    {
                        Colour colour(dimColour());
                        stream << " for: ";
                    }
                    std::string expr = result.getExpandedExpression();
                    std::replace(expr.begin(), expr.end(), '\n', ' ');
                    stream << expr;
                }
            }

            void printMessage() {
                if (itMessage != messages.end()) {
                    stream << " '" << itMessage->message << '\'';
                    ++itMessage;
                }
            }

            void printRemainingMessages(Colour::Code colour = dimColour()) {
                if (itMessage == messages.end()) {
                    return;
                }

                // using messages.end() directly (or auto) yields compilation error:
                std::vector<MessageInfo>::const_iterator itEnd = messages.end();
                const std::size_t N = static_cast<std::size_t>(std::distance(itMessage, itEnd));

                {
                    Colour colourGuard(colour);
                    stream << " with " << pluralise(N, "message") << ':';
                }

                for (; itMessage != itEnd; ) {
                    // If this assertion is a warning ignore any INFO messages
                    if (printInfoMessages || itMessage->type != ResultWas::Info) {
                        stream << " '" << itMessage->message << '\'';
                        if (++itMessage != itEnd) {
                            Colour colourGuard(dimColour());
                            stream << " and";
                        }
                    }
                }
            }

        private:
            std::ostream& stream;
            AssertionResult const& result;
            std::vector<MessageInfo> messages;
            std::vector<MessageInfo>::const_iterator itMessage;
            bool printInfoMessages;
            std::size_t counter;
        };

    } // End anonymous namespace

    TAPReporter::~TAPReporter() {}

    void TAPReporter::noMatchingTestCases(std::string const& spec) {
        stream << "# No test cases matched '" << spec << "'\n";
    }

    bool TAPReporter::assertionEnded(AssertionStats const& _assertionStats) {
        ++counter;

        stream << "# " << currentTestCaseInfo->name << '\n';
        TapAssertionPrinter printer(stream, _assertionStats, counter);
        printer.print();

        stream << '\n' << std::flush;
        return true;
    }

    void TAPReporter::testRunEnded(TestRunStats const& _testRunStats) {
        stream << "1.." << _testRunStats.totals.assertions.total();
        if (_testRunStats.totals.testCases.total() == 0) {
            stream << " # Skipped: No tests ran.";
        }
        stream << "\n\n" << std::flush;
        StreamingReporterBase::testRunEnded(_testRunStats);
    }




} // end namespace Catch
