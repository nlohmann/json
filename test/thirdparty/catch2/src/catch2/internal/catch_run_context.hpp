
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_RUN_CONTEXT_HPP_INCLUDED
#define CATCH_RUN_CONTEXT_HPP_INCLUDED

#include <catch2/interfaces/catch_interfaces_runner.hpp>
#include <catch2/interfaces/catch_interfaces_reporter.hpp>
#include <catch2/internal/catch_test_registry.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_message.hpp>
#include <catch2/catch_totals.hpp>
#include <catch2/internal/catch_test_case_tracker.hpp>
#include <catch2/catch_assertion_info.hpp>
#include <catch2/catch_assertion_result.hpp>
#include <catch2/internal/catch_option.hpp>

#include <string>

namespace Catch {

    struct IMutableContext;
    struct IGeneratorTracker;
    struct IConfig;

    ///////////////////////////////////////////////////////////////////////////

    class RunContext : public IResultCapture, public IRunner {

    public:
        RunContext( RunContext const& ) = delete;
        RunContext& operator =( RunContext const& ) = delete;

        explicit RunContext( IConfig const* _config, IStreamingReporterPtr&& reporter );

        ~RunContext() override;

        void testGroupStarting( std::string const& testSpec, std::size_t groupIndex, std::size_t groupsCount );
        void testGroupEnded( std::string const& testSpec, Totals const& totals, std::size_t groupIndex, std::size_t groupsCount );

        Totals runTest(TestCaseHandle const& testCase);

    public: // IResultCapture

        // Assertion handlers
        void handleExpr
                (   AssertionInfo const& info,
                    ITransientExpression const& expr,
                    AssertionReaction& reaction ) override;
        void handleMessage
                (   AssertionInfo const& info,
                    ResultWas::OfType resultType,
                    StringRef const& message,
                    AssertionReaction& reaction ) override;
        void handleUnexpectedExceptionNotThrown
                (   AssertionInfo const& info,
                    AssertionReaction& reaction ) override;
        void handleUnexpectedInflightException
                (   AssertionInfo const& info,
                    std::string const& message,
                    AssertionReaction& reaction ) override;
        void handleIncomplete
                (   AssertionInfo const& info ) override;
        void handleNonExpr
                (   AssertionInfo const &info,
                    ResultWas::OfType resultType,
                    AssertionReaction &reaction ) override;

        bool sectionStarted( SectionInfo const& sectionInfo, Counts& assertions ) override;

        void sectionEnded( SectionEndInfo const& endInfo ) override;
        void sectionEndedEarly( SectionEndInfo const& endInfo ) override;

        auto acquireGeneratorTracker( StringRef generatorName, SourceLineInfo const& lineInfo ) -> IGeneratorTracker& override;

        void benchmarkPreparing( std::string const& name ) override;
        void benchmarkStarting( BenchmarkInfo const& info ) override;
        void benchmarkEnded( BenchmarkStats<> const& stats ) override;
        void benchmarkFailed( std::string const& error ) override;

        void pushScopedMessage( MessageInfo const& message ) override;
        void popScopedMessage( MessageInfo const& message ) override;

        void emplaceUnscopedMessage( MessageBuilder const& builder ) override;

        std::string getCurrentTestName() const override;

        const AssertionResult* getLastResult() const override;

        void exceptionEarlyReported() override;

        void handleFatalErrorCondition( StringRef message ) override;

        bool lastAssertionPassed() override;

        void assertionPassed() override;

    public:
        // !TBD We need to do this another way!
        bool aborting() const override;

    private:

        void runCurrentTest( std::string& redirectedCout, std::string& redirectedCerr );
        void invokeActiveTestCase();

        void resetAssertionInfo();
        bool testForMissingAssertions( Counts& assertions );

        void assertionEnded( AssertionResult const& result );
        void reportExpr
                (   AssertionInfo const &info,
                    ResultWas::OfType resultType,
                    ITransientExpression const *expr,
                    bool negated );

        void populateReaction( AssertionReaction& reaction );

    private:

        void handleUnfinishedSections();

        TestRunInfo m_runInfo;
        IMutableContext& m_context;
        TestCaseHandle const* m_activeTestCase = nullptr;
        ITracker* m_testCaseTracker = nullptr;
        Option<AssertionResult> m_lastResult;

        IConfig const* m_config;
        Totals m_totals;
        IStreamingReporterPtr m_reporter;
        std::vector<MessageInfo> m_messages;
        std::vector<ScopedMessage> m_messageScopes; /* Keeps owners of so-called unscoped messages. */
        AssertionInfo m_lastAssertionInfo;
        std::vector<SectionEndInfo> m_unfinishedSections;
        std::vector<ITracker*> m_activeSections;
        TrackerContext m_trackerContext;
        bool m_lastAssertionPassed = false;
        bool m_shouldReportUnexpected = true;
        bool m_includeSuccessfulResults;
    };

    void seedRng(IConfig const& config);
    unsigned int rngSeed();
} // end namespace Catch

#endif // CATCH_RUN_CONTEXT_HPP_INCLUDED
