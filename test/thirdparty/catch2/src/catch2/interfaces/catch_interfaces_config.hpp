
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_INTERFACES_CONFIG_HPP_INCLUDED
#define CATCH_INTERFACES_CONFIG_HPP_INCLUDED

#include <catch2/internal/catch_noncopyable.hpp>

#include <chrono>
#include <iosfwd>
#include <string>
#include <vector>

namespace Catch {

    enum class Verbosity {
        Quiet = 0,
        Normal,
        High
    };

    struct WarnAbout { enum What {
        Nothing = 0x00,
        NoAssertions = 0x01,
        NoTests = 0x02
    }; };

    enum class ShowDurations {
        DefaultForReporter,
        Always,
        Never
    };
    enum class TestRunOrder {
        Declared,
        LexicographicallySorted,
        Randomized
    };
    enum class UseColour {
        Auto,
        Yes,
        No
    };
    struct WaitForKeypress { enum When {
        Never,
        BeforeStart = 1,
        BeforeExit = 2,
        BeforeStartAndExit = BeforeStart | BeforeExit
    }; };

    class TestSpec;

    struct IConfig : Detail::NonCopyable {

        virtual ~IConfig();

        virtual bool allowThrows() const = 0;
        virtual std::ostream& stream() const = 0;
        virtual std::string name() const = 0;
        virtual bool includeSuccessfulResults() const = 0;
        virtual bool shouldDebugBreak() const = 0;
        virtual bool warnAboutMissingAssertions() const = 0;
        virtual bool warnAboutNoTests() const = 0;
        virtual int abortAfter() const = 0;
        virtual bool showInvisibles() const = 0;
        virtual ShowDurations showDurations() const = 0;
        virtual double minDuration() const = 0;
        virtual TestSpec const& testSpec() const = 0;
        virtual bool hasTestFilters() const = 0;
        virtual std::vector<std::string> const& getTestsOrTags() const = 0;
        virtual TestRunOrder runOrder() const = 0;
        virtual unsigned int rngSeed() const = 0;
        virtual UseColour useColour() const = 0;
        virtual std::vector<std::string> const& getSectionsToRun() const = 0;
        virtual Verbosity verbosity() const = 0;

        virtual bool benchmarkNoAnalysis() const = 0;
        virtual int benchmarkSamples() const = 0;
        virtual double benchmarkConfidenceInterval() const = 0;
        virtual unsigned int benchmarkResamples() const = 0;
        virtual std::chrono::milliseconds benchmarkWarmupTime() const = 0;
    };
}

#endif // CATCH_INTERFACES_CONFIG_HPP_INCLUDED
