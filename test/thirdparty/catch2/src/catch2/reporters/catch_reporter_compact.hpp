
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_REPORTER_COMPACT_HPP_INCLUDED
#define CATCH_REPORTER_COMPACT_HPP_INCLUDED


#include <catch2/reporters/catch_reporter_streaming_base.hpp>


namespace Catch {

    struct CompactReporter : StreamingReporterBase {

        using StreamingReporterBase::StreamingReporterBase;

        ~CompactReporter() override;

        static std::string getDescription();

        void noMatchingTestCases(std::string const& spec) override;

        void assertionStarting(AssertionInfo const&) override;

        bool assertionEnded(AssertionStats const& _assertionStats) override;

        void sectionEnded(SectionStats const& _sectionStats) override;

        void testRunEnded(TestRunStats const& _testRunStats) override;

    };

} // end namespace Catch

#endif // CATCH_REPORTER_COMPACT_HPP_INCLUDED
