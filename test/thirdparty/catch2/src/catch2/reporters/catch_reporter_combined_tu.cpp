
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small reporter-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

#include <catch2/reporters/catch_reporter_helpers.hpp>
#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/internal/catch_console_width.hpp>
#include <catch2/internal/catch_errno_guard.hpp>

#include <cfloat>
#include <cstdio>
#include <ostream>

namespace Catch {

    // Because formatting using c++ streams is stateful, drop down to C is
    // required Alternatively we could use stringstream, but its performance
    // is... not good.
    std::string getFormattedDuration( double duration ) {
        // Max exponent + 1 is required to represent the whole part
        // + 1 for decimal point
        // + 3 for the 3 decimal places
        // + 1 for null terminator
        const std::size_t maxDoubleSize = DBL_MAX_10_EXP + 1 + 1 + 3 + 1;
        char buffer[maxDoubleSize];

        // Save previous errno, to prevent sprintf from overwriting it
        ErrnoGuard guard;
#ifdef _MSC_VER
        sprintf_s( buffer, "%.3f", duration );
#else
        std::sprintf( buffer, "%.3f", duration );
#endif
        return std::string( buffer );
    }

    bool shouldShowDuration( IConfig const& config, double duration ) {
        if ( config.showDurations() == ShowDurations::Always ) {
            return true;
        }
        if ( config.showDurations() == ShowDurations::Never ) {
            return false;
        }
        const double min = config.minDuration();
        return min >= 0 && duration >= min;
    }

    std::string serializeFilters( std::vector<std::string> const& filters ) {
        // We add a ' ' separator between each filter
        size_t serialized_size = filters.size() - 1;
        for (auto const& filter : filters) {
            serialized_size += filter.size();
        }

        std::string serialized;
        serialized.reserve(serialized_size);
        bool first = true;

        for (auto const& filter : filters) {
            if (!first) {
                serialized.push_back(' ');
            }
            first = false;
            serialized.append(filter);
        }

        return serialized;
    }

    std::ostream& operator<<( std::ostream& out, lineOfChars value ) {
        for ( size_t idx = 0; idx < CATCH_CONFIG_CONSOLE_WIDTH - 1; ++idx ) {
            out.put( value.c );
        }
        return out;
    }

} // namespace Catch


#include <catch2/reporters/catch_reporter_event_listener.hpp>

namespace Catch {
    void EventListenerBase::assertionStarting( AssertionInfo const& ) {}

    bool EventListenerBase::assertionEnded( AssertionStats const& ) {
        return false;
    }
    void
    EventListenerBase::listReporters( std::vector<ReporterDescription> const&,
                                      IConfig const& ) {}
    void EventListenerBase::listTests( std::vector<TestCaseHandle> const&,
                                       IConfig const& ) {}
    void EventListenerBase::listTags( std::vector<TagInfo> const&,
                                      IConfig const& ) {}
    void EventListenerBase::noMatchingTestCases( std::string const& ) {}
    void EventListenerBase::testRunStarting( TestRunInfo const& ) {}
    void EventListenerBase::testGroupStarting( GroupInfo const& ) {}
    void EventListenerBase::testCaseStarting( TestCaseInfo const& ) {}
    void EventListenerBase::sectionStarting( SectionInfo const& ) {}
    void EventListenerBase::sectionEnded( SectionStats const& ) {}
    void EventListenerBase::testCaseEnded( TestCaseStats const& ) {}
    void EventListenerBase::testGroupEnded( TestGroupStats const& ) {}
    void EventListenerBase::testRunEnded( TestRunStats const& ) {}
    void EventListenerBase::skipTest( TestCaseInfo const& ) {}
} // namespace Catch
