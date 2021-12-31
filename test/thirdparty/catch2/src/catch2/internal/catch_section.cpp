
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_section.hpp>
#include <catch2/internal/catch_test_macro_impl.hpp>
#include <catch2/internal/catch_uncaught_exceptions.hpp>

#include <utility>

namespace Catch {

    Section::Section( SectionInfo&& info ):
        m_info( std::move( info ) ),
        m_sectionIncluded(
            getResultCapture().sectionStarted( m_info, m_assertions ) ) {
        // Non-"included" sections will not use the timing information
        // anyway, so don't bother with the potential syscall.
        if (m_sectionIncluded) {
            m_timer.start();
        }
    }

    Section::~Section() {
        if( m_sectionIncluded ) {
            SectionEndInfo endInfo{ m_info, m_assertions, m_timer.getElapsedSeconds() };
            if( uncaught_exceptions() )
                getResultCapture().sectionEndedEarly( endInfo );
            else
                getResultCapture().sectionEnded( endInfo );
        }
    }

    // This indicates whether the section should be executed or not
    Section::operator bool() const {
        return m_sectionIncluded;
    }


} // end namespace Catch
