
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small matcher-related TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */

//////////////////////////////////////////////
// vvv formerly catch_matchers_impl.cpp vvv //
//////////////////////////////////////////////
#include <catch2/matchers/internal/catch_matchers_impl.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>

namespace Catch {

    // This is the general overload that takes a any string matcher
    // There is another overload, in catch_assertionhandler.h/.cpp, that only takes a string and infers
    // the Equals matcher (so the header does not mention matchers)
    void handleExceptionMatchExpr( AssertionHandler& handler, StringMatcher const& matcher, StringRef const& matcherString  ) {
        std::string exceptionMessage = Catch::translateActiveException();
        MatchExpr<std::string, StringMatcher const&> expr( std::move(exceptionMessage), matcher, matcherString );
        handler.handleExpr( expr );
    }

} // namespace Catch


//////////////////////////////////////////////////////////////
// vvv formerly catch_matchers_container_properties.cpp vvv //
//////////////////////////////////////////////////////////////
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/internal/catch_stream.hpp>

namespace Catch {
namespace Matchers {

    std::string IsEmptyMatcher::describe() const {
        return "is empty";
    }

    std::string HasSizeMatcher::describe() const {
        ReusableStringStream sstr;
        sstr << "has size == " << m_target_size;
        return sstr.str();
    }

    IsEmptyMatcher IsEmpty() {
        return {};
    }

    HasSizeMatcher SizeIs(std::size_t sz) {
        return HasSizeMatcher{ sz };
    }

} // end namespace Matchers
} // end namespace Catch



/////////////////////////////////////////
// vvv formerly catch_matchers.cpp vvv //
/////////////////////////////////////////

#include <catch2/matchers/catch_matchers.hpp>

namespace Catch {
namespace Matchers {

    std::string MatcherUntypedBase::toString() const {
        if (m_cachedToString.empty()) {
            m_cachedToString = describe();
        }
        return m_cachedToString;
    }

    MatcherUntypedBase::~MatcherUntypedBase() = default;

} // namespace Matchers
} // namespace Catch



///////////////////////////////////////////////////
// vvv formerly catch_matchers_predicate.cpp vvv //
///////////////////////////////////////////////////
#include <catch2/matchers/catch_matchers_predicate.hpp>

std::string Catch::Matchers::Detail::finalizeDescription(const std::string& desc) {
    if (desc.empty()) {
        return "matches undescribed predicate";
    } else {
        return "matches predicate: \"" + desc + '"';
    }
}





///////////////////////////////////////////////////
// vvv formerly catch_matchers_exception.cpp vvv //
///////////////////////////////////////////////////
#include <catch2/matchers/catch_matchers_exception.hpp>

namespace Catch {
namespace Matchers {

bool ExceptionMessageMatcher::match(std::exception const& ex) const {
    return ex.what() == m_message;
}

std::string ExceptionMessageMatcher::describe() const {
    return "exception message matches \"" + m_message + "\"";
}

ExceptionMessageMatcher Message(std::string const& message) {
    return ExceptionMessageMatcher(message);
}

} // namespace Matchers
} // namespace Catch
