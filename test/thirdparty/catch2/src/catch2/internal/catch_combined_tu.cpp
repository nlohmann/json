
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
/** \file
 * This is a special TU that combines what would otherwise be a very
 * small top-level TUs into one bigger TU.
 *
 * The reason for this is compilation performance improvements by
 * avoiding reparsing headers for many small TUs, instead having this
 * one TU include bit more, but having it all parsed only once.
 *
 * To avoid heavy-tail problem with compilation times, each "subpart"
 * of Catch2 has its own combined TU like this.
 */


////////////////////////////////////////////////////////
// vvv formerly catch_tag_alias_autoregistrar.cpp vvv //
////////////////////////////////////////////////////////

#include <catch2/catch_tag_alias_autoregistrar.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>

namespace Catch {

    RegistrarForTagAliases::RegistrarForTagAliases(char const* alias, char const* tag, SourceLineInfo const& lineInfo) {
        CATCH_TRY {
            getMutableRegistryHub().registerTagAlias(alias, tag, lineInfo);
        } CATCH_CATCH_ALL {
            // Do not throw when constructing global objects, instead register the exception to be processed later
            getMutableRegistryHub().registerStartupException();
        }
    }

}


//////////////////////////////////////////
// vvv formerly catch_polyfills.cpp vvv //
//////////////////////////////////////////

#include <catch2/internal/catch_polyfills.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <cmath>

namespace Catch {

#if !defined(CATCH_CONFIG_POLYFILL_ISNAN)
    bool isnan(float f) {
        return std::isnan(f);
    }
    bool isnan(double d) {
        return std::isnan(d);
    }
#else
    // For now we only use this for embarcadero
    bool isnan(float f) {
        return std::_isnan(f);
    }
    bool isnan(double d) {
        return std::_isnan(d);
    }
#endif

} // end namespace Catch


////////////////////////////////////////////////////
// vvv formerly catch_uncaught_exceptions.cpp vvv //
////////////////////////////////////////////////////

#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_uncaught_exceptions.hpp>
#include <catch2/internal/catch_config_uncaught_exceptions.hpp>

#include <exception>

namespace Catch {
    bool uncaught_exceptions() {
#if defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
        return false;
#elif defined(CATCH_CONFIG_CPP17_UNCAUGHT_EXCEPTIONS)
        return std::uncaught_exceptions() > 0;
#else
        return std::uncaught_exception();
#endif
  }
} // end namespace Catch


////////////////////////////////////////////
// vvv formerly catch_errno_guard.cpp vvv //
////////////////////////////////////////////
#include <catch2/internal/catch_errno_guard.hpp>

#include <cerrno>

namespace Catch {
        ErrnoGuard::ErrnoGuard():m_oldErrno(errno){}
        ErrnoGuard::~ErrnoGuard() { errno = m_oldErrno; }
}


///////////////////////////////////////////
// vvv formerly catch_decomposer.cpp vvv //
///////////////////////////////////////////
#include <catch2/internal/catch_decomposer.hpp>

namespace Catch {

    ITransientExpression::~ITransientExpression() = default;

    void formatReconstructedExpression( std::ostream &os, std::string const& lhs, StringRef op, std::string const& rhs ) {
        if( lhs.size() + rhs.size() < 40 &&
                lhs.find('\n') == std::string::npos &&
                rhs.find('\n') == std::string::npos )
            os << lhs << ' ' << op << ' ' << rhs;
        else
            os << lhs << '\n' << op << '\n' << rhs;
    }
}


///////////////////////////////////////////////////////////
// vvv formerly catch_startup_exception_registry.cpp vvv //
///////////////////////////////////////////////////////////
#include <catch2/internal/catch_startup_exception_registry.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>

namespace Catch {
#if !defined(CATCH_CONFIG_DISABLE_EXCEPTIONS)
    void StartupExceptionRegistry::add( std::exception_ptr const& exception ) noexcept {
        CATCH_TRY {
            m_exceptions.push_back(exception);
        } CATCH_CATCH_ALL {
            // If we run out of memory during start-up there's really not a lot more we can do about it
            std::terminate();
        }
    }

    std::vector<std::exception_ptr> const& StartupExceptionRegistry::getExceptions() const noexcept {
        return m_exceptions;
    }
#endif

} // end namespace Catch


//////////////////////////////////////////////
// vvv formerly catch_leak_detector.cpp vvv //
//////////////////////////////////////////////
#include <catch2/internal/catch_leak_detector.hpp>
#include <catch2/interfaces/catch_interfaces_registry_hub.hpp>


#ifdef CATCH_CONFIG_WINDOWS_CRTDBG
#include <crtdbg.h>

namespace Catch {

    LeakDetector::LeakDetector() {
        int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
        flag |= _CRTDBG_LEAK_CHECK_DF;
        flag |= _CRTDBG_ALLOC_MEM_DF;
        _CrtSetDbgFlag(flag);
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
        // Change this to leaking allocation's number to break there
        _CrtSetBreakAlloc(-1);
    }
}

#else // ^^ Windows crt debug heap enabled // Windows crt debug heap disabled vv

    Catch::LeakDetector::LeakDetector() {}

#endif // CATCH_CONFIG_WINDOWS_CRTDBG

Catch::LeakDetector::~LeakDetector() {
    Catch::cleanUp();
}


/////////////////////////////////////////////
// vvv formerly catch_message_info.cpp vvv //
/////////////////////////////////////////////

#include <catch2/internal/catch_message_info.hpp>

namespace Catch {

    MessageInfo::MessageInfo(   StringRef const& _macroName,
                                SourceLineInfo const& _lineInfo,
                                ResultWas::OfType _type )
    :   macroName( _macroName ),
        lineInfo( _lineInfo ),
        type( _type ),
        sequence( ++globalCount )
    {}

    // This may need protecting if threading support is added
    unsigned int MessageInfo::globalCount = 0;

} // end namespace Catch




//////////////////////////////////////////
// vvv formerly catch_lazy_expr.cpp vvv //
//////////////////////////////////////////
#include <catch2/internal/catch_lazy_expr.hpp>
#include <catch2/internal/catch_decomposer.hpp>

namespace Catch {

    auto operator << (std::ostream& os, LazyExpression const& lazyExpr) -> std::ostream& {
        if (lazyExpr.m_isNegated)
            os << "!";

        if (lazyExpr) {
            if (lazyExpr.m_isNegated && lazyExpr.m_transientExpression->isBinaryExpression())
                os << "(" << *lazyExpr.m_transientExpression << ")";
            else
                os << *lazyExpr.m_transientExpression;
        } else {
            os << "{** error - unchecked empty expression requested **}";
        }
        return os;
    }

} // namespace Catch
