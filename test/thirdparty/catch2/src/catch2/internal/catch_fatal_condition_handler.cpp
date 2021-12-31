
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_fatal_condition_handler.hpp>

#include <catch2/internal/catch_context.hpp>
#include <catch2/interfaces/catch_interfaces_capture.hpp>

#if defined(__GNUC__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#if defined( CATCH_CONFIG_WINDOWS_SEH ) || defined( CATCH_CONFIG_POSIX_SIGNALS )

namespace {
    // Report the error condition
    void reportFatal( char const * const message ) {
        Catch::getCurrentContext().getResultCapture()->handleFatalErrorCondition( message );
    }
}

#endif // signals/SEH handling

#if defined( CATCH_CONFIG_WINDOWS_SEH )

namespace Catch {
    struct SignalDefs { DWORD id; const char* name; };

    // There is no 1-1 mapping between signals and windows exceptions.
    // Windows can easily distinguish between SO and SigSegV,
    // but SigInt, SigTerm, etc are handled differently.
    static SignalDefs signalDefs[] = {
        { static_cast<DWORD>(EXCEPTION_ILLEGAL_INSTRUCTION),  "SIGILL - Illegal instruction signal" },
        { static_cast<DWORD>(EXCEPTION_STACK_OVERFLOW), "SIGSEGV - Stack overflow" },
        { static_cast<DWORD>(EXCEPTION_ACCESS_VIOLATION), "SIGSEGV - Segmentation violation signal" },
        { static_cast<DWORD>(EXCEPTION_INT_DIVIDE_BY_ZERO), "Divide by zero error" },
    };

    LONG CALLBACK FatalConditionHandler::handleVectoredException(PEXCEPTION_POINTERS ExceptionInfo) {
        for (auto const& def : signalDefs) {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode == def.id) {
                reportFatal(def.name);
            }
        }
        // If its not an exception we care about, pass it along.
        // This stops us from eating debugger breaks etc.
        return EXCEPTION_CONTINUE_SEARCH;
    }

    FatalConditionHandler::FatalConditionHandler() {
        isSet = true;
        // 32k seems enough for Catch to handle stack overflow,
        // but the value was found experimentally, so there is no strong guarantee
        guaranteeSize = 32 * 1024;
        exceptionHandlerHandle = nullptr;
        // Register as first handler in current chain
        exceptionHandlerHandle = AddVectoredExceptionHandler(1, handleVectoredException);
        // Pass in guarantee size to be filled
        SetThreadStackGuarantee(&guaranteeSize);
    }

    void FatalConditionHandler::reset() {
        if (isSet) {
            RemoveVectoredExceptionHandler(exceptionHandlerHandle);
            SetThreadStackGuarantee(&guaranteeSize);
            exceptionHandlerHandle = nullptr;
            isSet = false;
        }
    }

bool FatalConditionHandler::isSet = false;
ULONG FatalConditionHandler::guaranteeSize = 0;
PVOID FatalConditionHandler::exceptionHandlerHandle = nullptr;


} // namespace Catch

#elif defined( CATCH_CONFIG_POSIX_SIGNALS )

namespace Catch {

    struct SignalDefs {
        int id;
        const char* name;
    };

    // 32kb for the alternate stack seems to be sufficient. However, this value
    // is experimentally determined, so that's not guaranteed.
    static constexpr std::size_t sigStackSize = 32768 >= MINSIGSTKSZ ? 32768 : MINSIGSTKSZ;

    static SignalDefs signalDefs[] = {
        { SIGINT,  "SIGINT - Terminal interrupt signal" },
        { SIGILL,  "SIGILL - Illegal instruction signal" },
        { SIGFPE,  "SIGFPE - Floating point error signal" },
        { SIGSEGV, "SIGSEGV - Segmentation violation signal" },
        { SIGTERM, "SIGTERM - Termination request signal" },
        { SIGABRT, "SIGABRT - Abort (abnormal termination) signal" }
    };


    void FatalConditionHandler::handleSignal( int sig ) {
        char const * name = "<unknown signal>";
        for (auto const& def : signalDefs) {
            if (sig == def.id) {
                name = def.name;
                break;
            }
        }
        reset();
        reportFatal(name);
        raise( sig );
    }

    FatalConditionHandler::FatalConditionHandler() {
        isSet = true;
        stack_t sigStack;
        sigStack.ss_sp = altStackMem;
        sigStack.ss_size = sigStackSize;
        sigStack.ss_flags = 0;
        sigaltstack(&sigStack, &oldSigStack);
        struct sigaction sa = { };

        sa.sa_handler = handleSignal;
        sa.sa_flags = SA_ONSTACK;
        for (std::size_t i = 0; i < sizeof(signalDefs)/sizeof(SignalDefs); ++i) {
            sigaction(signalDefs[i].id, &sa, &oldSigActions[i]);
        }
    }

    void FatalConditionHandler::reset() {
        if( isSet ) {
            // Set signals back to previous values -- hopefully nobody overwrote them in the meantime
            for( std::size_t i = 0; i < sizeof(signalDefs)/sizeof(SignalDefs); ++i ) {
                sigaction(signalDefs[i].id, &oldSigActions[i], nullptr);
            }
            // Return the old stack
            sigaltstack(&oldSigStack, nullptr);
            isSet = false;
        }
    }

    bool FatalConditionHandler::isSet = false;
    struct sigaction FatalConditionHandler::oldSigActions[sizeof(signalDefs)/sizeof(SignalDefs)] = {};
    stack_t FatalConditionHandler::oldSigStack = {};
    char FatalConditionHandler::altStackMem[sigStackSize] = {};


} // namespace Catch

#endif // signals/SEH handling

#if defined(__GNUC__)
#    pragma GCC diagnostic pop
#endif
