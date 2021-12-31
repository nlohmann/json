
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_FATAL_CONDITION_HANDLER_HPP_INCLUDED
#define CATCH_FATAL_CONDITION_HANDLER_HPP_INCLUDED

#include <catch2/internal/catch_platform.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_windows_h_proxy.hpp>


#if defined( CATCH_CONFIG_WINDOWS_SEH )

namespace Catch {

    struct FatalConditionHandler {

        static LONG CALLBACK handleVectoredException(PEXCEPTION_POINTERS ExceptionInfo);
        FatalConditionHandler();
        static void reset();
        ~FatalConditionHandler() { reset(); }

    private:
        static bool isSet;
        static ULONG guaranteeSize;
        static PVOID exceptionHandlerHandle;
    };

} // namespace Catch

#elif defined ( CATCH_CONFIG_POSIX_SIGNALS )

#include <signal.h>

namespace Catch {

    struct FatalConditionHandler {

        static bool isSet;
        static struct sigaction oldSigActions[];
        static stack_t oldSigStack;
        static char altStackMem[];

        static void handleSignal( int sig );

        FatalConditionHandler();
        ~FatalConditionHandler() { reset(); }
        static void reset();
    };

} // namespace Catch


#else

namespace Catch {
    struct FatalConditionHandler {};
}

#endif

#endif // CATCH_FATAL_CONDITION_HANDLER_HPP_INCLUDED
