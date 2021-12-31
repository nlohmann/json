
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_debug_console.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>
#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_platform.hpp>
#include <catch2/internal/catch_windows_h_proxy.hpp>

#if defined(CATCH_CONFIG_ANDROID_LOGWRITE)
#include <android/log.h>

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            __android_log_write( ANDROID_LOG_DEBUG, "Catch", text.c_str() );
        }
    }

#elif defined(CATCH_PLATFORM_WINDOWS)

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            ::OutputDebugStringA( text.c_str() );
        }
    }

#else

    namespace Catch {
        void writeToDebugConsole( std::string const& text ) {
            // !TBD: Need a version for Mac/ XCode and other IDEs
            Catch::cout() << text;
        }
    }

#endif // Platform
