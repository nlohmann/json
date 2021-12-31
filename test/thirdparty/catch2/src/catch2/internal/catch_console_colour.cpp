
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wexit-time-destructors"
#endif


#include <catch2/internal/catch_console_colour.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_errno_guard.hpp>
#include <catch2/interfaces/catch_interfaces_config.hpp>
#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_context.hpp>
#include <catch2/internal/catch_platform.hpp>
#include <catch2/internal/catch_debugger.hpp>
#include <catch2/internal/catch_windows_h_proxy.hpp>

#include <ostream>

namespace Catch {
    namespace {

        struct IColourImpl {
            virtual ~IColourImpl() = default;
            virtual void use( Colour::Code _colourCode ) = 0;
        };

        struct NoColourImpl : IColourImpl {
            void use( Colour::Code ) override {}

            static IColourImpl* instance() {
                static NoColourImpl s_instance;
                return &s_instance;
            }
        };

    } // anon namespace
} // namespace Catch

#if !defined( CATCH_CONFIG_COLOUR_NONE ) && !defined( CATCH_CONFIG_COLOUR_WINDOWS ) && !defined( CATCH_CONFIG_COLOUR_ANSI )
#   ifdef CATCH_PLATFORM_WINDOWS
#       define CATCH_CONFIG_COLOUR_WINDOWS
#   else
#       define CATCH_CONFIG_COLOUR_ANSI
#   endif
#endif


#if defined ( CATCH_CONFIG_COLOUR_WINDOWS ) /////////////////////////////////////////

namespace Catch {
namespace {

    class Win32ColourImpl : public IColourImpl {
    public:
        Win32ColourImpl() : stdoutHandle( GetStdHandle(STD_OUTPUT_HANDLE) )
        {
            CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
            GetConsoleScreenBufferInfo( stdoutHandle, &csbiInfo );
            originalForegroundAttributes = csbiInfo.wAttributes & ~( BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_BLUE | BACKGROUND_INTENSITY );
            originalBackgroundAttributes = csbiInfo.wAttributes & ~( FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY );
        }

        void use( Colour::Code _colourCode ) override {
            switch( _colourCode ) {
                case Colour::None:      return setTextAttribute( originalForegroundAttributes );
                case Colour::White:     return setTextAttribute( FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE );
                case Colour::Red:       return setTextAttribute( FOREGROUND_RED );
                case Colour::Green:     return setTextAttribute( FOREGROUND_GREEN );
                case Colour::Blue:      return setTextAttribute( FOREGROUND_BLUE );
                case Colour::Cyan:      return setTextAttribute( FOREGROUND_BLUE | FOREGROUND_GREEN );
                case Colour::Yellow:    return setTextAttribute( FOREGROUND_RED | FOREGROUND_GREEN );
                case Colour::Grey:      return setTextAttribute( 0 );

                case Colour::LightGrey:     return setTextAttribute( FOREGROUND_INTENSITY );
                case Colour::BrightRed:     return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_RED );
                case Colour::BrightGreen:   return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_GREEN );
                case Colour::BrightWhite:   return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE );
                case Colour::BrightYellow:  return setTextAttribute( FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN );

                case Colour::Bright: CATCH_INTERNAL_ERROR( "not a colour" );

                default:
                    CATCH_ERROR( "Unknown colour requested" );
            }
        }

    private:
        void setTextAttribute( WORD _textAttribute ) {
            SetConsoleTextAttribute( stdoutHandle, _textAttribute | originalBackgroundAttributes );
        }
        HANDLE stdoutHandle;
        WORD originalForegroundAttributes;
        WORD originalBackgroundAttributes;
    };

    IColourImpl* platformColourInstance() {
        static Win32ColourImpl s_instance;

        auto const* config = getCurrentContext().getConfig();
        UseColour colourMode = config?
            config->useColour() : UseColour::Auto;
        if( colourMode == UseColour::Auto )
            colourMode = UseColour::Yes;
        return colourMode == UseColour::Yes
            ? &s_instance
            : NoColourImpl::instance();
    }

} // end anon namespace
} // end namespace Catch

#elif defined( CATCH_CONFIG_COLOUR_ANSI ) //////////////////////////////////////

#include <unistd.h>

namespace Catch {
namespace {

    // use POSIX/ ANSI console terminal codes
    // Thanks to Adam Strzelecki for original contribution
    // (http://github.com/nanoant)
    // https://github.com/philsquared/Catch/pull/131
    class PosixColourImpl : public IColourImpl {
    public:
        void use( Colour::Code _colourCode ) override {
            switch( _colourCode ) {
                case Colour::None:
                case Colour::White:     return setColour( "[0m" );
                case Colour::Red:       return setColour( "[0;31m" );
                case Colour::Green:     return setColour( "[0;32m" );
                case Colour::Blue:      return setColour( "[0;34m" );
                case Colour::Cyan:      return setColour( "[0;36m" );
                case Colour::Yellow:    return setColour( "[0;33m" );
                case Colour::Grey:      return setColour( "[1;30m" );

                case Colour::LightGrey:     return setColour( "[0;37m" );
                case Colour::BrightRed:     return setColour( "[1;31m" );
                case Colour::BrightGreen:   return setColour( "[1;32m" );
                case Colour::BrightWhite:   return setColour( "[1;37m" );
                case Colour::BrightYellow:  return setColour( "[1;33m" );

                case Colour::Bright: CATCH_INTERNAL_ERROR( "not a colour" );
                default: CATCH_INTERNAL_ERROR( "Unknown colour requested" );
            }
        }
        static IColourImpl* instance() {
            static PosixColourImpl s_instance;
            return &s_instance;
        }

    private:
        void setColour( const char* _escapeCode ) {
            // The escape sequence must be flushed to console, otherwise if
            // stdin and stderr are intermixed, we'd get accidentally coloured output.
            getCurrentContext().getConfig()->stream()
                << '\033' << _escapeCode << std::flush;
        }
    };

    bool useColourOnPlatform() {
        return
#if defined(CATCH_PLATFORM_MAC) || defined(CATCH_PLATFORM_IPHONE)
            !isDebuggerActive() &&
#endif
#if !(defined(__DJGPP__) && defined(__STRICT_ANSI__))
            isatty(STDOUT_FILENO)
#else
            false
#endif
            ;
    }
    IColourImpl* platformColourInstance() {
        ErrnoGuard guard;
        auto const* config = getCurrentContext().getConfig();
        UseColour colourMode = config
            ? config->useColour()
            : UseColour::Auto;
        if( colourMode == UseColour::Auto )
            colourMode = useColourOnPlatform()
                ? UseColour::Yes
                : UseColour::No;
        return colourMode == UseColour::Yes
            ? PosixColourImpl::instance()
            : NoColourImpl::instance();
    }

} // end anon namespace
} // end namespace Catch

#else  // not Windows or ANSI ///////////////////////////////////////////////

namespace Catch {

    static IColourImpl* platformColourInstance() { return NoColourImpl::instance(); }

} // end namespace Catch

#endif // Windows/ ANSI/ None

namespace Catch {

    Colour::Colour( Code _colourCode ) { use( _colourCode ); }
    Colour::Colour( Colour&& other ) noexcept {
        m_moved = other.m_moved;
        other.m_moved = true;
    }
    Colour& Colour::operator=( Colour&& other ) noexcept {
        m_moved = other.m_moved;
        other.m_moved  = true;
        return *this;
    }

    Colour::~Colour(){ if( !m_moved ) use( None ); }

    void Colour::use( Code _colourCode ) {
        static IColourImpl* impl = platformColourInstance();
        // Strictly speaking, this cannot possibly happen.
        // However, under some conditions it does happen (see #1626),
        // and this change is small enough that we can let practicality
        // triumph over purity in this case.
        if (impl != nullptr) {
            impl->use( _colourCode );
        }
    }

    std::ostream& operator << ( std::ostream& os, Colour const& ) {
        return os;
    }

} // end namespace Catch

#if defined(__clang__)
#    pragma clang diagnostic pop
#endif

