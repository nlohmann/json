
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_common.hpp>
#include <catch2/internal/catch_enforce.hpp>
#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_debug_console.hpp>
#include <catch2/internal/catch_stringref.hpp>
#include <catch2/internal/catch_singletons.hpp>
#include <catch2/internal/catch_unique_ptr.hpp>

#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

namespace Catch {

    Catch::IStream::~IStream() = default;

namespace Detail {
    namespace {
        template<typename WriterF, std::size_t bufferSize=256>
        class StreamBufImpl : public std::streambuf {
            char data[bufferSize];
            WriterF m_writer;

        public:
            StreamBufImpl() {
                setp( data, data + sizeof(data) );
            }

            ~StreamBufImpl() noexcept {
                StreamBufImpl::sync();
            }

        private:
            int overflow( int c ) override {
                sync();

                if( c != EOF ) {
                    if( pbase() == epptr() )
                        m_writer( std::string( 1, static_cast<char>( c ) ) );
                    else
                        sputc( static_cast<char>( c ) );
                }
                return 0;
            }

            int sync() override {
                if( pbase() != pptr() ) {
                    m_writer( std::string( pbase(), static_cast<std::string::size_type>( pptr() - pbase() ) ) );
                    setp( pbase(), epptr() );
                }
                return 0;
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        struct OutputDebugWriter {

            void operator()( std::string const&str ) {
                writeToDebugConsole( str );
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        class FileStream : public IStream {
            mutable std::ofstream m_ofs;
        public:
            FileStream( StringRef filename ) {
                m_ofs.open( filename.c_str() );
                CATCH_ENFORCE( !m_ofs.fail(), "Unable to open file: '" << filename << "'" );
            }
            ~FileStream() override = default;
        public: // IStream
            std::ostream& stream() const override {
                return m_ofs;
            }
        };

        ///////////////////////////////////////////////////////////////////////////

        class CoutStream : public IStream {
            mutable std::ostream m_os;
        public:
            // Store the streambuf from cout up-front because
            // cout may get redirected when running tests
            CoutStream() : m_os( Catch::cout().rdbuf() ) {}
            ~CoutStream() override = default;

        public: // IStream
            std::ostream& stream() const override { return m_os; }
        };

        ///////////////////////////////////////////////////////////////////////////

        class DebugOutStream : public IStream {
            Detail::unique_ptr<StreamBufImpl<OutputDebugWriter>> m_streamBuf;
            mutable std::ostream m_os;
        public:
            DebugOutStream()
            :   m_streamBuf( Detail::make_unique<StreamBufImpl<OutputDebugWriter>>() ),
                m_os( m_streamBuf.get() )
            {}

            ~DebugOutStream() override = default;

        public: // IStream
            std::ostream& stream() const override { return m_os; }
        };

    } // unnamed namespace
} // namespace Detail

    ///////////////////////////////////////////////////////////////////////////

    auto makeStream( StringRef const &filename ) -> IStream const* {
        if( filename.empty() )
            return new Detail::CoutStream();
        else if( filename[0] == '%' ) {
            if( filename == "%debug" )
                return new Detail::DebugOutStream();
            else
                CATCH_ERROR( "Unrecognised stream: '" << filename << "'" );
        }
        else
            return new Detail::FileStream( filename );
    }


    // This class encapsulates the idea of a pool of ostringstreams that can be reused.
    struct StringStreams {
        std::vector<Detail::unique_ptr<std::ostringstream>> m_streams;
        std::vector<std::size_t> m_unused;
        std::ostringstream m_referenceStream; // Used for copy state/ flags from

        auto add() -> std::size_t {
            if( m_unused.empty() ) {
                m_streams.push_back( Detail::unique_ptr<std::ostringstream>( new std::ostringstream ) );
                return m_streams.size()-1;
            }
            else {
                auto index = m_unused.back();
                m_unused.pop_back();
                return index;
            }
        }

        void release( std::size_t index ) {
            m_streams[index]->copyfmt( m_referenceStream ); // Restore initial flags and other state
            m_unused.push_back(index);
        }
    };

    ReusableStringStream::ReusableStringStream()
    :   m_index( Singleton<StringStreams>::getMutable().add() ),
        m_oss( Singleton<StringStreams>::getMutable().m_streams[m_index].get() )
    {}

    ReusableStringStream::~ReusableStringStream() {
        static_cast<std::ostringstream*>( m_oss )->str("");
        m_oss->clear();
        Singleton<StringStreams>::getMutable().release( m_index );
    }

    std::string ReusableStringStream::str() const {
        return static_cast<std::ostringstream*>( m_oss )->str();
    }

    void ReusableStringStream::str( std::string const& str ) {
        static_cast<std::ostringstream*>( m_oss )->str( str );
    }


    ///////////////////////////////////////////////////////////////////////////


#ifndef CATCH_CONFIG_NOSTDOUT // If you #define this you must implement these functions
    std::ostream& cout() { return std::cout; }
    std::ostream& cerr() { return std::cerr; }
    std::ostream& clog() { return std::clog; }
#endif
}
