
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_output_redirect.hpp>
#include <catch2/internal/catch_enforce.hpp>

#include <cstdio>
#include <cstring>
#include <sstream>

#if defined(CATCH_CONFIG_NEW_CAPTURE)
    #if defined(_MSC_VER)
    #include <io.h>      //_dup and _dup2
    #define dup _dup
    #define dup2 _dup2
    #define fileno _fileno
    #else
    #include <unistd.h>  // dup and dup2
    #endif
#endif


namespace Catch {

    RedirectedStream::RedirectedStream( std::ostream& originalStream, std::ostream& redirectionStream )
    :   m_originalStream( originalStream ),
        m_redirectionStream( redirectionStream ),
        m_prevBuf( m_originalStream.rdbuf() )
    {
        m_originalStream.rdbuf( m_redirectionStream.rdbuf() );
    }

    RedirectedStream::~RedirectedStream() {
        m_originalStream.rdbuf( m_prevBuf );
    }

    RedirectedStdOut::RedirectedStdOut() : m_cout( Catch::cout(), m_rss.get() ) {}
    auto RedirectedStdOut::str() const -> std::string { return m_rss.str(); }

    RedirectedStdErr::RedirectedStdErr()
    :   m_cerr( Catch::cerr(), m_rss.get() ),
        m_clog( Catch::clog(), m_rss.get() )
    {}
    auto RedirectedStdErr::str() const -> std::string { return m_rss.str(); }

    RedirectedStreams::RedirectedStreams(std::string& redirectedCout, std::string& redirectedCerr)
    :   m_redirectedCout(redirectedCout),
        m_redirectedCerr(redirectedCerr)
    {}

    RedirectedStreams::~RedirectedStreams() {
        m_redirectedCout += m_redirectedStdOut.str();
        m_redirectedCerr += m_redirectedStdErr.str();
    }

#if defined(CATCH_CONFIG_NEW_CAPTURE)

#if defined(_MSC_VER)
    TempFile::TempFile() {
        if (tmpnam_s(m_buffer)) {
            CATCH_RUNTIME_ERROR("Could not get a temp filename");
        }
        if (fopen_s(&m_file, m_buffer, "w+")) {
            char buffer[100];
            if (strerror_s(buffer, errno)) {
                CATCH_RUNTIME_ERROR("Could not translate errno to a string");
            }
            CATCH_RUNTIME_ERROR("Could not open the temp file: '" << m_buffer << "' because: " << buffer);
        }
    }
#else
    TempFile::TempFile() {
        m_file = std::tmpfile();
        if (!m_file) {
            CATCH_RUNTIME_ERROR("Could not create a temp file.");
        }
    }

#endif

    TempFile::~TempFile() {
         // TBD: What to do about errors here?
         std::fclose(m_file);
         // We manually create the file on Windows only, on Linux
         // it will be autodeleted
#if defined(_MSC_VER)
         std::remove(m_buffer);
#endif
    }


    FILE* TempFile::getFile() {
        return m_file;
    }

    std::string TempFile::getContents() {
        std::stringstream sstr;
        char buffer[100] = {};
        std::rewind(m_file);
        while (std::fgets(buffer, sizeof(buffer), m_file)) {
            sstr << buffer;
        }
        return sstr.str();
    }

    OutputRedirect::OutputRedirect(std::string& stdout_dest, std::string& stderr_dest) :
        m_originalStdout(dup(1)),
        m_originalStderr(dup(2)),
        m_stdoutDest(stdout_dest),
        m_stderrDest(stderr_dest) {
        dup2(fileno(m_stdoutFile.getFile()), 1);
        dup2(fileno(m_stderrFile.getFile()), 2);
    }

    OutputRedirect::~OutputRedirect() {
        Catch::cout() << std::flush;
        fflush(stdout);
        // Since we support overriding these streams, we flush cerr
        // even though std::cerr is unbuffered
        Catch::cerr() << std::flush;
        Catch::clog() << std::flush;
        fflush(stderr);

        dup2(m_originalStdout, 1);
        dup2(m_originalStderr, 2);

        m_stdoutDest += m_stdoutFile.getContents();
        m_stderrDest += m_stderrFile.getContents();
    }

#endif // CATCH_CONFIG_NEW_CAPTURE

} // namespace Catch

#if defined(CATCH_CONFIG_NEW_CAPTURE)
    #if defined(_MSC_VER)
    #undef dup
    #undef dup2
    #undef fileno
    #endif
#endif
