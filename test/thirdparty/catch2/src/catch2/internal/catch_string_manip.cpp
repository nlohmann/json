
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_string_manip.hpp>
#include <catch2/internal/catch_stringref.hpp>

#include <algorithm>
#include <ostream>
#include <cstring>
#include <cctype>
#include <vector>

namespace Catch {

    namespace {
        char toLowerCh(char c) {
            return static_cast<char>( std::tolower( static_cast<unsigned char>(c) ) );
        }
    }

    bool startsWith( std::string const& s, std::string const& prefix ) {
        return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
    }
    bool startsWith( std::string const& s, char prefix ) {
        return !s.empty() && s[0] == prefix;
    }
    bool endsWith( std::string const& s, std::string const& suffix ) {
        return s.size() >= suffix.size() && std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
    }
    bool endsWith( std::string const& s, char suffix ) {
        return !s.empty() && s[s.size()-1] == suffix;
    }
    bool contains( std::string const& s, std::string const& infix ) {
        return s.find( infix ) != std::string::npos;
    }
    void toLowerInPlace( std::string& s ) {
        std::transform( s.begin(), s.end(), s.begin(), toLowerCh );
    }
    std::string toLower( std::string const& s ) {
        std::string lc = s;
        toLowerInPlace( lc );
        return lc;
    }
    std::string trim( std::string const& str ) {
        static char const* whitespaceChars = "\n\r\t ";
        std::string::size_type start = str.find_first_not_of( whitespaceChars );
        std::string::size_type end = str.find_last_not_of( whitespaceChars );

        return start != std::string::npos ? str.substr( start, 1+end-start ) : std::string();
    }

    StringRef trim(StringRef ref) {
        const auto is_ws = [](char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        };
        size_t real_begin = 0;
        while (real_begin < ref.size() && is_ws(ref[real_begin])) { ++real_begin; }
        size_t real_end = ref.size();
        while (real_end > real_begin && is_ws(ref[real_end - 1])) { --real_end; }

        return ref.substr(real_begin, real_end - real_begin);
    }

    bool replaceInPlace( std::string& str, std::string const& replaceThis, std::string const& withThis ) {
        bool replaced = false;
        std::size_t i = str.find( replaceThis );
        while( i != std::string::npos ) {
            replaced = true;
            str = str.substr( 0, i ) + withThis + str.substr( i+replaceThis.size() );
            if( i < str.size()-withThis.size() )
                i = str.find( replaceThis, i+withThis.size() );
            else
                i = std::string::npos;
        }
        return replaced;
    }

    std::vector<StringRef> splitStringRef( StringRef str, char delimiter ) {
        std::vector<StringRef> subStrings;
        std::size_t start = 0;
        for(std::size_t pos = 0; pos < str.size(); ++pos ) {
            if( str[pos] == delimiter ) {
                if( pos - start > 1 )
                    subStrings.push_back( str.substr( start, pos-start ) );
                start = pos+1;
            }
        }
        if( start < str.size() )
            subStrings.push_back( str.substr( start, str.size()-start ) );
        return subStrings;
    }

    pluralise::pluralise( std::size_t count, std::string const& label )
    :   m_count( count ),
        m_label( label )
    {}

    std::ostream& operator << ( std::ostream& os, pluralise const& pluraliser ) {
        os << pluraliser.m_count << ' ' << pluraliser.m_label;
        if( pluraliser.m_count != 1 )
            os << 's';
        return os;
    }

}
