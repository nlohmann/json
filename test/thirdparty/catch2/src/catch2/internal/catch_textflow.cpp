
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_textflow.hpp>
#include <cstring>
#include <ostream>

namespace {
    bool isWhitespace( char c ) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    bool isBreakableBefore( char c ) {
        static const char chars[] = "[({<|";
        return std::memchr( chars, c, sizeof( chars ) - 1 ) != nullptr;
    }

    bool isBreakableAfter( char c ) {
        static const char chars[] = "])}>.,:;*+-=&/\\";
        return std::memchr( chars, c, sizeof( chars ) - 1 ) != nullptr;
    }

    bool isBoundary( std::string const& line, size_t at ) {
        assert( at > 0 );
        assert( at <= line.size() );

        return at == line.size() ||
               ( isWhitespace( line[at] ) && !isWhitespace( line[at - 1] ) ) ||
               isBreakableBefore( line[at] ) ||
               isBreakableAfter( line[at - 1] );
    }

} // namespace

namespace Catch {
    namespace TextFlow {

        void Column::iterator::calcLength() {
            m_suffix = false;
            auto width = m_column.m_width - indent();
            m_end = m_pos;
            std::string const& current_line = m_column.m_string;
            if ( current_line[m_pos] == '\n' ) {
                ++m_end;
            }
            while ( m_end < current_line.size() &&
                    current_line[m_end] != '\n' ) {
                ++m_end;
            }

            if ( m_end < m_pos + width ) {
                m_len = m_end - m_pos;
            } else {
                size_t len = width;
                while ( len > 0 && !isBoundary( current_line, m_pos + len ) ) {
                    --len;
                }
                while ( len > 0 &&
                        isWhitespace( current_line[m_pos + len - 1] ) ) {
                    --len;
                }

                if ( len > 0 ) {
                    m_len = len;
                } else {
                    m_suffix = true;
                    m_len = width - 1;
                }
            }
        }

        size_t Column::iterator::indent() const {
            auto initial =
                m_pos == 0 ? m_column.m_initialIndent : std::string::npos;
            return initial == std::string::npos ? m_column.m_indent : initial;
        }

        std::string
        Column::iterator::addIndentAndSuffix( size_t position,
                                              size_t length ) const {
            std::string ret;
            const auto desired_indent = indent();
            ret.reserve( desired_indent + length + m_suffix );
            ret.append( desired_indent, ' ' );
            ret.append( m_column.m_string, position, length );
            if ( m_suffix ) {
                ret.push_back( '-' );
            }

            return ret;
        }

        Column::iterator::iterator( Column const& column ): m_column( column ) {
            assert( m_column.m_width > m_column.m_indent );
            assert( m_column.m_initialIndent == std::string::npos ||
                    m_column.m_width > m_column.m_initialIndent );
            calcLength();
            if ( m_len == 0 ) {
                m_pos = m_column.m_string.size();
            }
        }

        std::string Column::iterator::operator*() const {
            assert( m_pos <= m_end );
            return addIndentAndSuffix( m_pos, m_len );
        }

        Column::iterator& Column::iterator::operator++() {
            m_pos += m_len;
            std::string const& current_line = m_column.m_string;
            if ( m_pos < current_line.size() && current_line[m_pos] == '\n' ) {
                m_pos += 1;
            } else {
                while ( m_pos < current_line.size() &&
                        isWhitespace( current_line[m_pos] ) ) {
                    ++m_pos;
                }
            }

            if ( m_pos != current_line.size() ) {
                calcLength();
            }
            return *this;
        }

        Column::iterator Column::iterator::operator++( int ) {
            iterator prev( *this );
            operator++();
            return prev;
        }

        std::ostream& operator<<( std::ostream& os, Column const& col ) {
            bool first = true;
            for ( auto line : col ) {
                if ( first ) {
                    first = false;
                } else {
                    os << '\n';
                }
                os << line;
            }
            return os;
        }

        Column Spacer( size_t spaceWidth ) {
            Column ret{ "" };
            ret.width( spaceWidth );
            return ret;
        }

        Columns::iterator::iterator( Columns const& columns, EndTag ):
            m_columns( columns.m_columns ), m_activeIterators( 0 ) {

            m_iterators.reserve( m_columns.size() );
            for ( auto const& col : m_columns ) {
                m_iterators.push_back( col.end() );
            }
        }

        Columns::iterator::iterator( Columns const& columns ):
            m_columns( columns.m_columns ),
            m_activeIterators( m_columns.size() ) {

            m_iterators.reserve( m_columns.size() );
            for ( auto const& col : m_columns ) {
                m_iterators.push_back( col.begin() );
            }
        }

        std::string Columns::iterator::operator*() const {
            std::string row, padding;

            for ( size_t i = 0; i < m_columns.size(); ++i ) {
                const auto width = m_columns[i].width();
                if ( m_iterators[i] != m_columns[i].end() ) {
                    std::string col = *m_iterators[i];
                    row += padding;
                    row += col;

                    padding.clear();
                    if ( col.size() < width ) {
                        padding.append( width - col.size(), ' ' );
                    }
                } else {
                    padding.append( width, ' ' );
                }
            }
            return row;
        }

        Columns::iterator& Columns::iterator::operator++() {
            for ( size_t i = 0; i < m_columns.size(); ++i ) {
                if ( m_iterators[i] != m_columns[i].end() ) {
                    ++m_iterators[i];
                }
            }
            return *this;
        }

        Columns::iterator Columns::iterator::operator++( int ) {
            iterator prev( *this );
            operator++();
            return prev;
        }

        std::ostream& operator<<( std::ostream& os, Columns const& cols ) {
            bool first = true;
            for ( auto line : cols ) {
                if ( first ) {
                    first = false;
                } else {
                    os << '\n';
                }
                os << line;
            }
            return os;
        }

        Columns Column::operator+( Column const& other ) {
            Columns cols;
            cols += *this;
            cols += other;
            return cols;
        }

        Columns& Columns::operator+=( Column const& col ) {
            m_columns.push_back( col );
            return *this;
        }

        Columns Columns::operator+( Column const& col ) {
            Columns combined = *this;
            combined += col;
            return combined;
        }

    } // namespace TextFlow
} // namespace Catch
