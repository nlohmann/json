
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_TEXTFLOW_HPP_INCLUDED
#define CATCH_TEXTFLOW_HPP_INCLUDED

#include <cassert>
#include <catch2/internal/catch_console_width.hpp>
#include <string>
#include <vector>

namespace Catch {
    namespace TextFlow {

        class Columns;

        class Column {
            std::string m_string;
            size_t m_width = CATCH_CONFIG_CONSOLE_WIDTH - 1;
            size_t m_indent = 0;
            size_t m_initialIndent = std::string::npos;

        public:
            class iterator {
                friend Column;
                struct EndTag {};

                Column const& m_column;
                size_t m_pos = 0;

                size_t m_len = 0;
                size_t m_end = 0;
                bool m_suffix = false;

                iterator( Column const& column, EndTag ):
                    m_column( column ), m_pos( m_column.m_string.size() ) {}

                void calcLength();

                // Returns current indention width
                size_t indent() const;

                // Creates an indented and (optionally) suffixed string from
                // current iterator position, indentation and length.
                std::string addIndentAndSuffix( size_t position,
                                                size_t length ) const;

            public:
                using difference_type = std::ptrdiff_t;
                using value_type = std::string;
                using pointer = value_type*;
                using reference = value_type&;
                using iterator_category = std::forward_iterator_tag;

                explicit iterator( Column const& column );

                std::string operator*() const;

                iterator& operator++();
                iterator operator++( int );

                bool operator==( iterator const& other ) const {
                    return m_pos == other.m_pos && &m_column == &other.m_column;
                }
                bool operator!=( iterator const& other ) const {
                    return !operator==( other );
                }
            };
            using const_iterator = iterator;

            explicit Column( std::string const& text ): m_string( text ) {}

            Column& width( size_t newWidth ) {
                assert( newWidth > 0 );
                m_width = newWidth;
                return *this;
            }
            Column& indent( size_t newIndent ) {
                m_indent = newIndent;
                return *this;
            }
            Column& initialIndent( size_t newIndent ) {
                m_initialIndent = newIndent;
                return *this;
            }

            size_t width() const { return m_width; }
            iterator begin() const { return iterator( *this ); }
            iterator end() const { return { *this, iterator::EndTag{} }; }

            friend std::ostream& operator<<( std::ostream& os,
                                             Column const& col );

            Columns operator+( Column const& other );
        };

        //! Creates a column that serves as an empty space of specific width
        Column Spacer( size_t spaceWidth );

        class Columns {
            std::vector<Column> m_columns;

        public:
            class iterator {
                friend Columns;
                struct EndTag {};

                std::vector<Column> const& m_columns;
                std::vector<Column::iterator> m_iterators;
                size_t m_activeIterators;

                iterator( Columns const& columns, EndTag );

            public:
                using difference_type = std::ptrdiff_t;
                using value_type = std::string;
                using pointer = value_type*;
                using reference = value_type&;
                using iterator_category = std::forward_iterator_tag;

                explicit iterator( Columns const& columns );

                auto operator==( iterator const& other ) const -> bool {
                    return m_iterators == other.m_iterators;
                }
                auto operator!=( iterator const& other ) const -> bool {
                    return m_iterators != other.m_iterators;
                }
                std::string operator*() const;
                iterator& operator++();
                iterator operator++( int );
            };
            using const_iterator = iterator;

            iterator begin() const { return iterator( *this ); }
            iterator end() const { return { *this, iterator::EndTag() }; }

            Columns& operator+=( Column const& col );
            Columns operator+( Column const& col );

            friend std::ostream& operator<<( std::ostream& os,
                                             Columns const& cols );
        };

    } // namespace TextFlow
} // namespace Catch
#endif // CATCH_TEXTFLOW_HPP_INCLUDED
