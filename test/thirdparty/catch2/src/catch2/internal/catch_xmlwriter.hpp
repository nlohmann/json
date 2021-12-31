
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#ifndef CATCH_XMLWRITER_HPP_INCLUDED
#define CATCH_XMLWRITER_HPP_INCLUDED

#include <catch2/internal/catch_stream.hpp>
#include <catch2/internal/catch_compiler_capabilities.hpp>

// FixMe: Without this include (and something inside it), MSVC goes crazy
//        and reports that calls to XmlEncode's op << are ambiguous between
//        the declaration and definition.
//        It also has to be in the header.
#include <catch2/internal/catch_common.hpp>


#include <vector>

namespace Catch {
    enum class XmlFormatting {
        None = 0x00,
        Indent = 0x01,
        Newline = 0x02,
    };

    XmlFormatting operator | (XmlFormatting lhs, XmlFormatting rhs);
    XmlFormatting operator & (XmlFormatting lhs, XmlFormatting rhs);

    class XmlEncode {
    public:
        enum ForWhat { ForTextNodes, ForAttributes };

        XmlEncode( std::string const& str, ForWhat forWhat = ForTextNodes );

        void encodeTo( std::ostream& os ) const;

        friend std::ostream& operator << ( std::ostream& os, XmlEncode const& xmlEncode );

    private:
        std::string m_str;
        ForWhat m_forWhat;
    };

    class XmlWriter {
    public:

        class ScopedElement {
        public:
            ScopedElement( XmlWriter* writer, XmlFormatting fmt );

            ScopedElement( ScopedElement&& other ) noexcept;
            ScopedElement& operator=( ScopedElement&& other ) noexcept;

            ~ScopedElement();

            ScopedElement& writeText( std::string const& text, XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent );

            template<typename T>
            ScopedElement& writeAttribute( std::string const& name, T const& attribute ) {
                m_writer->writeAttribute( name, attribute );
                return *this;
            }

        private:
            mutable XmlWriter* m_writer = nullptr;
            XmlFormatting m_fmt;
        };

        XmlWriter( std::ostream& os = Catch::cout() );
        ~XmlWriter();

        XmlWriter( XmlWriter const& ) = delete;
        XmlWriter& operator=( XmlWriter const& ) = delete;

        XmlWriter& startElement( std::string const& name, XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent);

        ScopedElement scopedElement( std::string const& name, XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent);

        XmlWriter& endElement(XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent);

        XmlWriter& writeAttribute( std::string const& name, std::string const& attribute );

        XmlWriter& writeAttribute( std::string const& name, bool attribute );

        template<typename T>
        XmlWriter& writeAttribute( std::string const& name, T const& attribute ) {
            ReusableStringStream rss;
            rss << attribute;
            return writeAttribute( name, rss.str() );
        }

        XmlWriter& writeText( std::string const& text, XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent);

        XmlWriter& writeComment(std::string const& text, XmlFormatting fmt = XmlFormatting::Newline | XmlFormatting::Indent);

        void writeStylesheetRef( std::string const& url );

        XmlWriter& writeBlankLine();

        void ensureTagClosed();

    private:

        void applyFormatting(XmlFormatting fmt);

        void writeDeclaration();

        void newlineIfNecessary();

        bool m_tagIsOpen = false;
        bool m_needsNewline = false;
        std::vector<std::string> m_tags;
        std::string m_indent;
        std::ostream& m_os;
    };

}

#endif // CATCH_XMLWRITER_HPP_INCLUDED
