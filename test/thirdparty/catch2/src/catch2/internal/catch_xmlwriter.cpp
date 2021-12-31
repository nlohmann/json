
//              Copyright Catch2 Authors
// Distributed under the Boost Software License, Version 1.0.
//   (See accompanying file LICENSE_1_0.txt or copy at
//        https://www.boost.org/LICENSE_1_0.txt)

// SPDX-License-Identifier: BSL-1.0
#include <catch2/internal/catch_xmlwriter.hpp>

#include <catch2/internal/catch_enforce.hpp>

#include <iomanip>
#include <type_traits>

namespace Catch {

namespace {

    size_t trailingBytes(unsigned char c) {
        if ((c & 0xE0) == 0xC0) {
            return 2;
        }
        if ((c & 0xF0) == 0xE0) {
            return 3;
        }
        if ((c & 0xF8) == 0xF0) {
            return 4;
        }
        CATCH_INTERNAL_ERROR("Invalid multibyte utf-8 start byte encountered");
    }

    uint32_t headerValue(unsigned char c) {
        if ((c & 0xE0) == 0xC0) {
            return c & 0x1F;
        }
        if ((c & 0xF0) == 0xE0) {
            return c & 0x0F;
        }
        if ((c & 0xF8) == 0xF0) {
            return c & 0x07;
        }
        CATCH_INTERNAL_ERROR("Invalid multibyte utf-8 start byte encountered");
    }

    void hexEscapeChar(std::ostream& os, unsigned char c) {
        std::ios_base::fmtflags f(os.flags());
        os << "\\x"
            << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(c);
        os.flags(f);
    }

    bool shouldNewline(XmlFormatting fmt) {
        return !!(static_cast<std::underlying_type_t<XmlFormatting>>(fmt & XmlFormatting::Newline));
    }

    bool shouldIndent(XmlFormatting fmt) {
        return !!(static_cast<std::underlying_type_t<XmlFormatting>>(fmt & XmlFormatting::Indent));
    }

} // anonymous namespace

    XmlFormatting operator | (XmlFormatting lhs, XmlFormatting rhs) {
        return static_cast<XmlFormatting>(
            static_cast<std::underlying_type_t<XmlFormatting>>(lhs) |
            static_cast<std::underlying_type_t<XmlFormatting>>(rhs)
        );
    }

    XmlFormatting operator & (XmlFormatting lhs, XmlFormatting rhs) {
        return static_cast<XmlFormatting>(
            static_cast<std::underlying_type_t<XmlFormatting>>(lhs) &
            static_cast<std::underlying_type_t<XmlFormatting>>(rhs)
        );
    }


    XmlEncode::XmlEncode( std::string const& str, ForWhat forWhat )
    :   m_str( str ),
        m_forWhat( forWhat )
    {}

    void XmlEncode::encodeTo( std::ostream& os ) const {
        // Apostrophe escaping not necessary if we always use " to write attributes
        // (see: http://www.w3.org/TR/xml/#syntax)

        for( std::size_t idx = 0; idx < m_str.size(); ++ idx ) {
            unsigned char c = m_str[idx];
            switch (c) {
            case '<':   os << "&lt;"; break;
            case '&':   os << "&amp;"; break;

            case '>':
                // See: http://www.w3.org/TR/xml/#syntax
                if (idx > 2 && m_str[idx - 1] == ']' && m_str[idx - 2] == ']')
                    os << "&gt;";
                else
                    os << c;
                break;

            case '\"':
                if (m_forWhat == ForAttributes)
                    os << "&quot;";
                else
                    os << c;
                break;

            default:
                // Check for control characters and invalid utf-8

                // Escape control characters in standard ascii
                // see http://stackoverflow.com/questions/404107/why-are-control-characters-illegal-in-xml-1-0
                if (c < 0x09 || (c > 0x0D && c < 0x20) || c == 0x7F) {
                    hexEscapeChar(os, c);
                    break;
                }

                // Plain ASCII: Write it to stream
                if (c < 0x7F) {
                    os << c;
                    break;
                }

                // UTF-8 territory
                // Check if the encoding is valid and if it is not, hex escape bytes.
                // Important: We do not check the exact decoded values for validity, only the encoding format
                // First check that this bytes is a valid lead byte:
                // This means that it is not encoded as 1111 1XXX
                // Or as 10XX XXXX
                if (c <  0xC0 ||
                    c >= 0xF8) {
                    hexEscapeChar(os, c);
                    break;
                }

                auto encBytes = trailingBytes(c);
                // Are there enough bytes left to avoid accessing out-of-bounds memory?
                if (idx + encBytes - 1 >= m_str.size()) {
                    hexEscapeChar(os, c);
                    break;
                }
                // The header is valid, check data
                // The next encBytes bytes must together be a valid utf-8
                // This means: bitpattern 10XX XXXX and the extracted value is sane (ish)
                bool valid = true;
                uint32_t value = headerValue(c);
                for (std::size_t n = 1; n < encBytes; ++n) {
                    unsigned char nc = m_str[idx + n];
                    valid &= ((nc & 0xC0) == 0x80);
                    value = (value << 6) | (nc & 0x3F);
                }

                if (
                    // Wrong bit pattern of following bytes
                    (!valid) ||
                    // Overlong encodings
                    (value < 0x80) ||
                    (0x80 <= value && value < 0x800   && encBytes > 2) ||
                    (0x800 < value && value < 0x10000 && encBytes > 3) ||
                    // Encoded value out of range
                    (value >= 0x110000)
                    ) {
                    hexEscapeChar(os, c);
                    break;
                }

                // If we got here, this is in fact a valid(ish) utf-8 sequence
                for (std::size_t n = 0; n < encBytes; ++n) {
                    os << m_str[idx + n];
                }
                idx += encBytes - 1;
                break;
            }
        }
    }

    std::ostream& operator << ( std::ostream& os, XmlEncode const& xmlEncode ) {
        xmlEncode.encodeTo( os );
        return os;
    }

    XmlWriter::ScopedElement::ScopedElement( XmlWriter* writer, XmlFormatting fmt )
    :   m_writer( writer ),
        m_fmt(fmt)
    {}

    XmlWriter::ScopedElement::ScopedElement( ScopedElement&& other ) noexcept
    :   m_writer( other.m_writer ),
        m_fmt(other.m_fmt)
    {
        other.m_writer = nullptr;
        other.m_fmt = XmlFormatting::None;
    }
    XmlWriter::ScopedElement& XmlWriter::ScopedElement::operator=( ScopedElement&& other ) noexcept {
        if ( m_writer ) {
            m_writer->endElement();
        }
        m_writer = other.m_writer;
        other.m_writer = nullptr;
        m_fmt = other.m_fmt;
        other.m_fmt = XmlFormatting::None;
        return *this;
    }


    XmlWriter::ScopedElement::~ScopedElement() {
        if (m_writer) {
            m_writer->endElement(m_fmt);
        }
    }

    XmlWriter::ScopedElement& XmlWriter::ScopedElement::writeText( std::string const& text, XmlFormatting fmt ) {
        m_writer->writeText( text, fmt );
        return *this;
    }

    XmlWriter::XmlWriter( std::ostream& os ) : m_os( os )
    {
        writeDeclaration();
    }

    XmlWriter::~XmlWriter() {
        while (!m_tags.empty()) {
            endElement();
        }
        newlineIfNecessary();
    }

    XmlWriter& XmlWriter::startElement( std::string const& name, XmlFormatting fmt ) {
        ensureTagClosed();
        newlineIfNecessary();
        if (shouldIndent(fmt)) {
            m_os << m_indent;
            m_indent += "  ";
        }
        m_os << '<' << name;
        m_tags.push_back( name );
        m_tagIsOpen = true;
        applyFormatting(fmt);
        return *this;
    }

    XmlWriter::ScopedElement XmlWriter::scopedElement( std::string const& name, XmlFormatting fmt ) {
        ScopedElement scoped( this, fmt );
        startElement( name, fmt );
        return scoped;
    }

    XmlWriter& XmlWriter::endElement(XmlFormatting fmt) {
        m_indent = m_indent.substr(0, m_indent.size() - 2);

        if( m_tagIsOpen ) {
            m_os << "/>";
            m_tagIsOpen = false;
        } else {
            newlineIfNecessary();
            if (shouldIndent(fmt)) {
                m_os << m_indent;
            }
            m_os << "</" << m_tags.back() << ">";
        }
        m_os << std::flush;
        applyFormatting(fmt);
        m_tags.pop_back();
        return *this;
    }

    XmlWriter& XmlWriter::writeAttribute( std::string const& name, std::string const& attribute ) {
        if( !name.empty() && !attribute.empty() )
            m_os << ' ' << name << "=\"" << XmlEncode( attribute, XmlEncode::ForAttributes ) << '"';
        return *this;
    }

    XmlWriter& XmlWriter::writeAttribute( std::string const& name, bool attribute ) {
        m_os << ' ' << name << "=\"" << ( attribute ? "true" : "false" ) << '"';
        return *this;
    }

    XmlWriter& XmlWriter::writeText( std::string const& text, XmlFormatting fmt) {
        if( !text.empty() ){
            bool tagWasOpen = m_tagIsOpen;
            ensureTagClosed();
            if (tagWasOpen && shouldIndent(fmt)) {
                m_os << m_indent;
            }
            m_os << XmlEncode( text );
            applyFormatting(fmt);
        }
        return *this;
    }

    XmlWriter& XmlWriter::writeComment( std::string const& text, XmlFormatting fmt) {
        ensureTagClosed();
        if (shouldIndent(fmt)) {
            m_os << m_indent;
        }
        m_os << "<!--" << text << "-->";
        applyFormatting(fmt);
        return *this;
    }

    void XmlWriter::writeStylesheetRef( std::string const& url ) {
        m_os << "<?xml-stylesheet type=\"text/xsl\" href=\"" << url << "\"?>\n";
    }

    XmlWriter& XmlWriter::writeBlankLine() {
        ensureTagClosed();
        m_os << '\n';
        return *this;
    }

    void XmlWriter::ensureTagClosed() {
        if( m_tagIsOpen ) {
            m_os << '>' << std::flush;
            newlineIfNecessary();
            m_tagIsOpen = false;
        }
    }

    void XmlWriter::applyFormatting(XmlFormatting fmt) {
        m_needsNewline = shouldNewline(fmt);
    }

    void XmlWriter::writeDeclaration() {
        m_os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    }

    void XmlWriter::newlineIfNecessary() {
        if( m_needsNewline ) {
            m_os << std::endl;
            m_needsNewline = false;
        }
    }
}
