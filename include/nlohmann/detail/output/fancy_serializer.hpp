#pragma once

#include <algorithm> // reverse, remove, fill, find, none_of
#include <array> // array
#include <cassert> // assert
#include <ciso646> // and, or
#include <clocale> // localeconv, lconv
#include <cmath> // labs, isfinite, isnan, signbit
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // uint8_t
#include <cstdio> // snprintf
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // is_same

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/conversions/to_chars.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/detail/output/primitive_serializer.hpp>

namespace nlohmann
{

struct fancy_serializer_style
{
    unsigned int indent_step = 0;
    char indent_char = ' ';
};

namespace detail
{
///////////////////
// serialization //
///////////////////

template<typename BasicJsonType>
class fancy_serializer
{
    using primitive_serializer_t = primitive_serializer<BasicJsonType>;
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    static constexpr uint8_t UTF8_ACCEPT = 0;
    static constexpr uint8_t UTF8_REJECT = 1;

  public:
    /*!
    @param[in] s  output stream to serialize to
    @param[in] ichar  indentation character to use
    */
    fancy_serializer(output_adapter_t<char> s,
                     const fancy_serializer_style& st)
        : o(std::move(s)), indent_string(512, st.indent_char), style(st)
    {}

    // delete because of pointer members
    fancy_serializer(const fancy_serializer&) = delete;
    fancy_serializer& operator=(const fancy_serializer&) = delete;

    /*!
    @brief internal implementation of the serialization function

    This function is called by the public member function dump and organizes
    the serialization internally. The indentation level is propagated as
    additional parameter. In case of arrays and objects, the function is
    called recursively.

    - strings and object keys are escaped using `escape_string()`
    - integer numbers are converted implicitly via `operator<<`
    - floating-point numbers are converted to a string using `"%g"` format

    @param[in] val             value to serialize
    @param[in] pretty_print    whether the output shall be pretty-printed
    @param[in] indent_step     the indent level
    @param[in] current_indent  the current indent level (only used internally)
    */
    void dump(const BasicJsonType& val,
              const bool ensure_ascii,
              const unsigned int current_indent = 0)
    {
        switch (val.m_type)
        {
            case value_t::object:
            {
                if (val.m_value.object->empty())
                {
                    o->write_characters("{}", 2);
                    return;
                }

                if (style.indent_step > 0)
                {
                    o->write_characters("{\n", 2);

                    // variable to hold indentation for recursive calls
                    const auto new_indent = current_indent + style.indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    // first n-1 elements
                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        o->write_character('\"');
                        prim_serializer.dump_escaped(*o, i->first, ensure_ascii);
                        o->write_characters("\": ", 3);
                        dump(i->second, ensure_ascii, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    // last element
                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_characters(indent_string.c_str(), new_indent);
                    o->write_character('\"');
                    prim_serializer.dump_escaped(*o, i->first, ensure_ascii);
                    o->write_characters("\": ", 3);
                    dump(i->second, ensure_ascii, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character('}');
                }
                else
                {
                    o->write_character('{');

                    // first n-1 elements
                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_character('\"');
                        prim_serializer.dump_escaped(*o, i->first, ensure_ascii);
                        o->write_characters("\":", 2);
                        dump(i->second, ensure_ascii, current_indent);
                        o->write_character(',');
                    }

                    // last element
                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_character('\"');
                    prim_serializer.dump_escaped(*o, i->first, ensure_ascii);
                    o->write_characters("\":", 2);
                    dump(i->second, ensure_ascii, current_indent);

                    o->write_character('}');
                }

                return;
            }

            case value_t::array:
            {
                if (val.m_value.array->empty())
                {
                    o->write_characters("[]", 2);
                    return;
                }

                if (style.indent_step > 0)
                {
                    o->write_characters("[\n", 2);

                    // variable to hold indentation for recursive calls
                    const auto new_indent = current_indent + style.indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    // first n-1 elements
                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        dump(*i, ensure_ascii, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    // last element
                    assert(not val.m_value.array->empty());
                    o->write_characters(indent_string.c_str(), new_indent);
                    dump(val.m_value.array->back(), ensure_ascii, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character(']');
                }
                else
                {
                    o->write_character('[');

                    // first n-1 elements
                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        dump(*i, ensure_ascii, current_indent);
                        o->write_character(',');
                    }

                    // last element
                    assert(not val.m_value.array->empty());
                    dump(val.m_value.array->back(), ensure_ascii, current_indent);

                    o->write_character(']');
                }

                return;
            }

            case value_t::string:
            {
                o->write_character('\"');
                prim_serializer.dump_escaped(*o, *val.m_value.string, ensure_ascii);
                o->write_character('\"');
                return;
            }

            case value_t::boolean:
            {
                if (val.m_value.boolean)
                {
                    o->write_characters("true", 4);
                }
                else
                {
                    o->write_characters("false", 5);
                }
                return;
            }

            case value_t::number_integer:
            {
                prim_serializer.dump_integer(*o, val.m_value.number_integer);
                return;
            }

            case value_t::number_unsigned:
            {
                prim_serializer.dump_integer(*o, val.m_value.number_unsigned);
                return;
            }

            case value_t::number_float:
            {
                prim_serializer.dump_float(*o, val.m_value.number_float);
                return;
            }

            case value_t::discarded:
            {
                o->write_characters("<discarded>", 11);
                return;
            }

            case value_t::null:
            {
                o->write_characters("null", 4);
                return;
            }
        }
    }

  private:
    /// the output of the fancy_serializer
    output_adapter_t<char> o = nullptr;

    /// the indentation string
    string_t indent_string;

    /// Used for serializing "base" objects. Strings are sort of
    /// counted in this, but not completely.
    primitive_serializer_t prim_serializer;

    /// Output style
    fancy_serializer_style style;
};
}

template<typename BasicJsonType>
std::ostream& fancy_dump(std::ostream& o, const BasicJsonType& j,
                         fancy_serializer_style style)
{
    // do the actual serialization
    detail::fancy_serializer<BasicJsonType> s(detail::output_adapter<char>(o), style);
    s.dump(j, false, 0u);
    return o;
}

}
