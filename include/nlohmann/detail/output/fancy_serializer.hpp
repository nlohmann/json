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
#include <map>
#include <sstream>
#include <functional>
#include <vector>

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/conversions/to_chars.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/detail/output/primitive_serializer.hpp>
#include <nlohmann/detail/json_pointer.hpp>

namespace nlohmann
{

namespace details
{
// Some metaprogramming stuff. The point here is to distinguish
// functions and function objects that take 'json' and
// 'json_pointer<json>' as the first argument. This can't be done
// conventionally because there are implicit conversions in both
// directions, so a function type that matches one will match the
// other. (The conversion from json to json_pointer doesn't really
// exist if you try to use it, but it does in the SFIANE context.)
//
// So we define takes_argument<Func, Arg> to see if Func(Arg) is
// not only legal but without undergoing any conversions on
// Arg. That's where 'metawrapper' comes into play. We actually
// check if Func(metawrapper<Arg>) is legal. That takes up the one
// implicit conversion that's allowed.
//
// See also the uses below.

template<typename... Ts> struct make_void
{
    typedef void type;
};
template<typename... Ts> using void_t = typename make_void<Ts...>::type;

template <typename T>
struct metawrapper
{
    operator T const& ();
};

template <typename = void, typename F = void, typename ...Args>
struct takes_arguments_impl : std::false_type { };

template <typename F, typename ...Args>
struct takes_arguments_impl<void_t<decltype(std::declval<F>()(metawrapper<Args>()...))>, F, Args...> : std::true_type { };

template<typename F, typename ...Args>
struct takes_arguments : takes_arguments_impl<void, F, Args...> { };
}

struct print_style
{
    unsigned int indent_step = 4;
    char indent_char = ' ';

    unsigned int depth_limit = std::numeric_limits<unsigned>::max();

    unsigned int strings_maximum_length = 0;

    bool space_after_colon = false;
    bool space_after_comma = false;

    bool multiline = false;

    print_style() = default;

    print_style(bool s_colon, bool s_comma, bool ml)
        : space_after_colon(s_colon), space_after_comma(s_comma), multiline(ml)
    {}

    static const print_style preset_compact;
    static const print_style preset_one_line;
    static const print_style preset_multiline;
};

const print_style print_style::preset_compact(false, false, false);
const print_style print_style::preset_one_line(true, true, false);
const print_style print_style::preset_multiline(true, true, true);

template<typename BasicJsonType>
class basic_print_stylizer
{
  public:
    using string_t = typename BasicJsonType::string_t;
    using json_pointer_t = json_pointer<BasicJsonType>;

    using json_matcher_predicate = std::function<bool (const BasicJsonType&)>;
    using context_matcher_predicate = std::function<bool (const json_pointer_t&)>;
    using matcher_predicate = std::function<bool (const json_pointer_t&, const BasicJsonType&)>;

    basic_print_stylizer(print_style const& ds)
        : default_style(ds)
    {}

    basic_print_stylizer() = default;

  public:
    const print_style& get_default_style() const
    {
        return default_style;
    }

    print_style& get_default_style()
    {
        return default_style;
    }

    const print_style* get_new_style_or_active(
        const json_pointer_t& pointer,
        const json& j,
        const print_style* active_style) const
    {
        for (auto const& pair : styles)
        {
            if (pair.first(pointer, j))
            {
                return &pair.second;
            }
        }
        return active_style;
    }

    print_style& register_style(
        matcher_predicate p,
        print_style style = print_style())
    {
        styles.emplace_back(p, style);
        return styles.back().second;
    }

    // Predicate is conceptually 'bool (json)' here
    template <typename Predicate>
    auto register_style(
        Predicate p,
        print_style style = print_style())
    -> typename std::enable_if<details::takes_arguments<Predicate, BasicJsonType>::value, print_style&>::type
    {
        auto wrapper = [p](const json_pointer_t&, const BasicJsonType & j)
        {
            return p(j);
        };
        styles.emplace_back(wrapper, style);
        return styles.back().second;
    }

    // Predicate is conceptually 'bool (json_pointer)' here...
    //
    // ...But we have to 'json' instead (or rather, BasicJsonType)
    // because json has an apparent (in the SFIANE context) implicit
    // conversion from and two everything. Including
    // 'metawrapper<json_pointer>'. So if you pass 'bool (json)', it
    // will look like it can pass a metawrapper<json_pointer> to it
    template <typename Predicate>
    auto register_style(
        Predicate p,
        print_style style = print_style())
    -> typename std::enable_if < !details::takes_arguments<Predicate, BasicJsonType>::value, print_style& >::type
    {
        auto wrapper = [p](const json_pointer_t& c, const BasicJsonType&)
        {
            return p(c);
        };
        styles.emplace_back(wrapper, style);
        return styles.back().second;
    }

    print_style& register_key_matcher_style(
        string_t str,
        print_style style = print_style())
    {
        return register_style([str](const json_pointer_t& pointer)
        {
            return (pointer.cbegin() != pointer.cend())
                   && (*pointer.crbegin() == str);
        },
        style);
    }

    print_style& last_registered_style()
    {
        return styles.back().second;
    }

  private:
    print_style default_style;
    std::vector<std::pair<matcher_predicate, print_style>> styles;
};

namespace detail
{
///////////////////
// serialization //
///////////////////

template<typename BasicJsonType>
class fancy_serializer
{
    using stylizer_t = basic_print_stylizer<BasicJsonType>;
    using primitive_serializer_t = primitive_serializer<BasicJsonType>;
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using json_pointer_t = json_pointer<BasicJsonType>;
    static constexpr uint8_t UTF8_ACCEPT = 0;
    static constexpr uint8_t UTF8_REJECT = 1;

  public:
    /*!
    @param[in] s  output stream to serialize to
    @param[in] ichar  indentation character to use
    */
    fancy_serializer(output_adapter_t<char> s,
                     const stylizer_t& st)
        : o(std::move(s)), stylizer(st),
          indent_string(512, st.get_default_style().indent_char)
    {}

    // delete because of pointer members
    fancy_serializer(const fancy_serializer&) = delete;
    fancy_serializer& operator=(const fancy_serializer&) = delete;

    void dump(const BasicJsonType& val, const bool ensure_ascii)
    {
        dump(val, ensure_ascii, 0, &stylizer.get_default_style(), json_pointer_t());
    }

  private:
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
    @param[in] depth           the current recursive depth
    */
    void dump(const BasicJsonType& val,
              const bool ensure_ascii,
              const unsigned int depth,
              const print_style* active_style,
              const json_pointer_t& context)
    {
        active_style = stylizer.get_new_style_or_active(context, val, active_style);

        switch (val.m_type)
        {
            case value_t::object:
            {
                dump_object(val, ensure_ascii, depth, active_style, context);
                return;
            }

            case value_t::array:
            {
                dump_array(val, ensure_ascii, depth, active_style, context);
                return;
            }

            case value_t::string:
            {
                dump_string(*val.m_value.string, ensure_ascii, active_style);
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
    template <typename Iterator>
    void dump_object_key_value(
        Iterator i, bool ensure_ascii, unsigned int depth,
        const print_style* active_style,
        const json_pointer_t& context)
    {
        const auto new_indent = (depth + 1) * active_style->indent_step * active_style->multiline;
        const int newline_len = active_style->space_after_colon;

        o->write_characters(indent_string.c_str(), new_indent);
        o->write_character('\"');
        prim_serializer.dump_escaped(*o, i->first, ensure_ascii);
        o->write_characters("\": ", 2 + newline_len);
        dump(i->second, ensure_ascii, depth + 1, active_style, context.appended(i->first));
    }

    void dump_object(const BasicJsonType& val,
                     bool ensure_ascii,
                     unsigned int depth,
                     const print_style* active_style,
                     const json_pointer_t& context)
    {
        if (val.m_value.object->empty())
        {
            o->write_characters("{}", 2);
            return;
        }
        else if (depth >= active_style->depth_limit)
        {
            o->write_characters("{...}", 5);
            return;
        }

        // variable to hold indentation for recursive calls
        const auto old_indent = depth * active_style->indent_step * active_style->multiline;
        const auto new_indent = (depth + 1) * active_style->indent_step * active_style->multiline;
        if (JSON_UNLIKELY(indent_string.size() < new_indent))
        {
            indent_string.resize(indent_string.size() * 2, active_style->indent_char);
        }
        const int newline_len = (active_style->multiline ? 1 : 0);

        o->write_characters("{\n", 1 + newline_len);

        // first n-1 elements
        auto i = val.m_value.object->cbegin();
        for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
        {
            dump_object_key_value(i, ensure_ascii, depth, active_style, context);
            o->write_characters(",\n", 1 + newline_len);
        }

        // last element
        assert(i != val.m_value.object->cend());
        assert(std::next(i) == val.m_value.object->cend());
        dump_object_key_value(i, ensure_ascii, depth, active_style, context);

        o->write_characters("\n", newline_len);
        o->write_characters(indent_string.c_str(), old_indent);
        o->write_character('}');
    }

    void dump_array(const BasicJsonType& val,
                    bool ensure_ascii,
                    unsigned int depth,
                    const print_style* active_style,
                    const json_pointer_t& context)
    {
        if (val.m_value.array->empty())
        {
            o->write_characters("[]", 2);
            return;
        }
        else if (depth >= active_style->depth_limit)
        {
            o->write_characters("[...]", 5);
            return;
        }

        // variable to hold indentation for recursive calls
        const auto old_indent = depth * active_style->indent_step * active_style->multiline;;
        const auto new_indent = (depth + 1) * active_style->indent_step * active_style->multiline;;
        if (JSON_UNLIKELY(indent_string.size() < new_indent))
        {
            indent_string.resize(indent_string.size() * 2, active_style->indent_char);
        }
        const int newline_len = (active_style->multiline ? 1 : 0);

        using pair = std::pair<const char*, int>;
        auto comma_string =
            active_style->multiline         ? pair(",\n", 2) :
            active_style->space_after_comma ? pair(", ", 2) :
            pair(",", 1);

        o->write_characters("[\n", 1 + newline_len);

        // first n-1 elements
        for (auto i = val.m_value.array->cbegin();
                i != val.m_value.array->cend() - 1; ++i)
        {
            o->write_characters(indent_string.c_str(), new_indent);
            dump(*i, ensure_ascii, depth + 1, active_style,
                 context.appended(i - val.m_value.array->cbegin()));
            o->write_characters(comma_string.first, comma_string.second);
        }

        // last element
        assert(not val.m_value.array->empty());
        o->write_characters(indent_string.c_str(), new_indent);
        dump(val.m_value.array->back(), ensure_ascii, depth + 1, active_style,
             context.appended(val.m_value.array->size()));

        o->write_characters("\n", newline_len);
        o->write_characters(indent_string.c_str(), old_indent);
        o->write_character(']');
    }

    void dump_string(const string_t& str, bool ensure_ascii,
                     const print_style* active_style)
    {
        o->write_character('\"');
        if (active_style->strings_maximum_length == 0)
        {
            prim_serializer.dump_escaped(*o, str, ensure_ascii);
        }
        else
        {
            std::stringstream ss;
            nlohmann::detail::output_adapter<char> o_string(ss);
            nlohmann::detail::output_adapter_t<char> oo_string = o_string;
            prim_serializer.dump_escaped(*oo_string, str, ensure_ascii);

            std::string full_str = ss.str();
            if (full_str.size() <= active_style->strings_maximum_length)
            {
                o->write_characters(full_str.c_str(), full_str.size());
            }
            else
            {
                const unsigned start_len = [](unsigned int maxl)
                {
                    if (maxl <= 3)
                    {
                        // There is only room for the ellipsis,
                        // no characters from the string
                        return 0u;
                    }
                    else if (maxl <= 5)
                    {
                        // With four allowed characters, we add in the
                        // first from the string. With five, we add in
                        // the *last* instead, so still just one at
                        // the start.
                        return 1u;
                    }
                    else
                    {
                        // We subtract three for the ellipsis
                        // and one for the last character.
                        return maxl - 4;
                    }
                }(active_style->strings_maximum_length);

                const unsigned end_len =
                    active_style->strings_maximum_length >= 5 ? 1 : 0;

                const unsigned ellipsis_length =
                    active_style->strings_maximum_length >= 3
                    ? 3
                    : active_style->strings_maximum_length;

                o->write_characters(full_str.c_str(), start_len);
                o->write_characters("...", ellipsis_length);
                o->write_characters(full_str.c_str() + str.size() - end_len, end_len);
            }
        }
        o->write_character('\"');
    }

  private:
    /// the output of the fancy_serializer
    output_adapter_t<char> o = nullptr;

    /// Used for serializing "base" objects. Strings are sort of
    /// counted in this, but not completely.
    primitive_serializer_t prim_serializer;

    /// the indentation string
    string_t indent_string;

    /// Output style
    const stylizer_t stylizer;
};
}

template<typename BasicJsonType>
std::ostream& fancy_dump(std::ostream& o, const BasicJsonType& j,
                         basic_print_stylizer<BasicJsonType> const& stylizer)
{
    // do the actual serialization
    detail::fancy_serializer<BasicJsonType> s(detail::output_adapter<char>(o), stylizer);
    s.dump(j, false);
    return o;
}

template<typename BasicJsonType>
std::ostream& fancy_dump(std::ostream& o, const BasicJsonType& j, print_style style)
{
    basic_print_stylizer<BasicJsonType> stylizer(style);
    return fancy_dump(o, j, stylizer);
}

}
