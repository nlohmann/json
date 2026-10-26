//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // remove, fill, find, none_of, min
#include <array> // array
#include <clocale> // localeconv, lconv
#include <cmath> // isfinite
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // uint8_t
#include <cstdio> // snprintf
#include <cstring> // memcpy, memset
#include <iterator> // next
#include <limits> // numeric_limits
#include <string> // string, char_traits
#include <type_traits> // is_same
#include <vector> // vector

#include <nlohmann/detail/conversions/to_chars.hpp>
#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/input/string_scan.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/output/error_handler.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/recursion_depth_limit.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/string_utils.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

///////////////////
// serialization //
///////////////////

template<typename BasicJsonType>
class serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    /// type of the absolute value of an integer: number_unsigned_t, or its
    /// unsigned counterpart if it is signed (it may be number_integer_t, #2573)
    using number_magnitude_t = typename std::conditional <
                               std::is_integral<number_unsigned_t>::value && std::is_signed<number_unsigned_t>::value,
                               std::make_unsigned<number_unsigned_t>,
                               std::enable_if<true, number_unsigned_t >>::type::type;
    using binary_char_t = typename BasicJsonType::binary_t::value_type;

  public:
    /*!
    @param[in] s  output adapter to serialize to; not owned by the serializer,
                  so it must outlive it (it lives at the call site)
    @param[in] ichar  indentation character to use
    @param[in] pretty_print_  whether the output shall be pretty-printed
    @param[in] ensure_ascii_ If @a ensure_ascii_ is true, all non-ASCII
    characters in the output are escaped with `\\uXXXX` sequences, and the
    result consists of ASCII characters only.
    @param[in] indent_step_  the indent level
    @param[in] error_handler_  how to react on decoding errors

    None of @a pretty_print_, @a ensure_ascii_ and @a indent_step_ change over
    the life of the serializer, so they are captured once here instead of
    being threaded through every call to @ref dump, @ref dump_container and
    @ref dump_iteratively.
    */
    serializer(output_adapter_protocol<char>& s, const char ichar,
               const bool pretty_print_ = false,
               const bool ensure_ascii_ = false,
               const std::size_t indent_step_ = 0,
               error_handler_t error_handler_ = error_handler_t::strict)
        : o(&s)
        , number_buffer() // NOLINT(readability-redundant-member-init)
        , string_buffer() // NOLINT(readability-redundant-member-init)
        , indent_char(ichar)
        , pretty_print(pretty_print_)
        , ensure_ascii(ensure_ascii_)
        , indent_step(indent_step_)
        , error_handler(error_handler_)
        , write_buffer() // NOLINT(readability-redundant-member-init)
    {}

    // deleted because of pointer members
    serializer(const serializer&) = delete;
    serializer& operator=(const serializer&) = delete;
    serializer(serializer&&) = delete;
    serializer& operator=(serializer&&) = delete;
    ~serializer() = default;

    /*!
    @brief internal implementation of the serialization function

    This function is called by the public member function dump and organizes
    the serialization internally. The indentation level is propagated as
    additional parameter. Arrays and objects are serialized without recursion,
    however deeply they are nested.

    - strings and object keys are escaped using @ref dump_escaped
    - integer numbers are converted using a digit-pair lookup table (@ref dump_integer)
    - floating-point numbers are converted to a string using @ref dump_float, which
      uses `to_chars` for IEEE-754 types and `snprintf` otherwise
    - binary values are serialized as objects containing the subtype and the
      byte array

    @param[in] val               value to serialize
    @param[in] current_indent    the current indent level (only used internally)
    */
    void dump(const BasicJsonType& val,
              const std::size_t current_indent = 0)
    {
        dump_element(val, current_indent, 0);
        flush();
    }

  JSON_PRIVATE_UNLESS_TESTED:
    /*!
    @brief serialize the object or array @a val

    Writes into the serializer's internal @ref write_buffer instead of issuing
    a virtual call per token; the public @ref dump flushes the buffer once the
    top-level value has been serialized. Scalars are written by @ref dump_scalar,
    which @ref dump_element calls without entering this function.

    Serializing a container descends into its elements, so a value nested deeply
    enough used to exhaust the call stack and terminate the process with no
    exception to catch. The descent is bounded here: once @ref recursion_depth_limit
    levels have been entered, @ref dump_iteratively writes out what is left
    without the call stack. A value nested less deeply than that - all but a
    vanishing minority - is written by exactly the code that always wrote it.

    @sa https://github.com/nlohmann/json/issues/5387
    */
    void dump_container(const BasicJsonType& val,
                        const std::size_t current_indent,
                        const std::size_t depth)
    {
        JSON_ASSERT(val.m_data.m_type == value_t::object || val.m_data.m_type == value_t::array);

        if (JSON_HEDLEY_UNLIKELY(depth >= recursion_depth_limit()))
        {
            dump_iteratively(val, current_indent);
            return;
        }

        if (val.m_data.m_type == value_t::object)
        {
            if (val.m_data.m_value.object->empty())
            {
                put_literal("{}");
                return;
            }

            if (pretty_print)
            {
                // variable to hold indentation for recursive calls
                const auto new_indent = next_indent(current_indent, indent_step);

                put_literal_indent("{\n", new_indent);

                // first n-1 elements
                auto i = val.m_data.m_value.object->cbegin();
                for (std::size_t cnt = 0; cnt < val.m_data.m_value.object->size() - 1; ++cnt, ++i)
                {
                    put_object_key(i->first, "\": ");
                    dump_element(i->second, new_indent, depth + 1);
                    put_literal_indent(",\n", new_indent);
                }

                // last element
                JSON_ASSERT(i != val.m_data.m_value.object->cend());
                JSON_ASSERT(std::next(i) == val.m_data.m_value.object->cend());
                put_object_key(i->first, "\": ");
                dump_element(i->second, new_indent, depth + 1);

                put_literal_indent("\n", current_indent);
                put_char('}');
            }
            else
            {
                put_char('{');

                // first n-1 elements
                auto i = val.m_data.m_value.object->cbegin();
                for (std::size_t cnt = 0; cnt < val.m_data.m_value.object->size() - 1; ++cnt, ++i)
                {
                    put_object_key(i->first, "\":");
                    dump_element(i->second, 0, depth + 1);
                    put_char(',');
                }

                // last element
                JSON_ASSERT(i != val.m_data.m_value.object->cend());
                JSON_ASSERT(std::next(i) == val.m_data.m_value.object->cend());
                put_object_key(i->first, "\":");
                dump_element(i->second, 0, depth + 1);

                put_char('}');
            }
            return;
        }

        if (val.m_data.m_value.array->empty())
        {
            put_literal("[]");
            return;
        }

        if (pretty_print)
        {
            // variable to hold indentation for recursive calls
            const auto new_indent = next_indent(current_indent, indent_step);

            put_literal_indent("[\n", new_indent);

            // first n-1 elements
            for (auto i = val.m_data.m_value.array->cbegin();
                    i != val.m_data.m_value.array->cend() - 1; ++i)
            {
                dump_element(*i, new_indent, depth + 1);
                put_literal_indent(",\n", new_indent);
            }

            // last element
            JSON_ASSERT(!val.m_data.m_value.array->empty());
            dump_element(val.m_data.m_value.array->back(), new_indent, depth + 1);

            put_literal_indent("\n", current_indent);
            put_char(']');
        }
        else
        {
            put_char('[');

            // first n-1 elements
            for (auto i = val.m_data.m_value.array->cbegin();
                    i != val.m_data.m_value.array->cend() - 1; ++i)
            {
                dump_element(*i, 0, depth + 1);
                put_char(',');
            }

            // last element
            JSON_ASSERT(!val.m_data.m_value.array->empty());
            dump_element(val.m_data.m_value.array->back(), 0, depth + 1);

            put_char(']');
        }
    }

  private:
    /*!
    @brief serialize an element of a container

    Most elements are scalars, which need none of the state dump_container() keeps
    for a container; writing them from here spares each the entry and exit of
    that function.
    */
    JSON_HEDLEY_ALWAYS_INLINE void dump_element(const BasicJsonType& val,
            const std::size_t current_indent,
            const std::size_t depth)
    {
        if (val.m_data.m_type == value_t::object || val.m_data.m_type == value_t::array)
        {
            dump_container(val, current_indent, depth);
        }
        else
        {
            dump_scalar(val, current_indent);
        }
    }

    /*!
    @brief write out @a val and everything below it without the call stack

    Emits the same bytes as @ref dump_container, keeping the containers it has
    entered on an explicit stack instead of descending into them. Only reached
    for values nested deeper than @ref recursion_depth_limit, which is why it is not
    written for speed: walking every value this way measured up to 20% slower on
    object-heavy documents than letting the compiler drive the descent.
    */
    void dump_iteratively(const BasicJsonType& val,
                          const std::size_t current_indent = 0)
    {
        // Scalars, empty containers and binary values are written by dump_value
        // alone, so nothing is allocated for them: only a container with
        // elements is ever pushed.
        std::vector<dump_frame> stack;

        dump_value(val, current_indent, stack);

        while (!stack.empty())
        {
            dump_frame& frame = stack.back();

            if (frame.value->m_data.m_type == value_t::object)
            {
                const auto* object = frame.value->m_data.m_value.object;

                if (frame.object_it == object->cend())
                {
                    if (pretty_print)
                    {
                        put_literal_indent("\n", frame.current_indent);
                    }

                    put_char('}');
                    stack.pop_back();
                    continue;
                }

                // the separator goes in front of every element but the first,
                // which puts exactly one between each pair and none at the end
                if (frame.object_it != object->cbegin())
                {
                    if (pretty_print)
                    {
                        put_literal(",\n");
                    }
                    else
                    {
                        put_char(',');
                    }
                }

                if (pretty_print)
                {
                    put_indent(frame.child_indent);
                }

                if (pretty_print)
                {
                    put_object_key(frame.object_it->first, "\": ");
                }
                else
                {
                    put_object_key(frame.object_it->first, "\":");
                }

                const BasicJsonType& element = frame.object_it->second;
                ++frame.object_it;

                // read everything needed from the frame before this: entering a
                // container pushes another one and can move them all
                const std::size_t element_indent = frame.child_indent;
                dump_value(element, element_indent, stack);
            }
            else
            {
                const auto* array = frame.value->m_data.m_value.array;

                if (frame.array_it == array->cend())
                {
                    if (pretty_print)
                    {
                        put_literal_indent("\n", frame.current_indent);
                    }

                    put_char(']');
                    stack.pop_back();
                    continue;
                }

                if (frame.array_it != array->cbegin())
                {
                    if (pretty_print)
                    {
                        put_literal(",\n");
                    }
                    else
                    {
                        put_char(',');
                    }
                }

                if (pretty_print)
                {
                    put_indent(frame.child_indent);
                }

                const BasicJsonType& element = *frame.array_it;
                ++frame.array_it;

                // see above
                const std::size_t element_indent = frame.child_indent;
                dump_value(element, element_indent, stack);
            }
        }
    }

  private:
    /// @brief a container that has been opened but not closed yet
    struct dump_frame
    {
        dump_frame(const BasicJsonType* value_, const std::size_t current_indent_,
                   const std::size_t child_indent_) noexcept
            : value(value_)
            , current_indent(current_indent_)
            , child_indent(child_indent_)
        {}

        /// the object or array being serialized
        const BasicJsonType* value;
        /// the element to serialize next; which of the two is live follows from
        /// the type of @a value. They are kept side by side rather than in a
        /// union, which would need its special members written out by hand, see
        /// detail/iterators/internal_iterator.hpp
        typename BasicJsonType::object_t::const_iterator object_it{};
        typename BasicJsonType::array_t::const_iterator array_it{};
        /// the indentation of the container itself, used by its closing bracket
        std::size_t current_indent;
        /// the indentation of the container's elements
        std::size_t child_indent;
    };

    /*!
    @brief serialize the value @a val, but not the elements of a container

    An object or array with elements is opened and pushed onto @a stack for
    @ref dump_iteratively to walk; everything else - including a binary value,
    which looks like an object but has no elements to descend into - is written
    out in full by @ref dump_scalar.
    */
    void dump_value(const BasicJsonType& val,
                    const std::size_t current_indent,
                    std::vector<dump_frame>& stack)
    {
        switch (val.m_data.m_type)
        {
            case value_t::object:
            {
                if (val.m_data.m_value.object->empty())
                {
                    put_literal("{}");
                    return;
                }

                std::size_t child_indent = current_indent;

                if (pretty_print)
                {
                    put_literal("{\n");
                    child_indent = next_indent(current_indent, indent_step);
                }
                else
                {
                    put_char('{');
                }

                stack.emplace_back(&val, current_indent, child_indent);
                stack.back().object_it = val.m_data.m_value.object->cbegin();
                return;
            }

            case value_t::array:
            {
                if (val.m_data.m_value.array->empty())
                {
                    put_literal("[]");
                    return;
                }

                std::size_t child_indent = current_indent;

                if (pretty_print)
                {
                    put_literal("[\n");
                    child_indent = next_indent(current_indent, indent_step);
                }
                else
                {
                    put_char('[');
                }

                stack.emplace_back(&val, current_indent, child_indent);
                stack.back().array_it = val.m_data.m_value.array->cbegin();
                return;
            }

            case value_t::string:
            case value_t::binary:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::discarded:
            case value_t::null:
            default:
                dump_scalar(val, current_indent);
                return;
        }
    }

    /*!
    @brief serialize the value @a val, which is neither an object nor an array

    Shared by @ref dump_element and @ref dump_value, so that a value is written
    the same way however deeply it is nested. A binary value is written out here
    in full: it looks like an object, but has no elements to descend into.

    @param[in] val             value to serialize; not an object or array
    @param[in] current_indent  the indentation of @a val, used for a
                               pretty-printed binary value
    */
    void dump_scalar(const BasicJsonType& val, const std::size_t current_indent)
    {
        switch (val.m_data.m_type)
        {
            case value_t::string:
            {
                dump_string_value(*val.m_data.m_value.string);
                return;
            }

            case value_t::binary:
            {
                dump_binary_value(current_indent, *val.m_data.m_value.binary);
                return;
            }

            case value_t::boolean:
            {
                if (val.m_data.m_value.boolean)
                {
                    put_literal("true");
                }
                else
                {
                    put_literal("false");
                }
                return;
            }

            case value_t::number_integer:
            {
                dump_signed_value(val.m_data.m_value.number_integer);
                return;
            }

            case value_t::number_unsigned:
            {
                dump_unsigned_value(val.m_data.m_value.number_unsigned);
                return;
            }

            case value_t::number_float:
            {
                dump_float_value(val.m_data.m_value.number_float);
                return;
            }

            case value_t::discarded:
            {
                put_literal("<discarded>");
                return;
            }

            case value_t::null:
            {
                put_literal("null");
                return;
            }

            case value_t::object: // LCOV_EXCL_LINE
            case value_t::array:  // LCOV_EXCL_LINE
            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }
    }

    /// @brief write the string @a s in quotes; kept out of line, so that the
    /// other scalars do not pay for its register needs (and the other way round)
    JSON_HEDLEY_NEVER_INLINE void dump_string_value(const string_t& s)
    {
#if JSON_LITTLE_ENDIAN_TARGET
        if (s.size() <= short_string_max && put_short_quoted(s, "\""))
        {
            return;
        }
#endif
        put_char('"');
        dump_escaped(s);
        put_char('"');
    }

    // The numbers, and the rest of what dump_scalar() writes, are left to
    // functions of their own as well: a single function holding all of them
    // saves and restores every register any of them needs, on every call. Now
    // dump_scalar() only dispatches, and each writer pays for what it uses.
    JSON_HEDLEY_NEVER_INLINE void dump_signed_value(const number_integer_t x)
    {
        dump_integer(x);
    }

    JSON_HEDLEY_NEVER_INLINE void dump_unsigned_value(const number_unsigned_t x)
    {
        dump_integer(x);
    }

    JSON_HEDLEY_NEVER_INLINE void dump_float_value(const number_float_t x)
    {
        dump_float(x);
    }

    JSON_HEDLEY_NEVER_INLINE void dump_binary_value(const std::size_t current_indent, const typename BasicJsonType::binary_t& binary)
    {
        if (pretty_print)
        {
            // variable to hold indentation for the bytes
            const auto new_indent = next_indent(current_indent, indent_step);

            put_literal_indent("{\n", new_indent);
            put_literal("\"bytes\": [");

            if (!binary.empty())
            {
                for (auto i = binary.cbegin(); i != binary.cend() - 1; ++i)
                {
                    dump_byte(*i);
                    put_literal(", ");
                }
                dump_byte(binary.back());
            }

            put_literal_indent("],\n", new_indent);

            put_literal("\"subtype\": ");
            if (binary.has_subtype())
            {
                dump_integer(binary.subtype());
            }
            else
            {
                put_literal("null");
            }
            put_literal_indent("\n", current_indent);
            put_char('}');
        }
        else
        {
            put_literal("{\"bytes\":[");

            if (!binary.empty())
            {
                for (auto i = binary.cbegin(); i != binary.cend() - 1; ++i)
                {
                    dump_byte(*i);
                    put_char(',');
                }
                dump_byte(binary.back());
            }

            put_literal("],\"subtype\":");
            if (binary.has_subtype())
            {
                dump_integer(binary.subtype());
                put_char('}');
            }
            else
            {
                put_literal("null}");
            }
        }
    }

    /*!
    @brief the indentation level to use for the children of the current value

    A very large @a indent_step can wrap the unsigned accumulation on deep
    nesting, which would silently truncate the indentation. Far harder to reach
    now that the accumulator is a std::size_t, but still reachable where that is
    32 bits wide.
    */
    static std::size_t next_indent(const std::size_t current_indent, const std::size_t indent_step)
    {
        const std::size_t new_indent = current_indent + indent_step;
        JSON_ASSERT(new_indent >= current_indent);
        return new_indent;
    }

  private:
    /*!
    @brief append the object key @a s in quotes, followed by @a tail

    @a tail is the closing quote and the colon, followed by a space when
    pretty-printing. The callers pass it because each of them already sits on
    the pretty-printing or the compact path; choosing it here would test
    @ref pretty_print once more for every key. Most keys are short and plain
    and are written in one go by put_short_quoted(); everything else takes the
    general path.
    */
    template<std::size_t N>
    void put_object_key(const string_t& s, const char (&tail)[N]) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
#if JSON_LITTLE_ENDIAN_TARGET
        if (put_short_quoted(s, tail))
        {
            return;
        }
#endif
        put_char('"');
        dump_escaped(s);
        put_literal(tail);
    }

    // put_short_quoted() assembles words from little-endian loads
#if JSON_LITTLE_ENDIAN_TARGET
    /// the longest string put_short_quoted() takes
    static constexpr std::size_t short_string_max = JSON_SCAN_VECTOR ? 32 : 16;

    /// the high bit of every byte of @a v that is not printable ASCII or is a
    /// quote, a backslash, or DEL (zero if the bytes can be copied as they are)
    static std::uint64_t swar_not_plain(const std::uint64_t v) noexcept
    {
        constexpr std::uint64_t ones = 0x0101010101010101ull;
        const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\'
        return (((q - ones) & ~q) | ((b - ones) & ~b)         // == '"', == '\\'
                | ((v - 0x2020202020202020ull) & ~v)          // < 0x20
                | v | (v + ones))                             // >= 0x7F
               & 0x8080808080808080ull;
    }

    template<typename WordType>
    static WordType load_word(const char* p) noexcept
    {
        WordType w;
        std::memcpy(&w, p, sizeof(w));
        return w;
    }

    template<typename WordType>
    static void store_word(char* p, const WordType w) noexcept
    {
        std::memcpy(p, &w, sizeof(w));
    }

    /*!
    @brief write `"`, @a s and @a tail if @a s is short and needs no escaping

    A string of up to 16 (32 with vector instructions) printable ASCII
    characters (no quote, backslash, or DEL) is read with two overlapping loads
    and written with two overlapping stores, instead of scanning it and calling
    memcpy with a length that is only known at run time. Returns false, having
    changed nothing, if @a s does not qualify or the write buffer lacks the
    room.
    */
    template<std::size_t N>
    bool put_short_quoted(const string_t& s, const char (&tail)[N]) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        const std::size_t n = s.size();
        if (n > short_string_max || write_buffer_pos + n + N > write_buffer.size())
        {
            return false;
        }

        char* d = write_buffer.data() + write_buffer_pos + 1;
        const char* const p = s.data();

        if (n >= 8)
        {
#if JSON_SCAN_VECTOR
            if (!(n >= 16 ? copy_plain_vectors(d, p, n) : copy_plain_halves(d, p, n)))
            {
                return false;
            }
#else
            const auto a = load_word<std::uint64_t>(p);
            const auto b = load_word<std::uint64_t>(p + n - 8);
            if ((swar_not_plain(a) | swar_not_plain(b)) != 0)
            {
                return false;
            }
            store_word(d, a);
            store_word(d + n - 8, b);
#endif
        }
        else if (n >= 4)
        {
            const auto a = load_word<std::uint32_t>(p);
            const auto b = load_word<std::uint32_t>(p + n - 4);
            // the bytes above the string are filled with a plain character
            const std::uint64_t w = a | (static_cast<std::uint64_t>(b) << (8 * (n - 4)))
                                    | (0x4141414141414141ull << (8 * n));
            if (swar_not_plain(w) != 0)
            {
                return false;
            }
            store_word(d, a);
            store_word(d + n - 4, b);
        }
        else if (n >= 2)
        {
            const auto a = load_word<std::uint16_t>(p);
            const auto b = load_word<std::uint16_t>(p + n - 2);
            const std::uint64_t w = a | (static_cast<std::uint64_t>(b) << (8 * (n - 2)))
                                    | (0x4141414141414141ull << (8 * n));
            if (swar_not_plain(w) != 0)
            {
                return false;
            }
            store_word(d, a);
            store_word(d + n - 2, b);
        }
        else if (n == 1)
        {
            const std::uint64_t w = static_cast<std::uint64_t>(static_cast<unsigned char>(p[0])) | (0x4141414141414141ull << 8u);
            if (swar_not_plain(w) != 0)
            {
                return false;
            }
            *d = p[0];
        }

        d[-1] = '"';
        std::memcpy(d + n, tail, N - 1);
        write_buffer_pos += n + N;
        return true;
    }

#if JSON_SCAN_VECTOR
    /// copy the 8 to 15 bytes [@a p, @a p + @a n) to @a d with two overlapping
    /// words, tested together as one vector, see copy_plain_vectors()
    static bool copy_plain_halves(char* d, const char* p, const std::size_t n) noexcept
    {
#if JSON_SCAN_NEON
        const uint8x8_t lo = vld1_u8(reinterpret_cast<const std::uint8_t*>(p));
        const uint8x8_t hi = vld1_u8(reinterpret_cast<const std::uint8_t*>(p + n - 8));
        const uint8x16_t in = vcombine_u8(lo, hi);
        const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))),
                                            vorrq_u8(vcltq_s8(vreinterpretq_s8_u8(in), vdupq_n_s8(0x20)), vceqq_u8(in, vdupq_n_u8(0x7F))));
        if (vmaxvq_u8(special) != 0)
        {
            return false;
        }
        vst1_u8(reinterpret_cast<std::uint8_t*>(d), lo);
        vst1_u8(reinterpret_cast<std::uint8_t*>(d + n - 8), hi);
#else
        const __m128i lo = _mm_loadl_epi64(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
        const __m128i hi = _mm_loadl_epi64(static_cast<const __m128i*>(static_cast<const void*>(p + n - 8))); // NOLINT(bugprone-casting-through-void)
        const __m128i in = _mm_unpacklo_epi64(lo, hi);
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_or_si128(_mm_cmplt_epi8(in, _mm_set1_epi8(0x20)), _mm_cmpeq_epi8(in, _mm_set1_epi8(0x7F))));
        if (_mm_movemask_epi8(special) != 0)
        {
            return false;
        }
        _mm_storel_epi64(static_cast<__m128i*>(static_cast<void*>(d)), lo); // NOLINT(bugprone-casting-through-void)
        _mm_storel_epi64(static_cast<__m128i*>(static_cast<void*>(d + n - 8)), hi); // NOLINT(bugprone-casting-through-void)
#endif
        return true;
    }

    /// copy the 16 to 32 bytes [@a p, @a p + @a n) to @a d with two overlapping
    /// vectors, unless one of them is a quote, a backslash, a control
    /// character, DEL or not ASCII
    static bool copy_plain_vectors(char* d, const char* p, const std::size_t n) noexcept
    {
#if JSON_SCAN_NEON
        const uint8x16_t a = vld1q_u8(reinterpret_cast<const std::uint8_t*>(p));
        const uint8x16_t b = vld1q_u8(reinterpret_cast<const std::uint8_t*>(p + n - 16));
        const uint8x16_t special = vorrq_u8(vorrq_u8(vorrq_u8(vceqq_u8(a, vdupq_n_u8('"')), vceqq_u8(a, vdupq_n_u8('\\'))),
                                            vorrq_u8(vceqq_u8(b, vdupq_n_u8('"')), vceqq_u8(b, vdupq_n_u8('\\')))),
                                            vorrq_u8(vorrq_u8(vcltq_s8(vreinterpretq_s8_u8(a), vdupq_n_s8(0x20)), vcltq_s8(vreinterpretq_s8_u8(b), vdupq_n_s8(0x20))),
                                                vorrq_u8(vceqq_u8(a, vdupq_n_u8(0x7F)), vceqq_u8(b, vdupq_n_u8(0x7F)))));
        if (vmaxvq_u8(special) != 0)
        {
            return false;
        }
        vst1q_u8(reinterpret_cast<std::uint8_t*>(d), a);
        vst1q_u8(reinterpret_cast<std::uint8_t*>(d + n - 16), b);
#else
        const __m128i a = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
        const __m128i b = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p + n - 16))); // NOLINT(bugprone-casting-through-void)
        const __m128i quote = _mm_set1_epi8('"');
        const __m128i backslash = _mm_set1_epi8('\\');
        const __m128i space = _mm_set1_epi8(0x20);
        const __m128i del = _mm_set1_epi8(0x7F);
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(a, quote), _mm_cmpeq_epi8(a, backslash)),
                                             _mm_or_si128(_mm_cmpeq_epi8(b, quote), _mm_cmpeq_epi8(b, backslash))),
                                             _mm_or_si128(_mm_or_si128(_mm_cmplt_epi8(a, space), _mm_cmplt_epi8(b, space)),
                                                 _mm_or_si128(_mm_cmpeq_epi8(a, del), _mm_cmpeq_epi8(b, del))));
        if (_mm_movemask_epi8(special) != 0)
        {
            return false;
        }
        _mm_storeu_si128(static_cast<__m128i*>(static_cast<void*>(d)), a); // NOLINT(bugprone-casting-through-void)
        _mm_storeu_si128(static_cast<__m128i*>(static_cast<void*>(d + n - 16)), b); // NOLINT(bugprone-casting-through-void)
#endif
        return true;
    }
#endif
#endif

  JSON_PRIVATE_UNLESS_TESTED:
    /*!
    @brief dump escaped string

    Escape a string by replacing certain special characters by a sequence of an
    escape character (backslash) and another character and other control
    characters by a sequence of "\u" followed by a four-digit hex
    representation. The escaped string is appended to @ref write_buffer.

    @param[in] s  the string to escape

    Complexity: Linear in the length of string @a s.

    @note kept out of line: with the short-string attempts in front of it gone
          from here, compilers would otherwise inline it into @ref put_object_key
          and then no longer into the loops that call that
    */
    JSON_HEDLEY_NEVER_INLINE void dump_escaped(const string_t& s)
    {
        // Short strings of printable ASCII - most object keys and many values -
        // are checked byte by byte against a table and then copied in one go.
        // For them, this is cheaper than starting the vector scanner below,
        // whose setup costs more than such a string takes to scan. The same
        // check serves both values of ensure_ascii.
        //
        // Where put_short_quoted() exists and takes strings of up to 32 bytes,
        // the callers have tried it already, and repeating the attempt only
        // costs time for strings that need escaping or are not ASCII.
#if !JSON_LITTLE_ENDIAN_TARGET || !JSON_SCAN_VECTOR
        if (s.size() <= 32)
        {
            const auto& copyable = ascii_copyable();
            const auto* const data = reinterpret_cast<const unsigned char*>(s.data());
            const std::size_t n = s.size();
            std::size_t k = 0;
            while (k + 4 <= n && copyable[data[k]] != 0 && copyable[data[k + 1]] != 0
                    && copyable[data[k + 2]] != 0 && copyable[data[k + 3]] != 0)
            {
                k += 4;
            }
            while (k < n && copyable[data[k]] != 0)
            {
                ++k;
            }
            if (k == n)
            {
                put_string(s, 0, n);
                return;
            }
        }
#endif

        // dispatch once here rather than test the flag inside the loop: it does
        // not change while a string is written, and folding it lets each of the
        // two scanners be inlined into a loop of its own
        if (ensure_ascii)
        {
            dump_escaped_impl<true>(s);
        }
        else
        {
            dump_escaped_impl<false>(s);
        }
    }

    /// write out the bytes pending in @ref string_buffer and reset @a bytes
    JSON_HEDLEY_ALWAYS_INLINE void emit_pending(std::size_t& bytes)
    {
        if (bytes != 0)
        {
            put_buffer(string_buffer, bytes);
            bytes = 0;
        }
    }

    /// write buffer and reset index if fewer than 13 bytes are left, as this
    /// is the maximal number of bytes to be written ("\uxxxx\uxxxx\0") for one
    /// code point
    JSON_HEDLEY_ALWAYS_INLINE void reserve_string_buffer(std::size_t& bytes)
    {
        if (string_buffer.size() - bytes < 13)
        {
            put_buffer(string_buffer, bytes);
            bytes = 0;
        }
    }

    /*!
    @brief worker for @ref dump_escaped

    @a ensure_ascii is a template parameter here so that the branch on it is
    resolved once, outside the loop; see @ref dump_escaped.
    */
#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning(push)
    // EnsureAscii is a template parameter; C++11 has no if constexpr
#pragma warning(disable : 4127) // conditional expression is constant
#endif
    template<bool EnsureAscii>
    void dump_escaped_impl(const string_t& s)
    {
        std::uint32_t codepoint{};
        std::uint8_t state = UTF8_ACCEPT;
        std::size_t bytes = 0;  // number of bytes written to string_buffer

        // number of bytes written at the point of the last valid byte
        std::size_t bytes_after_last_accept = 0;
        std::size_t undumped_chars = 0;

        for (std::size_t i = 0; i < s.size(); ++i)
        {
            // Fast path: at a character boundary (state == UTF8_ACCEPT),
            // bulk-copy the longest run of bytes that need no escaping using a
            // SWAR scanner shared with the lexer's contiguous path. The scanner
            // stops exactly at the first byte dump_escaped would handle
            // individually, so that byte is left to the byte-at-a-time path
            // below, keeping escaping output and error diagnostics unchanged.
            //
            // - EnsureAscii == false: string_bulk_run() copies ordinary bytes
            //   and complete well-formed UTF-8, stopping at a quote, backslash,
            //   control character (< 0x20), or ill-formed/truncated sequence.
            // - EnsureAscii == true: only printable ASCII may be copied
            //   verbatim; find_ascii_copyable_run() additionally stops at 0x7F
            //   and every non-ASCII byte (>= 0x80), which must be \u-escaped.
            if (state == UTF8_ACCEPT)
            {
                const auto* const data = reinterpret_cast<const unsigned char*>(s.data());
                // A run can only be non-empty when the very first byte is one
                // the scanner may copy, so test that single byte before paying
                // for the scan. Without it, text whose characters all have to be
                // escaped - CJK under ensure_ascii, where every byte is >= 0x80 -
                // runs the scanner once per character only to be told zero.
                std::size_t run = 0;
                if (!EnsureAscii)
                {
                    run = string_bulk_run(data + i, s.size() - i);
                }
                else if (is_ascii_copyable(data[i]))
                {
                    run = find_ascii_copyable_run(data + i, s.size() - i);
                }
                if (run != 0)
                {
                    // emit any bytes still pending in string_buffer first to
                    // preserve output order, then write the run directly
                    emit_pending(bytes);
                    put_run(s, i, run);
                    bytes_after_last_accept = 0;
                    undumped_chars = 0;
                    i += run;
                    if (i >= s.size())
                    {
                        break;
                    }
                }

                // A byte below 0x60 is a complete code point and needs no
                // UTF-8 decoding. The scanner stops only at a control
                // character, a quote, or a backslash in that range, so look up
                // its escape sequence and write all 8 bytes of the table entry
                // straight into the write buffer; only the length stored in the
                // last byte of the entry is kept.
                if (data[i] < 0x60)
                {
                    // emit any bytes still pending in string_buffer first to
                    // preserve output order
                    emit_pending(bytes);
                    // deliberately not put_buffer(): a fixed 8-byte memcpy
                    // has no asserts and no write-through branch, which
                    // matters on the hot path
                    const auto& escape = ascii_escapes()[data[i]];
                    if (JSON_HEDLEY_UNLIKELY(write_buffer.size() - write_buffer_pos < escape.size()))
                    {
                        flush();
                    }
                    std::memcpy(write_buffer.data() + write_buffer_pos, escape.data(), escape.size());
                    write_buffer_pos += static_cast<std::size_t>(escape[7]);
                    bytes_after_last_accept = 0;
                    undumped_chars = 0;
                    continue;
                }
            }

            const auto byte = static_cast<std::uint8_t>(s[i]);

            if (EnsureAscii && state == UTF8_ACCEPT && byte >= 0x80)
            {
                // a run of well-formed multi-byte characters is escaped
                // straight into the write buffer; an ill-formed sequence
                // ends the run and is left to the byte-at-a-time path
                if (bytes != 0)
                {
                    put_buffer(string_buffer, bytes);
                    bytes = 0;
                    bytes_after_last_accept = 0;
                }
                const std::size_t escaped = write_u_escapes(reinterpret_cast<const unsigned char*>(s.data()) + i, s.size() - i);
                if (escaped != 0)
                {
                    bytes_after_last_accept = 0;
                    undumped_chars = 0;
                    i += escaped - 1;
                    continue;
                }
            }

            switch (decode(state, codepoint, byte))
            {
                case UTF8_ACCEPT:  // decode found a new code point
                {
                    // the code point is at least 0x60 (smaller ones are handled
                    // above) and is not printable ASCII (which the scanner
                    // copies): it is DEL (0x7F) under EnsureAscii or a non-ASCII
                    // character
                    if (EnsureAscii)
                    {
                        JSON_ASSERT(codepoint >= 0x7F);
                        if (error_handler == error_handler_t::keep)
                        {
                            // this character was buffered as raw bytes below
                            // in case it turned out to be part of an
                            // ill-formed sequence (which is kept as is); now
                            // that it decoded to a well-formed code point,
                            // undo that and \u-escape it like any other
                            // character instead
                            bytes = bytes_after_last_accept;
                        }
                        if (codepoint <= 0xFFFF)
                        {
                            write_u_escape(bytes, static_cast<std::uint16_t>(codepoint));
                        }
                        else
                        {
                            write_u_escape(bytes, static_cast<std::uint16_t>(0xD7C0u + (codepoint >> 10u)));
                            write_u_escape(bytes, static_cast<std::uint16_t>(0xDC00u + (codepoint & 0x3FFu)));
                        }
                    }
                    else
                    {
                        // copy byte to buffer (all previous bytes of the
                        // sequence have been copied in the default case below)
                        string_buffer[bytes++] = s[i];
                    }

                    reserve_string_buffer(bytes);

                    // remember the byte position of this accept
                    bytes_after_last_accept = bytes;
                    undumped_chars = 0;
                    break;
                }

                case UTF8_REJECT:  // decode found invalid UTF-8 byte
                {
                    switch (error_handler)
                    {
                        case error_handler_t::strict:
                        {
                            JSON_THROW(type_error::create(exception_id::invalid_utf8, concat("invalid UTF-8 byte at index ", std::to_string(i), ": 0x", detail::hex_byte(byte)), nullptr));
                        }

                        case error_handler_t::ignore:
                        case error_handler_t::replace:
                        {
                            // in case we saw this character the first time, we
                            // would like to read it again, because the byte
                            // may be OK for itself, but just not OK for the
                            // previous sequence
                            if (undumped_chars > 0)
                            {
                                --i;
                            }

                            // reset length buffer to the last accepted index;
                            // thus removing/ignoring the invalid characters
                            bytes = bytes_after_last_accept;

                            if (error_handler == error_handler_t::replace)
                            {
                                // add a replacement character
                                if (EnsureAscii)
                                {
                                    string_buffer[bytes++] = '\\';
                                    string_buffer[bytes++] = 'u';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'f';
                                    string_buffer[bytes++] = 'd';
                                }
                                else
                                {
                                    string_buffer[bytes++] = '\xEF';
                                    string_buffer[bytes++] = '\xBF';
                                    string_buffer[bytes++] = '\xBD';
                                }

                                reserve_string_buffer(bytes);

                                bytes_after_last_accept = bytes;
                            }

                            undumped_chars = 0;

                            // continue processing the string
                            state = UTF8_ACCEPT;
                            break;
                        }

                        case error_handler_t::keep:
                        {
                            // the bytes of this (now abandoned) ill-formed
                            // sequence seen so far are already buffered below
                            // and are kept unchanged in the output
                            if (undumped_chars > 0)
                            {
                                // the byte that ended the sequence may be OK
                                // for itself (e.g., a quote that must still be
                                // escaped, or the lead byte of a well-formed
                                // code point), so read it again
                                --i;
                            }
                            else
                            {
                                // a byte that cannot start a sequence (e.g.,
                                // 0xFF or a stray continuation byte) is kept
                                // as well
                                string_buffer[bytes++] = s[i];
                            }

                            reserve_string_buffer(bytes);

                            bytes_after_last_accept = bytes;
                            undumped_chars = 0;

                            // continue processing the string
                            state = UTF8_ACCEPT;
                            break;
                        }

                        default:            // LCOV_EXCL_LINE
                            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
                    }
                    break;
                }

                default:  // decode found yet incomplete multibyte code point
                {
                    if (!EnsureAscii || error_handler == error_handler_t::keep)
                    {
                        // code point will not be escaped (or will be kept as
                        // is if it turns out to be ill-formed) - copy byte to
                        // buffer; dropped again above if it decodes to a
                        // well-formed code point that needs \u-escaping
                        string_buffer[bytes++] = s[i];
                    }
                    ++undumped_chars;
                    break;
                }
            }
        }

        // we finished processing the string
        if (JSON_HEDLEY_LIKELY(state == UTF8_ACCEPT))
        {
            // write buffer
            if (bytes > 0)
            {
                put_buffer(string_buffer, bytes);
            }
        }
        else
        {
            // we finish reading, but do not accept: string was incomplete
            switch (error_handler)
            {
                case error_handler_t::strict:
                {
                    JSON_THROW(type_error::create(exception_id::invalid_utf8, concat("incomplete UTF-8 string; last byte: 0x", detail::hex_byte(static_cast<std::uint8_t>(s[s.size() - 1]))), nullptr));
                }

                case error_handler_t::ignore:
                {
                    // write all accepted bytes
                    put_buffer(string_buffer, bytes_after_last_accept);
                    break;
                }

                case error_handler_t::replace:
                {
                    // write all accepted bytes
                    put_buffer(string_buffer, bytes_after_last_accept);
                    // add a replacement character
                    if (EnsureAscii)
                    {
                        put_literal("\\ufffd");
                    }
                    else
                    {
                        put_literal("\xEF\xBF\xBD");
                    }
                    break;
                }

                case error_handler_t::keep:
                {
                    // write the ill-formed trailing bytes as is; they were
                    // buffered above regardless of EnsureAscii
                    put_buffer(string_buffer, bytes);
                    break;
                }

                default:            // LCOV_EXCL_LINE
                    JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            }
        }
    }
#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning(pop)
#endif

  private:
    /*!
    @brief append a single character to the write buffer

    Structural characters ('{', '"', ',', ...) previously went straight to the
    output adapter, one virtual call each. Buffering them and flushing in bulk
    turns those many indirect calls into a single memcpy plus an occasional
    flush, which dominates the cost of serializing object/array-heavy values.
    */
    void put_char(char c)
    {
        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos == write_buffer.size()))
        {
            flush();
        }
        write_buffer[write_buffer_pos++] = c;
    }

    /*!
    @brief append @a indent indentation characters to the write buffer

    Writes the indentation straight into the buffer instead of copying it out of
    a pre-grown indentation string, so no auxiliary string has to be sized,
    resized, or kept in sync with the deepest nesting level reached.

    An indentation wider than the buffer is emitted by filling the buffer with
    the indentation character once and flushing that same content repeatedly:
    flushing does not disturb what the buffer holds, so re-filling it between
    flushes would be redundant work.

    @note inlined on purpose, as is @ref put_literal: GCC otherwise stops
          inlining both into the pretty-printing loops once @ref dump_escaped
          has grown, which made indented output up to 13% slower
    */
    JSON_HEDLEY_ALWAYS_INLINE void put_indent(std::size_t indent)
    {
        // closing braces at the outermost level ask for no indentation at all
        if (indent == 0)
        {
            return;
        }

        // the usual indentation, without a call of memset
        if (JSON_HEDLEY_LIKELY(put_short_literal_indent("", indent)))
        {
            return;
        }

        const std::size_t capacity = write_buffer.size();

        // fill whatever room is left in the buffer; this is the whole job
        // whenever the indentation is narrower than the buffer, which is the
        // case for every sane indent_step
        const std::size_t head = (std::min)(indent, capacity - write_buffer_pos);
        std::memset(write_buffer.data() + write_buffer_pos, indent_char, head);
        write_buffer_pos += head;
        indent -= head;

        if (JSON_HEDLEY_LIKELY(indent == 0))
        {
            return;
        }

        // the buffer is full and the remainder spans whole buffer-fulls: flush
        // what is pending, then fill the buffer with the indentation character
        // exactly once and hand the same bytes to the adapter as often as needed
        flush();
        std::memset(write_buffer.data(), indent_char, capacity);

        while (indent >= capacity)
        {
            write_buffer_pos = capacity;
            flush();
            indent -= capacity;
        }

        // the buffer still holds indentation characters throughout, so the tail
        // only has to be claimed, not written again
        write_buffer_pos = indent;
    }

    /*!
    @brief append a string literal and then @a indent indentation characters

    The usual line break and indentation go into the buffer with one check of
    its room and four stores of the indentation, see @ref put_short_literal_indent.
    */
    template<std::size_t N>
    JSON_HEDLEY_ALWAYS_INLINE void put_literal_indent(const char (&s)[N], const std::size_t indent) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        if (JSON_HEDLEY_LIKELY(put_short_literal_indent(s, indent)))
        {
            return;
        }
        put_literal(s);
        put_indent(indent);
    }

    /*!
    @brief append a string literal and up to 32 indentation characters in one go

    Four words of the indentation character are stored unconditionally and only
    the part wanted is claimed, which spares the call of memset. Shared by
    @ref put_indent (with an empty literal, whose copy compiles to nothing) and
    @ref put_literal_indent. Returns false, having written nothing, if
    @a indent is wider or the write buffer lacks the room.
    */
    template<std::size_t N>
    JSON_HEDLEY_ALWAYS_INLINE bool put_short_literal_indent(const char (&s)[N], const std::size_t indent) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        constexpr std::size_t length = N - 1;
        if (indent > 32 || write_buffer_pos + length + 32 > write_buffer.size())
        {
            return false;
        }
        const std::uint64_t word = 0x0101010101010101ull * static_cast<unsigned char>(indent_char);
        char* const d = write_buffer.data() + write_buffer_pos;
        std::memcpy(d, s, length);
        std::memcpy(d + length, &word, sizeof(word));
        std::memcpy(d + length + 8, &word, sizeof(word));
        std::memcpy(d + length + 16, &word, sizeof(word));
        std::memcpy(d + length + 24, &word, sizeof(word));
        write_buffer_pos += length + indent;
        return true;
    }

    /*!
    @brief append a string literal to the write buffer

    The length comes from the array bound rather than a hand-written count, so
    it cannot drift out of sync with the literal. A literal always fits into the
    buffer (checked at compile time), so unlike @ref put_string this needs no
    write-through path for oversized runs.
    */
    template<std::size_t N>
    JSON_HEDLEY_ALWAYS_INLINE void put_literal(const char (&s)[N]) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        static_assert(N >= 2, "put_literal expects a non-empty string literal");
        // the array bound counts the terminating NUL, which is not written
        constexpr std::size_t length = N - 1;
        static_assert(length < write_buffer_size, "string literal must fit into the write buffer");

        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos + length > write_buffer.size()))
        {
            flush();
        }
        std::memcpy(write_buffer.data() + write_buffer_pos, s, length);
        write_buffer_pos += length;
    }

    /*!
    @brief append the characters of @a str in [@a start, @a start + @a length)

    A run of up to 16 characters with 16 or more in the string from @a start on
    and in the write buffer from its end on is copied as a whole block of 16,
    which spares the call of memcpy with a length known only at run time; the
    surplus characters in the buffer are overwritten by what follows.
    */
    template<typename StringType>
    void put_run(const StringType& str, const std::size_t start, const std::size_t length)
    {
        // a short run is the exception in text without escapes (CJK, accented
        // Latin), for which this keeps the long path the fast one
        if (JSON_HEDLEY_UNLIKELY(length <= 16 && start + 16 <= str.size() && write_buffer_pos + 16 <= write_buffer.size()))
        {
            std::memcpy(write_buffer.data() + write_buffer_pos, str.data() + start, 16);
            write_buffer_pos += length;
            return;
        }
        put_string(str, start, start + length);
    }

    /*!
    @brief append the characters of @a str in [@a start, @a end)

    The only way to append a run of characters: @a str carries its own bound,
    so the range can be checked against it, which a bare pointer plus a count
    could not do. Runs that do not fit the buffer are written straight through
    the output adapter (after flushing what is pending), so large string and
    number payloads are not copied an extra time.
    */
    template<typename StringType>
    void put_string(const StringType& str, std::size_t start, std::size_t end)
    {
        JSON_ASSERT(start <= end);
        JSON_ASSERT(end <= str.size());

        const char* const s = str.data() + start;
        const std::size_t length = end - start;

        if (JSON_HEDLEY_UNLIKELY(length >= write_buffer.size()))
        {
            flush();
            o->write_characters(s, length);
            return;
        }
        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos + length > write_buffer.size()))
        {
            flush();
        }
        std::memcpy(write_buffer.data() + write_buffer_pos, s, length);
        write_buffer_pos += length;
    }

    /*!
    @brief append the first @a length characters of a fixed-size buffer
    */
    template<std::size_t N>
    void put_buffer(const std::array<char, N>& buffer, std::size_t length)
    {
        put_string(buffer, 0, length);
    }

  JSON_PRIVATE_UNLESS_TESTED:
    /*!
    @brief flush the write buffer to the output adapter

    Writing zero characters is a well-defined no-op for every output adapter, so
    the buffered length is passed through unconditionally (no empty-guard branch
    to leave uncovered).

    @note dump_escaped() and dump_integer()/dump_float() write into the internal
    write buffer; callers that invoke them directly (rather than through the
    public dump()) must call flush() before inspecting the output.
    */
    void flush()
    {
        o->write_characters(write_buffer.data(), write_buffer_pos);
        write_buffer_pos = 0;
    }

  private:
    /*!
    @brief count digits

    Count the number of decimal (base 10) digits for an input unsigned integer.

    @param[in] x  unsigned integer number to count its digits
    @return    number of decimal digits
    */
    unsigned int count_digits(number_magnitude_t x) noexcept
    {
        unsigned int n_digits = 1;
        for (;;)
        {
            if (x < 10)
            {
                return n_digits;
            }
            if (x < 100)
            {
                return n_digits + 1;
            }
            if (x < 1000)
            {
                return n_digits + 2;
            }
            if (x < 10000)
            {
                return n_digits + 3;
            }
            x = x / 10000u;
            n_digits += 4;
        }
    }

    /*!
    @brief whether each byte can be written verbatim under either value of ensure_ascii

    Entry c is 1 for printable ASCII other than '"' and '\\' (see
    is_ascii_copyable()) and 0 otherwise. A table lookup per byte is the
    cheapest test for the short strings handled first in dump_escaped().
    */
    static const std::array<std::uint8_t, 256>& ascii_copyable() noexcept
    {
        // constant-initialized from the predicate: no runtime loop, no guard
        static constexpr std::array<std::uint8_t, 256> copyable = make_ascii_copyable(make_index_sequence<256> {});
        return copyable;
    }

    template<std::size_t... Is>
    static constexpr std::array<std::uint8_t, 256> make_ascii_copyable(index_sequence<Is...> /*unused*/) noexcept
    {
        return {{ static_cast<std::uint8_t>(is_ascii_copyable(static_cast<unsigned char>(Is)) ? 1 : 0)... }};
    }

    /*!
    @brief the JSON form of each character below 0x60

    Entry c holds the escape sequence of character c - the short form for
    \\b, \\t, \\n, \\f, \\r, \\" and \\\\, \\u00xx for the other control characters -
    or c itself if it needs no escaping, padded with zeros to 7 bytes. The last
    byte is the length of the sequence. The 8 bytes of an entry are copied at
    once, so writing an escape needs neither a branch nor a byte-wise loop.
    */
    static const std::array<std::array<char, 8>, 0x60>& ascii_escapes() noexcept
    {
        static const std::array<std::array<char, 8>, 0x60> escapes =
        {
            {
                {{'\\', 'u', '0', '0', '0', '0', 0, 6}}, // 0x00
                {{'\\', 'u', '0', '0', '0', '1', 0, 6}}, // 0x01
                {{'\\', 'u', '0', '0', '0', '2', 0, 6}}, // 0x02
                {{'\\', 'u', '0', '0', '0', '3', 0, 6}}, // 0x03
                {{'\\', 'u', '0', '0', '0', '4', 0, 6}}, // 0x04
                {{'\\', 'u', '0', '0', '0', '5', 0, 6}}, // 0x05
                {{'\\', 'u', '0', '0', '0', '6', 0, 6}}, // 0x06
                {{'\\', 'u', '0', '0', '0', '7', 0, 6}}, // 0x07
                {{'\\', 'b', 0, 0, 0, 0, 0, 2}}, // 0x08
                {{'\\', 't', 0, 0, 0, 0, 0, 2}}, // 0x09
                {{'\\', 'n', 0, 0, 0, 0, 0, 2}}, // 0x0A
                {{'\\', 'u', '0', '0', '0', 'b', 0, 6}}, // 0x0B
                {{'\\', 'f', 0, 0, 0, 0, 0, 2}}, // 0x0C
                {{'\\', 'r', 0, 0, 0, 0, 0, 2}}, // 0x0D
                {{'\\', 'u', '0', '0', '0', 'e', 0, 6}}, // 0x0E
                {{'\\', 'u', '0', '0', '0', 'f', 0, 6}}, // 0x0F
                {{'\\', 'u', '0', '0', '1', '0', 0, 6}}, // 0x10
                {{'\\', 'u', '0', '0', '1', '1', 0, 6}}, // 0x11
                {{'\\', 'u', '0', '0', '1', '2', 0, 6}}, // 0x12
                {{'\\', 'u', '0', '0', '1', '3', 0, 6}}, // 0x13
                {{'\\', 'u', '0', '0', '1', '4', 0, 6}}, // 0x14
                {{'\\', 'u', '0', '0', '1', '5', 0, 6}}, // 0x15
                {{'\\', 'u', '0', '0', '1', '6', 0, 6}}, // 0x16
                {{'\\', 'u', '0', '0', '1', '7', 0, 6}}, // 0x17
                {{'\\', 'u', '0', '0', '1', '8', 0, 6}}, // 0x18
                {{'\\', 'u', '0', '0', '1', '9', 0, 6}}, // 0x19
                {{'\\', 'u', '0', '0', '1', 'a', 0, 6}}, // 0x1A
                {{'\\', 'u', '0', '0', '1', 'b', 0, 6}}, // 0x1B
                {{'\\', 'u', '0', '0', '1', 'c', 0, 6}}, // 0x1C
                {{'\\', 'u', '0', '0', '1', 'd', 0, 6}}, // 0x1D
                {{'\\', 'u', '0', '0', '1', 'e', 0, 6}}, // 0x1E
                {{'\\', 'u', '0', '0', '1', 'f', 0, 6}}, // 0x1F
                {{' ', 0, 0, 0, 0, 0, 0, 1}}, // 0x20
                {{'!', 0, 0, 0, 0, 0, 0, 1}}, // 0x21
                {{'\\', '"', 0, 0, 0, 0, 0, 2}}, // 0x22
                {{'#', 0, 0, 0, 0, 0, 0, 1}}, // 0x23
                {{'$', 0, 0, 0, 0, 0, 0, 1}}, // 0x24
                {{'%', 0, 0, 0, 0, 0, 0, 1}}, // 0x25
                {{'&', 0, 0, 0, 0, 0, 0, 1}}, // 0x26
                {{'\'', 0, 0, 0, 0, 0, 0, 1}}, // 0x27
                {{'(', 0, 0, 0, 0, 0, 0, 1}}, // 0x28
                {{')', 0, 0, 0, 0, 0, 0, 1}}, // 0x29
                {{'*', 0, 0, 0, 0, 0, 0, 1}}, // 0x2A
                {{'+', 0, 0, 0, 0, 0, 0, 1}}, // 0x2B
                {{',', 0, 0, 0, 0, 0, 0, 1}}, // 0x2C
                {{'-', 0, 0, 0, 0, 0, 0, 1}}, // 0x2D
                {{'.', 0, 0, 0, 0, 0, 0, 1}}, // 0x2E
                {{'/', 0, 0, 0, 0, 0, 0, 1}}, // 0x2F
                {{'0', 0, 0, 0, 0, 0, 0, 1}}, // 0x30
                {{'1', 0, 0, 0, 0, 0, 0, 1}}, // 0x31
                {{'2', 0, 0, 0, 0, 0, 0, 1}}, // 0x32
                {{'3', 0, 0, 0, 0, 0, 0, 1}}, // 0x33
                {{'4', 0, 0, 0, 0, 0, 0, 1}}, // 0x34
                {{'5', 0, 0, 0, 0, 0, 0, 1}}, // 0x35
                {{'6', 0, 0, 0, 0, 0, 0, 1}}, // 0x36
                {{'7', 0, 0, 0, 0, 0, 0, 1}}, // 0x37
                {{'8', 0, 0, 0, 0, 0, 0, 1}}, // 0x38
                {{'9', 0, 0, 0, 0, 0, 0, 1}}, // 0x39
                {{':', 0, 0, 0, 0, 0, 0, 1}}, // 0x3A
                {{';', 0, 0, 0, 0, 0, 0, 1}}, // 0x3B
                {{'<', 0, 0, 0, 0, 0, 0, 1}}, // 0x3C
                {{'=', 0, 0, 0, 0, 0, 0, 1}}, // 0x3D
                {{'>', 0, 0, 0, 0, 0, 0, 1}}, // 0x3E
                {{'?', 0, 0, 0, 0, 0, 0, 1}}, // 0x3F
                {{'@', 0, 0, 0, 0, 0, 0, 1}}, // 0x40
                {{'A', 0, 0, 0, 0, 0, 0, 1}}, // 0x41
                {{'B', 0, 0, 0, 0, 0, 0, 1}}, // 0x42
                {{'C', 0, 0, 0, 0, 0, 0, 1}}, // 0x43
                {{'D', 0, 0, 0, 0, 0, 0, 1}}, // 0x44
                {{'E', 0, 0, 0, 0, 0, 0, 1}}, // 0x45
                {{'F', 0, 0, 0, 0, 0, 0, 1}}, // 0x46
                {{'G', 0, 0, 0, 0, 0, 0, 1}}, // 0x47
                {{'H', 0, 0, 0, 0, 0, 0, 1}}, // 0x48
                {{'I', 0, 0, 0, 0, 0, 0, 1}}, // 0x49
                {{'J', 0, 0, 0, 0, 0, 0, 1}}, // 0x4A
                {{'K', 0, 0, 0, 0, 0, 0, 1}}, // 0x4B
                {{'L', 0, 0, 0, 0, 0, 0, 1}}, // 0x4C
                {{'M', 0, 0, 0, 0, 0, 0, 1}}, // 0x4D
                {{'N', 0, 0, 0, 0, 0, 0, 1}}, // 0x4E
                {{'O', 0, 0, 0, 0, 0, 0, 1}}, // 0x4F
                {{'P', 0, 0, 0, 0, 0, 0, 1}}, // 0x50
                {{'Q', 0, 0, 0, 0, 0, 0, 1}}, // 0x51
                {{'R', 0, 0, 0, 0, 0, 0, 1}}, // 0x52
                {{'S', 0, 0, 0, 0, 0, 0, 1}}, // 0x53
                {{'T', 0, 0, 0, 0, 0, 0, 1}}, // 0x54
                {{'U', 0, 0, 0, 0, 0, 0, 1}}, // 0x55
                {{'V', 0, 0, 0, 0, 0, 0, 1}}, // 0x56
                {{'W', 0, 0, 0, 0, 0, 0, 1}}, // 0x57
                {{'X', 0, 0, 0, 0, 0, 0, 1}}, // 0x58
                {{'Y', 0, 0, 0, 0, 0, 0, 1}}, // 0x59
                {{'Z', 0, 0, 0, 0, 0, 0, 1}}, // 0x5A
                {{'[', 0, 0, 0, 0, 0, 0, 1}}, // 0x5B
                {{'\\', '\\', 0, 0, 0, 0, 0, 2}}, // 0x5C
                {{']', 0, 0, 0, 0, 0, 0, 1}}, // 0x5D
                {{'^', 0, 0, 0, 0, 0, 0, 1}}, // 0x5E
                {{'_', 0, 0, 0, 0, 0, 0, 1}}, // 0x5F
            }
        };
        return escapes;
    }

    /*!
    @brief escape the well-formed multi-byte characters at the start of @a data

    Writes the "\\uXXXX" escape of each character (two of them for a character
    above U+FFFF) straight into the write buffer, which is why the caller must
    have written out what is pending in @ref string_buffer. Stops at the first
    byte that is below 0x80 or starts an ill-formed or truncated sequence, which
    the caller handles.

    @return the number of bytes of @a data that have been escaped
    */
    JSON_HEDLEY_NEVER_INLINE std::size_t write_u_escapes(const unsigned char* data, std::size_t n)
    {
        std::size_t i = 0;
        while (i < n && data[i] >= 0x80)
        {
            const std::size_t length = validate_one_utf8(data + i, n - i);
            if (length == 0)
            {
                break;
            }

            // a lead byte of 0x80 or above starts a sequence of 2 to 4 bytes
            JSON_ASSERT(length >= 2 && length <= 4);

            const auto b0 = static_cast<std::uint32_t>(data[i]);
            const auto b1 = static_cast<std::uint32_t>(data[i + 1]);
            std::uint32_t codepoint = 0;
            switch (length)
            {
                case 2:
                    codepoint = ((b0 & 0x1Fu) << 6u) | (b1 & 0x3Fu);
                    break;
                case 3:
                    codepoint = ((b0 & 0x0Fu) << 12u) | ((b1 & 0x3Fu) << 6u) | (static_cast<std::uint32_t>(data[i + 2]) & 0x3Fu);
                    break;
                default: // 4
                    codepoint = ((b0 & 0x07u) << 18u) | ((b1 & 0x3Fu) << 12u) | ((static_cast<std::uint32_t>(data[i + 2]) & 0x3Fu) << 6u) | (static_cast<std::uint32_t>(data[i + 3]) & 0x3Fu);
                    break;
            }

            // at most two escapes of six bytes each
            if (JSON_HEDLEY_UNLIKELY(write_buffer.size() - write_buffer_pos < 12))
            {
                flush();
            }
            char* d = write_buffer.data() + write_buffer_pos;
            if (codepoint > 0xFFFFu)
            {
                d = put_u_escape(d, static_cast<std::uint16_t>(0xD7C0u + (codepoint >> 10u)));
                codepoint = 0xDC00u + (codepoint & 0x3FFu);
            }
            d = put_u_escape(d, static_cast<std::uint16_t>(codepoint));
            write_buffer_pos = static_cast<std::size_t>(d - write_buffer.data());
            i += length;
        }
        return i;
    }

    static char* put_u_escape(char* d, const std::uint16_t codeunit) noexcept
    {
        d[0] = '\\';
        d[1] = 'u';
        return hex4_lower(codeunit, d + 2);
    }

    /*!
     * @brief write a lowercase "\\uXXXX" escape sequence into @a string_buffer
     *
     * Branch-free replacement for `snprintf(buf, 7, "\\u%04x", codeunit)` in the
     * string escaping hot path. It writes exactly six characters ('\\', 'u' and
     * four hex digits) at position @a pos of @a string_buffer via a nibble
     * lookup table (@ref hex4_lower), avoiding the format-string parsing and locale machinery of
     * `snprintf`. Advances @a pos by the number of bytes written (6).
     *
     * @param[in] pos       position in @a string_buffer to write at; there must
     *                      be at least 6 bytes of headroom
     * @param[in] codeunit  16-bit value to encode
     */
    void write_u_escape(std::size_t& pos, std::uint16_t codeunit) noexcept
    {
        JSON_ASSERT(string_buffer.size() - pos >= 6);
        string_buffer[pos + 0] = '\\';
        string_buffer[pos + 1] = 'u';
        hex4_lower(codeunit, &string_buffer[pos + 2]);
        pos += 6;
    }

    /*!
    @brief convert a single element of a binary value to its byte value

    The elements of a binary value are dumped as the numbers 0..255, regardless
    of the value type of the configured BinaryType: that type may be signed
    (`char`), unsigned (`std::uint8_t`), or not an integer at all
    (`std::byte`), none of which @ref dump_integer can handle uniformly.
    */
    static std::uint8_t to_byte_value(binary_char_t x) noexcept
    {
        return static_cast<std::uint8_t>(x);
    }

    // templates to avoid warnings about useless casts
    template <typename NumberType, enable_if_t<std::is_signed<NumberType>::value, int> = 0>
    bool is_negative_number(NumberType x)
    {
        return x < 0;
    }

    template < typename NumberType, enable_if_t <std::is_unsigned<NumberType>::value, int > = 0 >
    bool is_negative_number(NumberType /*unused*/)
    {
        return false;
    }

    /*!
    @brief write the decimal representation of the byte @a value

    A binary value's bytes are always in [0, 255], so writing one needs neither
    the digit counting nor the 64-bit arithmetic that @ref dump_integer does for
    an arbitrary number, and the three digits it takes at most are written
    straight into the write buffer.

    Any byte type that is not a plain unsigned byte is converted to its
    @ref to_byte_value "byte value" and left to @ref dump_integer, so a signed
    or non-integral BinaryType::value_type (`char`, `std::byte`, ...) still
    dumps as 0..255.
    */
    template<typename ByteType>
    void dump_byte(const ByteType value)
    {
        dump_byte(value, std::integral_constant < bool,
                  std::is_unsigned<ByteType>::value && sizeof(ByteType) == 1
                  && !std::is_same<ByteType, bool>::value > {});
    }

    template<typename ByteType>
    void dump_byte(const ByteType value, std::false_type /*is_plain_byte*/)
    {
        dump_integer(to_byte_value(value));
    }

    template<typename ByteType>
    void dump_byte(const ByteType value, std::true_type /*is_plain_byte*/)
    {
        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos + 3 > write_buffer.size()))
        {
            flush();
        }

        const auto byte = static_cast<unsigned>(value);
        // Accumulate the offset in a local and store it back once. Writing
        // through write_buffer[] is a char write, which may alias any object,
        // so with the member updated in place the compiler has to reload and
        // store it around every digit - measured 2.4x slower on a dump of a
        // multi-megabyte binary value.
        std::size_t pos = write_buffer_pos;

        if (byte >= 100)
        {
            write_buffer[pos++] = static_cast<char>('0' + (byte / 100));
            write_buffer[pos++] = static_cast<char>('0' + ((byte / 10) % 10));
        }
        else if (byte >= 10)
        {
            write_buffer[pos++] = static_cast<char>('0' + (byte / 10));
        }

        write_buffer[pos++] = static_cast<char>('0' + (byte % 10));

        write_buffer_pos = pos;
    }

    /*!
    @brief dump an integer

    Dump a given integer, appending it to @ref write_buffer (directly: copying
    the digits from another buffer right after writing them waits until the
    stores are done).

    @param[in] x  integer number (signed or unsigned) to dump
    @tparam NumberType either @a number_integer_t or @a number_unsigned_t
    */
    template < typename NumberType, detail::enable_if_t <
                   std::is_integral<NumberType>::value ||
                   std::is_same<NumberType, number_unsigned_t>::value ||
                   std::is_same<NumberType, number_integer_t>::value,
                   int > = 0 >
    void dump_integer(NumberType x)
    {
        static constexpr std::array<std::array<char, 2>, 100> digits_to_99
        {
            {
                {{'0', '0'}}, {{'0', '1'}}, {{'0', '2'}}, {{'0', '3'}}, {{'0', '4'}}, {{'0', '5'}}, {{'0', '6'}}, {{'0', '7'}}, {{'0', '8'}}, {{'0', '9'}},
                {{'1', '0'}}, {{'1', '1'}}, {{'1', '2'}}, {{'1', '3'}}, {{'1', '4'}}, {{'1', '5'}}, {{'1', '6'}}, {{'1', '7'}}, {{'1', '8'}}, {{'1', '9'}},
                {{'2', '0'}}, {{'2', '1'}}, {{'2', '2'}}, {{'2', '3'}}, {{'2', '4'}}, {{'2', '5'}}, {{'2', '6'}}, {{'2', '7'}}, {{'2', '8'}}, {{'2', '9'}},
                {{'3', '0'}}, {{'3', '1'}}, {{'3', '2'}}, {{'3', '3'}}, {{'3', '4'}}, {{'3', '5'}}, {{'3', '6'}}, {{'3', '7'}}, {{'3', '8'}}, {{'3', '9'}},
                {{'4', '0'}}, {{'4', '1'}}, {{'4', '2'}}, {{'4', '3'}}, {{'4', '4'}}, {{'4', '5'}}, {{'4', '6'}}, {{'4', '7'}}, {{'4', '8'}}, {{'4', '9'}},
                {{'5', '0'}}, {{'5', '1'}}, {{'5', '2'}}, {{'5', '3'}}, {{'5', '4'}}, {{'5', '5'}}, {{'5', '6'}}, {{'5', '7'}}, {{'5', '8'}}, {{'5', '9'}},
                {{'6', '0'}}, {{'6', '1'}}, {{'6', '2'}}, {{'6', '3'}}, {{'6', '4'}}, {{'6', '5'}}, {{'6', '6'}}, {{'6', '7'}}, {{'6', '8'}}, {{'6', '9'}},
                {{'7', '0'}}, {{'7', '1'}}, {{'7', '2'}}, {{'7', '3'}}, {{'7', '4'}}, {{'7', '5'}}, {{'7', '6'}}, {{'7', '7'}}, {{'7', '8'}}, {{'7', '9'}},
                {{'8', '0'}}, {{'8', '1'}}, {{'8', '2'}}, {{'8', '3'}}, {{'8', '4'}}, {{'8', '5'}}, {{'8', '6'}}, {{'8', '7'}}, {{'8', '8'}}, {{'8', '9'}},
                {{'9', '0'}}, {{'9', '1'}}, {{'9', '2'}}, {{'9', '3'}}, {{'9', '4'}}, {{'9', '5'}}, {{'9', '6'}}, {{'9', '7'}}, {{'9', '8'}}, {{'9', '9'}},
            }
        };

        // special case for "0"
        if (x == 0)
        {
            put_char('0');
            return;
        }

        // use a pointer to fill the buffer (room for as much as number_buffer holds)
        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos + number_buffer.size() > write_buffer.size()))
        {
            flush();
        }
        auto* buffer_ptr = write_buffer.data() + write_buffer_pos;

        number_magnitude_t abs_value;

        // one byte for the minus sign
        unsigned int n_chars = 0;

        if (is_negative_number(x))
        {
            *buffer_ptr = '-';
            abs_value = remove_sign(static_cast<number_integer_t>(x));
            n_chars = 1;
        }
        else
        {
            abs_value = static_cast<number_magnitude_t>(x);
        }

        // up to 16 digits: eight at a time (as the digits of floats), written
        // without leading zeros
        if (abs_value < 10000000000000000u)
        {
            const auto value = static_cast<std::uint64_t>(abs_value); // fits: abs_value < 10^16
            const std::uint64_t upper = value / 100000000u;
            const std::uint64_t first = dtoa_impl::eight_digit_bytes(upper != 0 ? upper : value);
            const auto leading = static_cast<unsigned>(count_leading_zeros(first) / 8); // (first is not 0)
            char* const p = buffer_ptr + n_chars;
            dtoa_impl::store_msb_first(p, (first << (8 * leading)) + 0x3030303030303030u);
            n_chars += 8 - leading;
            if (upper != 0)
            {
                dtoa_impl::store_msb_first(p + 8 - leading, dtoa_impl::eight_digit_bytes(value - (upper * 100000000u)) + 0x3030303030303030u);
                n_chars += 8;
            }
            write_buffer_pos += n_chars;
            return;
        }

        n_chars += count_digits(abs_value);

        // spare 1 byte for '\0'
        JSON_ASSERT(n_chars < number_buffer.size() - 1);

        // jump to the end to generate the string from backward,
        // so we later avoid reversing the result
        buffer_ptr += n_chars;

        // Fast int2ascii implementation inspired by "Fastware" talk by Andrei Alexandrescu
        // See: https://www.youtube.com/watch?v=o4-CwDo2zpg
        while (abs_value >= 100)
        {
            const auto digits_index = static_cast<unsigned>((abs_value % 100));
            abs_value /= 100;
            *(--buffer_ptr) = digits_to_99[digits_index][1];
            *(--buffer_ptr) = digits_to_99[digits_index][0];
        }

        if (abs_value >= 10)
        {
            const auto digits_index = static_cast<unsigned>(abs_value);
            *(--buffer_ptr) = digits_to_99[digits_index][1];
            *(--buffer_ptr) = digits_to_99[digits_index][0];
        }
        else
        {
            *(--buffer_ptr) = static_cast<char>('0' + abs_value);
        }

        write_buffer_pos += n_chars;
    }

    /*!
    @brief dump a floating-point number

    Dump a given floating-point number, appending it to @ref write_buffer.

    @param[in] x  floating-point number to dump
    */
    void dump_float(number_float_t x)
    {
        // NaN / inf
        if (!std::isfinite(x))
        {
            put_literal("null");
            return;
        }

        // If number_float_t is an IEEE-754 single or double precision number,
        // use the Grisu2 algorithm to produce short numbers which are
        // guaranteed to round-trip, using strtof and strtod, resp.
        //
        // NB: The test below works if <long double> == <double>.
        static constexpr bool is_ieee_single_or_double
            = (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 24 && std::numeric_limits<number_float_t>::max_exponent == 128) ||
              (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 53 && std::numeric_limits<number_float_t>::max_exponent == 1024);

        dump_float(x, std::integral_constant<bool, is_ieee_single_or_double>());
    }

    void dump_float(number_float_t x, std::true_type /*is_ieee_single_or_double*/)
    {
        // directly into the write buffer: copying the text from number_buffer
        // right after to_chars() wrote it waits until its stores are done
        if (JSON_HEDLEY_UNLIKELY(write_buffer_pos + number_buffer.size() > write_buffer.size()))
        {
            flush();
        }
        auto* begin = write_buffer.data() + write_buffer_pos;
        auto* end = ::nlohmann::detail::to_chars(begin, begin + number_buffer.size(), x);
        write_buffer_pos += static_cast<std::size_t>(end - begin);
    }

    JSON_HEDLEY_NON_NULL(1)
    static int snprintf_float(char* buf, std::size_t size, int d, double x)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        return (std::snprintf)(buf, size, "%.*g", d, x);
    }

    JSON_HEDLEY_NON_NULL(1)
    static int snprintf_float(char* buf, std::size_t size, int d, long double x)
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        return (std::snprintf)(buf, size, "%.*Lg", d, x);
    }

    void dump_float(number_float_t x, std::false_type /*is_ieee_single_or_double*/)
    {
        // get the number of digits for a float -> text -> float round-trip
        static constexpr auto d = std::numeric_limits<number_float_t>::max_digits10;

        // the actual conversion
        std::ptrdiff_t len = snprintf_float(number_buffer.data(), number_buffer.size(), d, x);

        // negative value indicates an error
        JSON_ASSERT(len > 0);
        // check if the buffer was large enough
        JSON_ASSERT(static_cast<std::size_t>(len) < number_buffer.size());

        // look up the locale's thousands separator and decimal point now,
        // matching what snprintf_float() just used (see lexer::get_decimal_point())
        const auto* loc = std::localeconv();
        JSON_ASSERT(loc != nullptr);
        const char thousands_sep = (loc->thousands_sep == nullptr) ? '\0' : *loc->thousands_sep;
        const char decimal_point = (loc->decimal_point == nullptr) ? '\0' : *loc->decimal_point;

        // erase thousands separators
        if (thousands_sep != '\0')
        {
            // NOLINTNEXTLINE(readability-qualified-auto,llvm-qualified-auto): std::remove returns an iterator, see https://github.com/nlohmann/json/issues/3081
            const auto end = std::remove(number_buffer.begin(), number_buffer.begin() + len, thousands_sep);
            std::fill(end, number_buffer.end(), '\0');
            JSON_ASSERT((end - number_buffer.begin()) <= len);
            len = (end - number_buffer.begin());
        }

        // convert decimal point to '.'
        if (decimal_point != '\0' && decimal_point != '.')
        {
            // NOLINTNEXTLINE(readability-qualified-auto,llvm-qualified-auto): std::find returns an iterator, see https://github.com/nlohmann/json/issues/3081
            const auto dec_pos = std::find(number_buffer.begin(), number_buffer.end(), decimal_point);
            if (dec_pos != number_buffer.end())
            {
                *dec_pos = '.';
            }
        }

        put_buffer(number_buffer, static_cast<std::size_t>(len));

        // determine if we need to append ".0"
        const bool value_is_int_like =
            std::none_of(number_buffer.begin(), number_buffer.begin() + len + 1,
                         [](char c)
        {
            return c == '.' || c == 'e';
        });

        if (value_is_int_like)
        {
            put_literal(".0");
        }
    }

    /*
     * Helper function for dump_integer
     *
     * This function takes a negative signed integer and returns its absolute
     * value as an unsigned integer. The plus/minus shuffling is necessary as we
     * cannot directly remove the sign of an arbitrary signed integer as the
     * absolute values of INT_MIN and INT_MAX are usually not the same. See
     * #1708 for details.
     */
    number_magnitude_t remove_sign(number_integer_t x) noexcept
    {
        JSON_ASSERT(x < 0);
        return static_cast<number_magnitude_t>(-(x + 1)) + 1;
    }

  private:
    /// the output of the serializer (non-owning; the adapter lives at the call site)
    output_adapter_protocol<char>* o = nullptr;

    /// a character buffer left uninitialized: the buffers below are written
    /// before they are read (only the part written is ever read), and zeroing
    /// 1.6 KiB took more than half of what dumping a small value costs (the
    /// user-provided constructor keeps the member initialization, which
    /// -Weffc++ asks for, from zeroing them)
    template<std::size_t N>
    struct uninitialized_buffer : std::array<char, N>
    {
        uninitialized_buffer() noexcept {} // NOLINT(modernize-use-equals-default,hicpp-use-equals-default,cppcoreguidelines-pro-type-member-init,hicpp-member-init): see above
    };

    /// a (hopefully) large enough character buffer
    uninitialized_buffer<64> number_buffer;

    /// string buffer
    uninitialized_buffer<512> string_buffer;

    /// the indentation character
    const char indent_char;

    /// whether to pretty-print the output
    const bool pretty_print;

    /// whether to escape non-ASCII characters with \\uXXXX sequences
    const bool ensure_ascii;

    /// the indent level
    const std::size_t indent_step;

    /// error_handler how to react on decoding errors
    const error_handler_t error_handler;

    /// buffer collecting output before it is flushed to the output adapter, so
    /// that the many small structural writes become few bulk writes
    static constexpr std::size_t write_buffer_size = 1024;
    uninitialized_buffer<write_buffer_size> write_buffer;
    /// number of valid bytes currently held in @ref write_buffer
    std::size_t write_buffer_pos = 0;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
