//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // nullptr_t
#include <exception> // exception
#if JSON_DIAGNOSTICS
    #include <numeric> // accumulate
#endif
#include <stdexcept> // runtime_error
#include <string> // to_string
#include <vector> // vector

#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/detail/string_escape.hpp>
#include <nlohmann/detail/input/position_t.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/string_concat.hpp>

// With -Wweak-vtables, Clang will complain about the exception classes as they
// have no out-of-line virtual method definitions and their vtable will be
// emitted in every translation unit. This issue cannot be fixed with a
// header-only library as there is no implementation file to move these
// functions to. As a result, we suppress this warning here to avoid client
// code stumbling over this. See https://github.com/nlohmann/json/issues/4087
// for a discussion.
#if defined(__clang__)
    JSON_HEDLEY_DIAGNOSTIC_PUSH
    JSON_HEDLEY_PRAGMA(clang diagnostic ignored "-Wweak-vtables")
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

////////////////
// exceptions //
////////////////

/*!
@brief the ids of the exceptions thrown by the library
@note The values are part of the public API: they are the `id` member of the
      exceptions and appear in their `what()` messages.
@sa https://json.nlohmann.me/home/exceptions/
*/
enum class exception_id : int
{
    // parse_error
    syntax_error = 101, ///< unexpected token or invalid literal while parsing JSON
    patch_not_an_array = 104, ///< a JSON Patch document is not an array of objects
    patch_invalid_operation = 105, ///< a JSON Patch operation is malformed
    pointer_index_leading_zero = 106, ///< a JSON Pointer array index has a leading zero
    pointer_missing_slash = 107, ///< a JSON Pointer does not start with '/'
    pointer_invalid_escape = 108, ///< a JSON Pointer contains an escape other than ~0 and ~1
    pointer_index_not_a_number = 109, ///< a JSON Pointer array index is not a number
    unexpected_end_of_input = 110, ///< a binary input ends early, or has bytes left at its end
    unexpected_byte = 112, ///< a binary input contains an unexpected byte or invalid length
    invalid_string_or_size = 113, ///< a binary input contains an invalid string or size specification
    bson_unsupported_type = 114, ///< a BSON record type is not supported
    invalid_high_precision_number = 115, ///< a UBJSON/BJData high-precision number cannot be parsed
    // invalid_iterator
    iterators_incompatible = 201, ///< the iterators of a range belong to different values
    iterator_from_other_value = 202, ///< an iterator does not belong to the value it is used with
    iterator_range_from_other_value = 203, ///< an iterator range does not belong to the value it is used with
    iterator_range_out_of_range = 204, ///< an iterator range of a primitive value is not [begin, end)
    iterator_out_of_range = 205, ///< an iterator of a primitive value is not begin()
    iterator_range_of_null = 206, ///< an iterator range belongs to a null value
    iterator_key_not_object = 207, ///< key() is called on an iterator of a non-object
    iterator_subscript_on_object = 208, ///< operator[] is called on an iterator of an object
    iterator_arithmetic_on_object = 209, ///< an offset operator is used on an iterator of an object
    insert_range_incompatible = 210, ///< the iterators of an inserted range belong to different values
    insert_range_into_itself = 211, ///< an inserted range belongs to the value it is inserted into
    iterators_compare_different_values = 212, ///< iterators of different values are compared
    iterator_order_on_object = 213, ///< iterators of an object are compared by order
    iterator_value_unavailable = 214, ///< an iterator does not refer to a value
    // type_error
    object_from_non_pairs = 301, ///< an object is created from an initializer list that is not a list of pairs
    type_mismatch = 302, ///< a value has the wrong type for a conversion
    incompatible_reference_type = 303, ///< get_ref() is called with a reference type that does not match the value
    at_wrong_type = 304, ///< at() is called on a value of the wrong type
    subscript_wrong_type = 305, ///< operator[] is called on a value of the wrong type
    value_wrong_type = 306, ///< value() is called on a value of the wrong type
    erase_wrong_type = 307, ///< erase() is called on a value of the wrong type
    push_back_wrong_type = 308, ///< push_back() or operator+= is called on a value of the wrong type
    insert_wrong_type = 309, ///< insert() is called on a value of the wrong type
    swap_wrong_type = 310, ///< swap() is called on a value of the wrong type
    emplace_wrong_type = 311, ///< emplace() or emplace_back() is called on a value of the wrong type
    update_wrong_type = 312, ///< update() is called on a value of the wrong type
    unflatten_invalid_value = 313, ///< unflatten() finds conflicting paths
    unflatten_not_object = 314, ///< unflatten() is called on a non-object
    unflatten_value_not_primitive = 315, ///< unflatten() is called on an object with non-primitive values
    invalid_utf8 = 316, ///< dump() finds a string that is not valid UTF-8
    type_not_serializable = 317, ///< a value cannot be serialized to the requested binary format
    enum_key_duplicate = 318, ///< an enum-keyed map has two keys that serialize to the same string
    discarded_value_used = 321, ///< a discarded value is used
    // out_of_range
    array_index_out_of_range = 401, ///< an array index is out of range
    pointer_past_the_end_index = 402, ///< a JSON Pointer uses the array index '-'
    key_not_found = 403, ///< an object key is not found
    pointer_unresolved = 404, ///< a JSON Pointer reference token cannot be resolved
    patch_on_root = 405, ///< the root of a value has no parent, e.g. for a JSON Patch 'remove' or 'add' at the root
    number_overflow = 406, ///< a number cannot be stored without overflowing to NaN or INF
    integer_too_large = 407, ///< an integer cannot be represented in the binary format
    container_too_large = 408, ///< the size of a container in a binary input exceeds the maximal capacity
    bson_key_with_null = 409, ///< a BSON key contains U+0000
    value_out_of_range = 410, ///< an enum value is undefined, or a JSON Pointer array index exceeds size_type
    patch_add_parent_not_container = 411, ///< the parent of a JSON Patch 'add' target is not a container
    length_too_large = 412, ///< a length does not fit into the length field of a binary format
    patch_remove_parent_not_container = 413, ///< the parent of a JSON Patch 'remove' target is not a container
    patch_move_into_child = 414, ///< a JSON Patch 'move' moves a value into one of its children
    subtype_out_of_range = 415, ///< a binary subtype does not fit into one byte
    // other_error
    internal_error = 500, ///< unreachable code was reached
    patch_test_failed = 501, ///< a JSON Patch 'test' operation failed
    size_marker_required = 502  ///< UBJSON/BJData output with type markers requires size markers
};

/// @brief general exception of the @ref basic_json class
/// @sa https://json.nlohmann.me/api/basic_json/exception/
class exception : public std::exception
{
  public:
    /// returns the explanatory string
    const char* what() const noexcept override
    {
        return m.what();
    }

    /// the id of the exception
    const int id; // NOLINT(cppcoreguidelines-non-private-member-variables-in-classes)

  protected:
    JSON_HEDLEY_NON_NULL(3)
    exception(int id_, const char* what_arg) : id(id_), m(what_arg) {} // NOLINT(bugprone-throw-keyword-missing)

    static std::string name(const std::string& ename, int id_)
    {
        return concat("[json.exception.", ename, '.', std::to_string(id_), "] ");
    }

    static std::string diagnostics(std::nullptr_t /*leaf_element*/)
    {
        return "";
    }

    template<typename BasicJsonType>
    static std::string diagnostics(const BasicJsonType* leaf_element)
    {
#if JSON_DIAGNOSTICS
        std::vector<std::string> tokens;
        for (const auto* current = leaf_element; current != nullptr && current->m_parent != nullptr; current = current->m_parent)
        {
            switch (current->m_parent->type())
            {
                case value_t::array:
                {
                    for (std::size_t i = 0; i < current->m_parent->m_data.m_value.array->size(); ++i)
                    {
                        if (&current->m_parent->m_data.m_value.array->operator[](i) == current)
                        {
                            tokens.emplace_back(std::to_string(i));
                            break;
                        }
                    }
                    break;
                }

                case value_t::object:
                {
                    for (const auto& element : *current->m_parent->m_data.m_value.object)
                    {
                        if (&element.second == current)
                        {
                            // data() is null-terminated, so a key containing
                            // a null byte is cut short here rather than
                            // truncating the whole message at what()
                            tokens.emplace_back(element.first.data());
                            break;
                        }
                    }
                    break;
                }

                case value_t::null: // LCOV_EXCL_LINE
                case value_t::string: // LCOV_EXCL_LINE
                case value_t::boolean: // LCOV_EXCL_LINE
                case value_t::number_integer: // LCOV_EXCL_LINE
                case value_t::number_unsigned: // LCOV_EXCL_LINE
                case value_t::number_float: // LCOV_EXCL_LINE
                case value_t::binary: // LCOV_EXCL_LINE
                case value_t::discarded: // LCOV_EXCL_LINE
                default:   // LCOV_EXCL_LINE
                    break; // LCOV_EXCL_LINE
            }
        }

        if (tokens.empty())
        {
            return "";
        }

        auto str = std::accumulate(tokens.rbegin(), tokens.rend(), std::string{},
                                   [](const std::string & a, const std::string & b)
        {
            return concat(a, '/', detail::escape(b));
        });

        return concat('(', str, ") ", get_byte_positions(leaf_element));
#else
        return get_byte_positions(leaf_element);
#endif
    }

  private:
    /// an exception object as storage for error messages
    std::runtime_error m;
#if JSON_DIAGNOSTIC_POSITIONS
    template<typename BasicJsonType>
    static std::string get_byte_positions(const BasicJsonType* leaf_element)
    {
        if ((leaf_element->start_pos() != std::string::npos) && (leaf_element->end_pos() != std::string::npos))
        {
            return concat("(bytes ", std::to_string(leaf_element->start_pos()), "-", std::to_string(leaf_element->end_pos()), ") ");
        }
        return "";
    }
#else
    template<typename BasicJsonType>
    static std::string get_byte_positions(const BasicJsonType* leaf_element)
    {
        static_cast<void>(leaf_element);
        return "";
    }
#endif
};

/// @brief exception indicating a parse error
/// @sa https://json.nlohmann.me/api/basic_json/parse_error/
class parse_error : public exception
{
  public:
    /*!
    @brief create a parse error exception
    @param[in] id_       the id of the exception
    @param[in] pos       the position where the error occurred (or with
                         chars_read_total=0 if the position cannot be
                         determined)
    @param[in] what_arg  the explanatory string
    @return parse_error object
    */
    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static parse_error create(int id_, const position_t& pos, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("parse_error", id_), "parse error",
                                     position_string(pos), ": ", exception::diagnostics(context), what_arg);
        return {id_, pos.chars_read_total, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static parse_error create(int id_, std::size_t byte_, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("parse_error", id_), "parse error",
                                     (byte_ != 0 ? (concat(" at byte ", std::to_string(byte_))) : ""),
                                     ": ", exception::diagnostics(context), what_arg);
        return {id_, byte_, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static parse_error create(exception_id id_, const position_t& pos, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), pos, what_arg, context);
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static parse_error create(exception_id id_, std::size_t byte_, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), byte_, what_arg, context);
    }

    /*!
    @brief byte index of the parse error

    The byte index of the last read character in the input file.

    @note For an input with n bytes, 1 is the index of the first character and
          n+1 is the index of the terminating null byte or the end of file.
          This also holds true when reading a byte vector (CBOR or MessagePack).
    */
    const std::size_t byte;

  private:
    parse_error(int id_, std::size_t byte_, const char* what_arg)
        : exception(id_, what_arg), byte(byte_) {}

    static std::string position_string(const position_t& pos)
    {
        return concat(" at line ", std::to_string(pos.lines_read + 1),
                      ", column ", std::to_string(pos.chars_read_current_line));
    }
};

/// @brief exception indicating errors with iterators
/// @sa https://json.nlohmann.me/api/basic_json/invalid_iterator/
class invalid_iterator : public exception
{
  public:
    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static invalid_iterator create(int id_, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("invalid_iterator", id_), exception::diagnostics(context), what_arg);
        return {id_, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static invalid_iterator create(exception_id id_, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), what_arg, context);
    }

  private:
    JSON_HEDLEY_NON_NULL(3)
    invalid_iterator(int id_, const char* what_arg)
        : exception(id_, what_arg) {}
};

/// @brief exception indicating executing a member function with a wrong type
/// @sa https://json.nlohmann.me/api/basic_json/type_error/
class type_error : public exception
{
  public:
    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static type_error create(int id_, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("type_error", id_), exception::diagnostics(context), what_arg);
        return {id_, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static type_error create(exception_id id_, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), what_arg, context);
    }

  private:
    JSON_HEDLEY_NON_NULL(3)
    type_error(int id_, const char* what_arg) : exception(id_, what_arg) {}
};

/// @brief exception indicating access out of the defined range
/// @sa https://json.nlohmann.me/api/basic_json/out_of_range/
class out_of_range : public exception
{
  public:
    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static out_of_range create(int id_, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("out_of_range", id_), exception::diagnostics(context), what_arg);
        return {id_, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static out_of_range create(exception_id id_, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), what_arg, context);
    }

  private:
    JSON_HEDLEY_NON_NULL(3)
    out_of_range(int id_, const char* what_arg) : exception(id_, what_arg) {}
};

/// @brief exception indicating other library errors
/// @sa https://json.nlohmann.me/api/basic_json/other_error/
class other_error : public exception
{
  public:
    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static other_error create(int id_, const std::string& what_arg, BasicJsonContext context)
    {
        const std::string w = concat(exception::name("other_error", id_), exception::diagnostics(context), what_arg);
        return {id_, w.c_str()};
    }

    template<typename BasicJsonContext, enable_if_t<is_basic_json_context<BasicJsonContext>::value, int> = 0>
    static other_error create(exception_id id_, const std::string& what_arg, BasicJsonContext context)
    {
        return create(static_cast<int>(id_), what_arg, context);
    }

  private:
    JSON_HEDLEY_NON_NULL(3)
    other_error(int id_, const char* what_arg) : exception(id_, what_arg) {}
};

/*!
@brief helper function to call JSON_THROW from a template
@note JSON_THROW is a macro that, depending on the JSON_THROW_USER /
      JSON_TRY_USER / JSON_NOEXCEPTION configuration, may expand to code
      that does not reference its argument (e.g. `std::abort()`), which
      would trigger a compilation error if the argument's type depends on
      a template parameter that is otherwise unused. Wrapping the call in
      a templated function avoids this and gives the compiler a single
      place to see the (possibly unused) parameter.
*/
template<typename ExceptionType>
void templated_json_throw(ExceptionType exception)
{
    JSON_THROW(exception);

    // JSON_THROW may expand to code that discards its argument (e.g. when
    // exceptions are disabled) - the cast below avoids an unused-parameter
    // warning with -Werror in that case
    (void)exception;
}

/*!
@brief throws because @a j does not have the type a conversion expects
@param[in] expected  the expected type(s), e.g. "array" or "binary or array"
@param[in] j         the value with the wrong type
@throw type_error.302 always
*/
template<typename BasicJsonType>
JSON_HEDLEY_NO_RETURN inline void throw_type_must_be(const char* expected, const BasicJsonType& j)
{
    static_cast<void>(expected); // unused when JSON_NOEXCEPTION is defined
    static_cast<void>(j);
    JSON_THROW(type_error::create(exception_id::type_mismatch, concat("type must be ", expected, ", but is ", j.type_name()), &j));
}

/*!
@brief throws because an operation is not supported for the type of @a j
@param[in] id_        the id of the type_error exception (at_wrong_type..update_wrong_type)
@param[in] operation  the operation, e.g. "erase()"
@param[in] j          the value the operation was called on
@throw type_error always
*/
template<typename BasicJsonType>
JSON_HEDLEY_NO_RETURN inline void throw_cannot_use_with(const exception_id id_, const char* operation, const BasicJsonType& j)
{
    static_cast<void>(id_); // unused when JSON_NOEXCEPTION is defined
    static_cast<void>(operation);
    static_cast<void>(j);
    JSON_THROW(type_error::create(id_, concat("cannot use ", operation, " with ", j.type_name()), &j));
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

#if defined(__clang__)
    JSON_HEDLEY_DIAGNOSTIC_POP
#endif
