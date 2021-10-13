/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++
|  |  |__   |  |  | | | |  version 3.10.3
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef INCLUDE_NLOHMANN_JSON_HPP_
#define INCLUDE_NLOHMANN_JSON_HPP_

#define NLOHMANN_JSON_VERSION_MAJOR 3
#define NLOHMANN_JSON_VERSION_MINOR 10
#define NLOHMANN_JSON_VERSION_PATCH 3

#include <algorithm> // all_of, find, for_each
#include <cstddef> // nullptr_t, ptrdiff_t, size_t
#include <functional> // hash, less
#include <initializer_list> // initializer_list
#ifndef JSON_NO_IO
    #include <iosfwd> // istream, ostream
#endif  // JSON_NO_IO
#include <iterator> // random_access_iterator_tag
#include <memory> // unique_ptr
#include <numeric> // accumulate
#include <string> // string, stoi, to_string
#include <utility> // declval, forward, move, pair, swap
#include <vector> // vector

#include <nlohmann/adl_serializer.hpp>
#include <nlohmann/byte_container_with_subtype.hpp>
#include <nlohmann/detail/conversions/from_json.hpp>
#include <nlohmann/detail/conversions/to_json.hpp>
#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/hash.hpp>
#include <nlohmann/detail/input/binary_reader.hpp>
#include <nlohmann/detail/input/input_adapters.hpp>
#include <nlohmann/detail/input/lexer.hpp>
#include <nlohmann/detail/input/parser.hpp>
#include <nlohmann/detail/iterators/internal_iterator.hpp>
#include <nlohmann/detail/iterators/iter_impl.hpp>
#include <nlohmann/detail/iterators/iteration_proxy.hpp>
#include <nlohmann/detail/iterators/json_reverse_iterator.hpp>
#include <nlohmann/detail/iterators/primitive_iterator.hpp>
#include <nlohmann/detail/json_pointer.hpp>
#include <nlohmann/detail/json_ref.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/string_escape.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/output/binary_writer.hpp>
#include <nlohmann/detail/output/output_adapters.hpp>
#include <nlohmann/detail/output/serializer.hpp>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/json_fwd.hpp>
#include <nlohmann/ordered_map.hpp>

#if defined(JSON_HAS_CPP_17)
    #include <string_view>
#endif

/*!
@brief namespace for Niels Lohmann
@see https://github.com/nlohmann
@since version 1.0.0
*/
namespace nlohmann
{

/*!
@brief a class to store JSON values

@tparam ObjectType type for JSON objects (`std::map` by default; will be used
in @ref object_t)
@tparam ArrayType type for JSON arrays (`std::vector` by default; will be used
in @ref array_t)
@tparam StringType type for JSON strings and object keys (`std::string` by
default; will be used in @ref string_t)
@tparam BooleanType type for JSON booleans (`bool` by default; will be used
in @ref boolean_t)
@tparam NumberIntegerType type for JSON integer numbers (`int64_t` by
default; will be used in @ref number_integer_t)
@tparam NumberUnsignedType type for JSON unsigned integer numbers (@c
`uint64_t` by default; will be used in @ref number_unsigned_t)
@tparam NumberFloatType type for JSON floating-point numbers (`double` by
default; will be used in @ref number_float_t)
@tparam BinaryType type for packed binary data for compatibility with binary
serialization formats (`std::vector<std::uint8_t>` by default; will be used in
@ref binary_t)
@tparam AllocatorType type of the allocator to use (`std::allocator` by
default)
@tparam JSONSerializer the serializer to resolve internal calls to `to_json()`
and `from_json()` (@ref adl_serializer by default)

@requirement The class satisfies the following concept requirements:
- Basic
 - [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible):
   JSON values can be default constructed. The result will be a JSON null
   value.
 - [MoveConstructible](https://en.cppreference.com/w/cpp/named_req/MoveConstructible):
   A JSON value can be constructed from an rvalue argument.
 - [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible):
   A JSON value can be copy-constructed from an lvalue expression.
 - [MoveAssignable](https://en.cppreference.com/w/cpp/named_req/MoveAssignable):
   A JSON value van be assigned from an rvalue argument.
 - [CopyAssignable](https://en.cppreference.com/w/cpp/named_req/CopyAssignable):
   A JSON value can be copy-assigned from an lvalue expression.
 - [Destructible](https://en.cppreference.com/w/cpp/named_req/Destructible):
   JSON values can be destructed.
- Layout
 - [StandardLayoutType](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType):
   JSON values have
   [standard layout](https://en.cppreference.com/w/cpp/language/data_members#Standard_layout):
   All non-static data members are private and standard layout types, the
   class has no virtual functions or (virtual) base classes.
- Library-wide
 - [EqualityComparable](https://en.cppreference.com/w/cpp/named_req/EqualityComparable):
   JSON values can be compared with `==`, see @ref
   operator==(const_reference,const_reference).
 - [LessThanComparable](https://en.cppreference.com/w/cpp/named_req/LessThanComparable):
   JSON values can be compared with `<`, see @ref
   operator<(const_reference,const_reference).
 - [Swappable](https://en.cppreference.com/w/cpp/named_req/Swappable):
   Any JSON lvalue or rvalue of can be swapped with any lvalue or rvalue of
   other compatible types, using unqualified function call @ref swap().
 - [NullablePointer](https://en.cppreference.com/w/cpp/named_req/NullablePointer):
   JSON values can be compared against `std::nullptr_t` objects which are used
   to model the `null` value.
- Container
 - [Container](https://en.cppreference.com/w/cpp/named_req/Container):
   JSON values can be used like STL containers and provide iterator access.
 - [ReversibleContainer](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer);
   JSON values can be used like STL containers and provide reverse iterator
   access.

@invariant The member variables @a m_value and @a m_type have the following
relationship:
- If `m_type == value_t::object`, then `m_value.object != nullptr`.
- If `m_type == value_t::array`, then `m_value.array != nullptr`.
- If `m_type == value_t::string`, then `m_value.string != nullptr`.
The invariants are checked by member function assert_invariant().

@internal
@note ObjectType trick from https://stackoverflow.com/a/9860911
@endinternal

@see [RFC 8259: The JavaScript Object Notation (JSON) Data Interchange
Format](https://tools.ietf.org/html/rfc8259)

@since version 1.0.0

@nosubgrouping
*/
NLOHMANN_BASIC_JSON_TPL_DECLARATION
class basic_json // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
{
  private:
    template<detail::value_t> friend struct detail::external_constructor;
    friend ::nlohmann::json_pointer<basic_json>;

    template<typename BasicJsonType, typename InputType>
    friend class ::nlohmann::detail::parser;
    friend ::nlohmann::detail::serializer<basic_json>;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::iter_impl;
    template<typename BasicJsonType, typename CharType>
    friend class ::nlohmann::detail::binary_writer;
    template<typename BasicJsonType, typename InputType, typename SAX>
    friend class ::nlohmann::detail::binary_reader;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::json_sax_dom_parser;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::json_sax_dom_callback_parser;
    friend class ::nlohmann::detail::exception;

    /// workaround type for MSVC
    using basic_json_t = NLOHMANN_BASIC_JSON_TPL;

  JSON_PRIVATE_UNLESS_TESTED:
    // convenience aliases for types residing in namespace detail;
    using lexer = ::nlohmann::detail::lexer_base<basic_json>;

    template<typename InputAdapterType>
    static ::nlohmann::detail::parser<basic_json, InputAdapterType> parser(
        InputAdapterType adapter,
        detail::parser_callback_t<basic_json>cb = nullptr,
        const bool allow_exceptions = true,
        const bool ignore_comments = false
    )
    {
        return ::nlohmann::detail::parser<basic_json, InputAdapterType>(std::move(adapter),
                std::move(cb), allow_exceptions, ignore_comments);
    }

  private:
    using primitive_iterator_t = ::nlohmann::detail::primitive_iterator_t;
    template<typename BasicJsonType>
    using internal_iterator = ::nlohmann::detail::internal_iterator<BasicJsonType>;
    template<typename BasicJsonType>
    using iter_impl = ::nlohmann::detail::iter_impl<BasicJsonType>;
    template<typename Iterator>
    using iteration_proxy = ::nlohmann::detail::iteration_proxy<Iterator>;
    template<typename Base> using json_reverse_iterator = ::nlohmann::detail::json_reverse_iterator<Base>;

    template<typename CharType>
    using output_adapter_t = ::nlohmann::detail::output_adapter_t<CharType>;

    template<typename InputType>
    using binary_reader = ::nlohmann::detail::binary_reader<basic_json, InputType>;
    template<typename CharType> using binary_writer = ::nlohmann::detail::binary_writer<basic_json, CharType>;

  JSON_PRIVATE_UNLESS_TESTED:
    using serializer = ::nlohmann::detail::serializer<basic_json>;

  public:
    using value_t = detail::value_t;
    /// JSON Pointer, see @ref nlohmann::json_pointer
    using json_pointer = ::nlohmann::json_pointer<basic_json>;
    template<typename T, typename SFINAE>
    using json_serializer = JSONSerializer<T, SFINAE>;
    /// how to treat decoding errors
    using error_handler_t = detail::error_handler_t;
    /// how to treat CBOR tags
    using cbor_tag_handler_t = detail::cbor_tag_handler_t;
    /// helper type for initializer lists of basic_json values
    using initializer_list_t = std::initializer_list<detail::json_ref<basic_json>>;

    using input_format_t = detail::input_format_t;
    /// SAX interface type, see @ref nlohmann::json_sax
    using json_sax_t = json_sax<basic_json>;

    ////////////////
    // exceptions //
    ////////////////

    /// @name exceptions
    /// Classes to implement user-defined exceptions.
    /// @{

    /// @copydoc detail::exception
    using exception = detail::exception;
    /// @copydoc detail::parse_error
    using parse_error = detail::parse_error;
    /// @copydoc detail::invalid_iterator
    using invalid_iterator = detail::invalid_iterator;
    /// @copydoc detail::type_error
    using type_error = detail::type_error;
    /// @copydoc detail::out_of_range
    using out_of_range = detail::out_of_range;
    /// @copydoc detail::other_error
    using other_error = detail::other_error;

    /// @}


    /////////////////////
    // container types //
    /////////////////////

    /// @name container types
    /// The canonic container types to use @ref basic_json like any other STL
    /// container.
    /// @{

    /// the type of elements in a basic_json container
    using value_type = basic_json;

    /// the type of an element reference
    using reference = value_type&;
    /// the type of an element const reference
    using const_reference = const value_type&;

    /// a type to represent differences between iterators
    using difference_type = std::ptrdiff_t;
    /// a type to represent container sizes
    using size_type = std::size_t;

    /// the allocator type
    using allocator_type = AllocatorType<basic_json>;

    /// the type of an element pointer
    using pointer = typename std::allocator_traits<allocator_type>::pointer;
    /// the type of an element const pointer
    using const_pointer = typename std::allocator_traits<allocator_type>::const_pointer;

    /// an iterator for a basic_json container
    using iterator = iter_impl<basic_json>;
    /// a const iterator for a basic_json container
    using const_iterator = iter_impl<const basic_json>;
    /// a reverse iterator for a basic_json container
    using reverse_iterator = json_reverse_iterator<typename basic_json::iterator>;
    /// a const reverse iterator for a basic_json container
    using const_reverse_iterator = json_reverse_iterator<typename basic_json::const_iterator>;

    /// @}


    /// @brief returns the allocator associated with the container
    /// @sa https://json.nlohmann.me/api/basic_json/get_allocator/
    static allocator_type get_allocator()
    {
        return allocator_type();
    }

    /// @brief returns version information on the library
    /// @sa https://json.nlohmann.me/api/basic_json/meta/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json meta()
    {
        basic_json result;

        result["copyright"] = "(C) 2013-2021 Niels Lohmann";
        result["name"] = "JSON for Modern C++";
        result["url"] = "https://github.com/nlohmann/json";
        result["version"]["string"] =
            std::to_string(NLOHMANN_JSON_VERSION_MAJOR) + "." +
            std::to_string(NLOHMANN_JSON_VERSION_MINOR) + "." +
            std::to_string(NLOHMANN_JSON_VERSION_PATCH);
        result["version"]["major"] = NLOHMANN_JSON_VERSION_MAJOR;
        result["version"]["minor"] = NLOHMANN_JSON_VERSION_MINOR;
        result["version"]["patch"] = NLOHMANN_JSON_VERSION_PATCH;

#ifdef _WIN32
        result["platform"] = "win32";
#elif defined __linux__
        result["platform"] = "linux";
#elif defined __APPLE__
        result["platform"] = "apple";
#elif defined __unix__
        result["platform"] = "unix";
#else
        result["platform"] = "unknown";
#endif

#if defined(__ICC) || defined(__INTEL_COMPILER)
        result["compiler"] = {{"family", "icc"}, {"version", __INTEL_COMPILER}};
#elif defined(__clang__)
        result["compiler"] = {{"family", "clang"}, {"version", __clang_version__}};
#elif defined(__GNUC__) || defined(__GNUG__)
        result["compiler"] = {{"family", "gcc"}, {"version", std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." + std::to_string(__GNUC_PATCHLEVEL__)}};
#elif defined(__HP_cc) || defined(__HP_aCC)
        result["compiler"] = "hp"
#elif defined(__IBMCPP__)
        result["compiler"] = {{"family", "ilecpp"}, {"version", __IBMCPP__}};
#elif defined(_MSC_VER)
        result["compiler"] = {{"family", "msvc"}, {"version", _MSC_VER}};
#elif defined(__PGI)
        result["compiler"] = {{"family", "pgcpp"}, {"version", __PGI}};
#elif defined(__SUNPRO_CC)
        result["compiler"] = {{"family", "sunpro"}, {"version", __SUNPRO_CC}};
#else
        result["compiler"] = {{"family", "unknown"}, {"version", "unknown"}};
#endif

#ifdef __cplusplus
        result["compiler"]["c++"] = std::to_string(__cplusplus);
#else
        result["compiler"]["c++"] = "unknown";
#endif
        return result;
    }


    ///////////////////////////
    // JSON value data types //
    ///////////////////////////

    /// @name JSON value data types
    /// The data types to store a JSON value. These types are derived from
    /// the template arguments passed to class @ref basic_json.
    /// @{

    /// @brief object key comparator type
    /// @sa https://json.nlohmann.me/api/basic_json/object_comparator_t/
#if defined(JSON_HAS_CPP_14)
    // Use transparent comparator if possible, combined with perfect forwarding
    // on find() and count() calls prevents unnecessary string construction.
    using object_comparator_t = std::less<>;
#else
    using object_comparator_t = std::less<StringType>;
#endif

    /// @brief a type for an object
    /// @sa https://json.nlohmann.me/api/basic_json/object_t/
    using object_t = ObjectType<StringType,
          basic_json,
          object_comparator_t,
          AllocatorType<std::pair<const StringType,
          basic_json>>>;

    /// @brief a type for an array
    /// @sa https://json.nlohmann.me/api/basic_json/array_t/
    using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;

    /// @brief a type for a string
    /// @sa https://json.nlohmann.me/api/basic_json/string_t/
    using string_t = StringType;

    /// @brief a type for a boolean
    /// @sa https://json.nlohmann.me/api/basic_json/boolean_t/
    using boolean_t = BooleanType;

    /// @brief a type for a number (integer)
    /// @sa https://json.nlohmann.me/api/basic_json/number_integer_t/
    using number_integer_t = NumberIntegerType;

    /// @brief a type for a number (unsigned)
    /// @sa https://json.nlohmann.me/api/basic_json/number_unsigned_t/
    using number_unsigned_t = NumberUnsignedType;

    /// @brief a type for a number (floating-point)
    /// @sa https://json.nlohmann.me/api/basic_json/number_float_t/
    using number_float_t = NumberFloatType;

    /// @brief a type for a packed binary type
    /// @sa https://json.nlohmann.me/api/basic_json/binary_t/
    using binary_t = nlohmann::byte_container_with_subtype<BinaryType>;

    /// @}

  private:

    /// helper for exception-safe object creation
    template<typename T, typename... Args>
    JSON_HEDLEY_RETURNS_NON_NULL
    static T* create(Args&& ... args)
    {
        AllocatorType<T> alloc;
        using AllocatorTraits = std::allocator_traits<AllocatorType<T>>;

        auto deleter = [&](T * obj)
        {
            AllocatorTraits::deallocate(alloc, obj, 1);
        };
        std::unique_ptr<T, decltype(deleter)> obj(AllocatorTraits::allocate(alloc, 1), deleter);
        AllocatorTraits::construct(alloc, obj.get(), std::forward<Args>(args)...);
        JSON_ASSERT(obj != nullptr);
        return obj.release();
    }

    ////////////////////////
    // JSON value storage //
    ////////////////////////

  JSON_PRIVATE_UNLESS_TESTED:
    /*!
    @brief a JSON value

    The actual storage for a JSON value of the @ref basic_json class. This
    union combines the different storage types for the JSON value types
    defined in @ref value_t.

    JSON type | value_t type    | used type
    --------- | --------------- | ------------------------
    object    | object          | pointer to @ref object_t
    array     | array           | pointer to @ref array_t
    string    | string          | pointer to @ref string_t
    boolean   | boolean         | @ref boolean_t
    number    | number_integer  | @ref number_integer_t
    number    | number_unsigned | @ref number_unsigned_t
    number    | number_float    | @ref number_float_t
    binary    | binary          | pointer to @ref binary_t
    null      | null            | *no value is stored*

    @note Variable-length types (objects, arrays, and strings) are stored as
    pointers. The size of the union should not exceed 64 bits if the default
    value types are used.

    @since version 1.0.0
    */
    union json_value
    {
        /// object (stored with pointer to save storage)
        object_t* object;
        /// array (stored with pointer to save storage)
        array_t* array;
        /// string (stored with pointer to save storage)
        string_t* string;
        /// binary (stored with pointer to save storage)
        binary_t* binary;
        /// boolean
        boolean_t boolean;
        /// number (integer)
        number_integer_t number_integer;
        /// number (unsigned integer)
        number_unsigned_t number_unsigned;
        /// number (floating-point)
        number_float_t number_float;

        /// default constructor (for null values)
        json_value() = default;
        /// constructor for booleans
        json_value(boolean_t v) noexcept : boolean(v) {}
        /// constructor for numbers (integer)
        json_value(number_integer_t v) noexcept : number_integer(v) {}
        /// constructor for numbers (unsigned)
        json_value(number_unsigned_t v) noexcept : number_unsigned(v) {}
        /// constructor for numbers (floating-point)
        json_value(number_float_t v) noexcept : number_float(v) {}
        /// constructor for empty values of a given type
        json_value(value_t t)
        {
            switch (t)
            {
                case value_t::object:
                {
                    object = create<object_t>();
                    break;
                }

                case value_t::array:
                {
                    array = create<array_t>();
                    break;
                }

                case value_t::string:
                {
                    string = create<string_t>("");
                    break;
                }

                case value_t::binary:
                {
                    binary = create<binary_t>();
                    break;
                }

                case value_t::boolean:
                {
                    boolean = boolean_t(false);
                    break;
                }

                case value_t::number_integer:
                {
                    number_integer = number_integer_t(0);
                    break;
                }

                case value_t::number_unsigned:
                {
                    number_unsigned = number_unsigned_t(0);
                    break;
                }

                case value_t::number_float:
                {
                    number_float = number_float_t(0.0);
                    break;
                }

                case value_t::null:
                {
                    object = nullptr;  // silence warning, see #821
                    break;
                }

                case value_t::discarded:
                default:
                {
                    object = nullptr;  // silence warning, see #821
                    if (JSON_HEDLEY_UNLIKELY(t == value_t::null))
                    {
                        JSON_THROW(other_error::create(500, "961c151d2e87f2686a955a9be24d316f1362bf21 3.10.3", basic_json())); // LCOV_EXCL_LINE
                    }
                    break;
                }
            }
        }

        /// constructor for strings
        json_value(const string_t& value)
        {
            string = create<string_t>(value);
        }

        /// constructor for rvalue strings
        json_value(string_t&& value)
        {
            string = create<string_t>(std::move(value));
        }

        /// constructor for objects
        json_value(const object_t& value)
        {
            object = create<object_t>(value);
        }

        /// constructor for rvalue objects
        json_value(object_t&& value)
        {
            object = create<object_t>(std::move(value));
        }

        /// constructor for arrays
        json_value(const array_t& value)
        {
            array = create<array_t>(value);
        }

        /// constructor for rvalue arrays
        json_value(array_t&& value)
        {
            array = create<array_t>(std::move(value));
        }

        /// constructor for binary arrays
        json_value(const typename binary_t::container_type& value)
        {
            binary = create<binary_t>(value);
        }

        /// constructor for rvalue binary arrays
        json_value(typename binary_t::container_type&& value)
        {
            binary = create<binary_t>(std::move(value));
        }

        /// constructor for binary arrays (internal type)
        json_value(const binary_t& value)
        {
            binary = create<binary_t>(value);
        }

        /// constructor for rvalue binary arrays (internal type)
        json_value(binary_t&& value)
        {
            binary = create<binary_t>(std::move(value));
        }

        void destroy(value_t t)
        {
            if (t == value_t::array || t == value_t::object)
            {
                // flatten the current json_value to a heap-allocated stack
                std::vector<basic_json> stack;

                // move the top-level items to stack
                if (t == value_t::array)
                {
                    stack.reserve(array->size());
                    std::move(array->begin(), array->end(), std::back_inserter(stack));
                }
                else
                {
                    stack.reserve(object->size());
                    for (auto&& it : *object)
                    {
                        stack.push_back(std::move(it.second));
                    }
                }

                while (!stack.empty())
                {
                    // move the last item to local variable to be processed
                    basic_json current_item(std::move(stack.back()));
                    stack.pop_back();

                    // if current_item is array/object, move
                    // its children to the stack to be processed later
                    if (current_item.is_array())
                    {
                        std::move(current_item.m_value.array->begin(), current_item.m_value.array->end(), std::back_inserter(stack));

                        current_item.m_value.array->clear();
                    }
                    else if (current_item.is_object())
                    {
                        for (auto&& it : *current_item.m_value.object)
                        {
                            stack.push_back(std::move(it.second));
                        }

                        current_item.m_value.object->clear();
                    }

                    // it's now safe that current_item get destructed
                    // since it doesn't have any children
                }
            }

            switch (t)
            {
                case value_t::object:
                {
                    AllocatorType<object_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, object);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, object, 1);
                    break;
                }

                case value_t::array:
                {
                    AllocatorType<array_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, array);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, array, 1);
                    break;
                }

                case value_t::string:
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, string, 1);
                    break;
                }

                case value_t::binary:
                {
                    AllocatorType<binary_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, binary);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, binary, 1);
                    break;
                }

                case value_t::null:
                case value_t::boolean:
                case value_t::number_integer:
                case value_t::number_unsigned:
                case value_t::number_float:
                case value_t::discarded:
                default:
                {
                    break;
                }
            }
        }
    };

  private:
    /*!
    @brief checks the class invariants

    This function asserts the class invariants. It needs to be called at the
    end of every constructor to make sure that created objects respect the
    invariant. Furthermore, it has to be called each time the type of a JSON
    value is changed, because the invariant expresses a relationship between
    @a m_type and @a m_value.

    Furthermore, the parent relation is checked for arrays and objects: If
    @a check_parents true and the value is an array or object, then the
    container's elements must have the current value as parent.

    @param[in] check_parents  whether the parent relation should be checked.
               The value is true by default and should only be set to false
               during destruction of objects when the invariant does not
               need to hold.
    */
    void assert_invariant(bool check_parents = true) const noexcept
    {
        JSON_ASSERT(m_type != value_t::object || m_value.object != nullptr);
        JSON_ASSERT(m_type != value_t::array || m_value.array != nullptr);
        JSON_ASSERT(m_type != value_t::string || m_value.string != nullptr);
        JSON_ASSERT(m_type != value_t::binary || m_value.binary != nullptr);

#if JSON_DIAGNOSTICS
        JSON_TRY
        {
            // cppcheck-suppress assertWithSideEffect
            JSON_ASSERT(!check_parents || !is_structured() || std::all_of(begin(), end(), [this](const basic_json & j)
            {
                return j.m_parent == this;
            }));
        }
        JSON_CATCH(...) {} // LCOV_EXCL_LINE
#endif
        static_cast<void>(check_parents);
    }

    void set_parents()
    {
#if JSON_DIAGNOSTICS
        switch (m_type)
        {
            case value_t::array:
            {
                for (auto& element : *m_value.array)
                {
                    element.m_parent = this;
                }
                break;
            }

            case value_t::object:
            {
                for (auto& element : *m_value.object)
                {
                    element.second.m_parent = this;
                }
                break;
            }

            case value_t::null:
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
                break;
        }
#endif
    }

    iterator set_parents(iterator it, typename iterator::difference_type count)
    {
#if JSON_DIAGNOSTICS
        for (typename iterator::difference_type i = 0; i < count; ++i)
        {
            (it + i)->m_parent = this;
        }
#else
        static_cast<void>(count);
#endif
        return it;
    }

    reference set_parent(reference j, std::size_t old_capacity = std::size_t(-1))
    {
#if JSON_DIAGNOSTICS
        if (old_capacity != std::size_t(-1))
        {
            // see https://github.com/nlohmann/json/issues/2838
            JSON_ASSERT(type() == value_t::array);
            if (JSON_HEDLEY_UNLIKELY(m_value.array->capacity() != old_capacity))
            {
                // capacity has changed: update all parents
                set_parents();
                return j;
            }
        }

        // ordered_json uses a vector internally, so pointers could have
        // been invalidated; see https://github.com/nlohmann/json/issues/2962
#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning(push )
#pragma warning(disable : 4127) // ignore warning to replace if with if constexpr
#endif
        if (detail::is_ordered_map<object_t>::value)
        {
            set_parents();
            return j;
        }
#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning( pop )
#endif

        j.m_parent = this;
#else
        static_cast<void>(j);
        static_cast<void>(old_capacity);
#endif
        return j;
    }

  public:
    //////////////////////////
    // JSON parser callback //
    //////////////////////////

    /// @brief parser event types
    /// @sa https://json.nlohmann.me/api/basic_json/parse_event_t/
    using parse_event_t = detail::parse_event_t;

    /// @brief per-element parser callback type
    /// @sa https://json.nlohmann.me/api/basic_json/parser_callback_t/
    using parser_callback_t = detail::parser_callback_t<basic_json>;

    //////////////////
    // constructors //
    //////////////////

    /// @name constructors and destructors
    /// Constructors of class @ref basic_json, copy/move constructor, copy
    /// assignment, static functions creating objects, and the destructor.
    /// @{

    /// @brief create an empty value with a given type
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(const value_t v)
        : m_type(v), m_value(v)
    {
        assert_invariant();
    }

    /// @brief create a null object
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(std::nullptr_t = nullptr) noexcept
        : basic_json(value_t::null)
    {
        assert_invariant();
    }

    /// @brief create a JSON value from compatible types
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    template < typename CompatibleType,
               typename U = detail::uncvref_t<CompatibleType>,
               detail::enable_if_t <
                   !detail::is_basic_json<U>::value && detail::is_compatible_type<basic_json_t, U>::value, int > = 0 >
    basic_json(CompatibleType && val) noexcept(noexcept( // NOLINT(bugprone-forwarding-reference-overload,bugprone-exception-escape)
                JSONSerializer<U>::to_json(std::declval<basic_json_t&>(),
                                           std::forward<CompatibleType>(val))))
    {
        JSONSerializer<U>::to_json(*this, std::forward<CompatibleType>(val));
        set_parents();
        assert_invariant();
    }

    /// @brief create a JSON value from an existing one
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    template < typename BasicJsonType,
               detail::enable_if_t <
                   detail::is_basic_json<BasicJsonType>::value&& !std::is_same<basic_json, BasicJsonType>::value, int > = 0 >
    basic_json(const BasicJsonType& val)
    {
        using other_boolean_t = typename BasicJsonType::boolean_t;
        using other_number_float_t = typename BasicJsonType::number_float_t;
        using other_number_integer_t = typename BasicJsonType::number_integer_t;
        using other_number_unsigned_t = typename BasicJsonType::number_unsigned_t;
        using other_string_t = typename BasicJsonType::string_t;
        using other_object_t = typename BasicJsonType::object_t;
        using other_array_t = typename BasicJsonType::array_t;
        using other_binary_t = typename BasicJsonType::binary_t;

        switch (val.type())
        {
            case value_t::boolean:
                JSONSerializer<other_boolean_t>::to_json(*this, val.template get<other_boolean_t>());
                break;
            case value_t::number_float:
                JSONSerializer<other_number_float_t>::to_json(*this, val.template get<other_number_float_t>());
                break;
            case value_t::number_integer:
                JSONSerializer<other_number_integer_t>::to_json(*this, val.template get<other_number_integer_t>());
                break;
            case value_t::number_unsigned:
                JSONSerializer<other_number_unsigned_t>::to_json(*this, val.template get<other_number_unsigned_t>());
                break;
            case value_t::string:
                JSONSerializer<other_string_t>::to_json(*this, val.template get_ref<const other_string_t&>());
                break;
            case value_t::object:
                JSONSerializer<other_object_t>::to_json(*this, val.template get_ref<const other_object_t&>());
                break;
            case value_t::array:
                JSONSerializer<other_array_t>::to_json(*this, val.template get_ref<const other_array_t&>());
                break;
            case value_t::binary:
                JSONSerializer<other_binary_t>::to_json(*this, val.template get_ref<const other_binary_t&>());
                break;
            case value_t::null:
                *this = nullptr;
                break;
            case value_t::discarded:
                m_type = value_t::discarded;
                break;
            default:            // LCOV_EXCL_LINE
                JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
        }
        set_parents();
        assert_invariant();
    }

    /// @brief create a container (array or object) from an initializer list
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(initializer_list_t init,
               bool type_deduction = true,
               value_t manual_type = value_t::array)
    {
        // check if each element is an array with two elements whose first
        // element is a string
        bool is_an_object = std::all_of(init.begin(), init.end(),
                                        [](const detail::json_ref<basic_json>& element_ref)
        {
            return element_ref->is_array() && element_ref->size() == 2 && (*element_ref)[0].is_string();
        });

        // adjust type if type deduction is not wanted
        if (!type_deduction)
        {
            // if array is wanted, do not create an object though possible
            if (manual_type == value_t::array)
            {
                is_an_object = false;
            }

            // if object is wanted but impossible, throw an exception
            if (JSON_HEDLEY_UNLIKELY(manual_type == value_t::object && !is_an_object))
            {
                JSON_THROW(type_error::create(301, "cannot create object from initializer list", basic_json()));
            }
        }

        if (is_an_object)
        {
            // the initializer list is a list of pairs -> create object
            m_type = value_t::object;
            m_value = value_t::object;

            for (auto& element_ref : init)
            {
                auto element = element_ref.moved_or_copied();
                m_value.object->emplace(
                    std::move(*((*element.m_value.array)[0].m_value.string)),
                    std::move((*element.m_value.array)[1]));
            }
        }
        else
        {
            // the initializer list describes an array -> create array
            m_type = value_t::array;
            m_value.array = create<array_t>(init.begin(), init.end());
        }

        set_parents();
        assert_invariant();
    }

    /*!
    @brief explicitly create a binary array (without subtype)

    Creates a JSON binary array value from a given binary container. Binary
    values are part of various binary formats, such as CBOR, MessagePack, and
    BSON. This constructor is used to create a value for serialization to those
    formats.

    @note Note, this function exists because of the difficulty in correctly
    specifying the correct template overload in the standard value ctor, as both
    JSON arrays and JSON binary arrays are backed with some form of a
    `std::vector`. Because JSON binary arrays are a non-standard extension it
    was decided that it would be best to prevent automatic initialization of a
    binary array type, for backwards compatibility and so it does not happen on
    accident.

    @param[in] init container containing bytes to use as binary type

    @return JSON binary array value

    @complexity Linear in the size of @a init.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes to any JSON value.

    @since version 3.8.0
    */
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json binary(const typename binary_t::container_type& init)
    {
        auto res = basic_json();
        res.m_type = value_t::binary;
        res.m_value = init;
        return res;
    }

    /// @brief explicitly create a binary array (with subtype)
    /// @sa https://json.nlohmann.me/api/basic_json/binary/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json binary(const typename binary_t::container_type& init, typename binary_t::subtype_type subtype)
    {
        auto res = basic_json();
        res.m_type = value_t::binary;
        res.m_value = binary_t(init, subtype);
        return res;
    }

    /// @brief explicitly create a binary array
    /// @sa https://json.nlohmann.me/api/basic_json/binary/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json binary(typename binary_t::container_type&& init)
    {
        auto res = basic_json();
        res.m_type = value_t::binary;
        res.m_value = std::move(init);
        return res;
    }

    /// @brief explicitly create a binary array (with subtype)
    /// @sa https://json.nlohmann.me/api/basic_json/binary/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json binary(typename binary_t::container_type&& init, typename binary_t::subtype_type subtype)
    {
        auto res = basic_json();
        res.m_type = value_t::binary;
        res.m_value = binary_t(std::move(init), subtype);
        return res;
    }

    /// @brief explicitly create an array from an initializer list
    /// @sa https://json.nlohmann.me/api/basic_json/array/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json array(initializer_list_t init = {})
    {
        return basic_json(init, false, value_t::array);
    }

    /// @brief explicitly create an object from an initializer list
    /// @sa https://json.nlohmann.me/api/basic_json/object/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json object(initializer_list_t init = {})
    {
        return basic_json(init, false, value_t::object);
    }

    /// @brief construct an array with count copies of given value
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(size_type cnt, const basic_json& val)
        : m_type(value_t::array)
    {
        m_value.array = create<array_t>(cnt, val);
        set_parents();
        assert_invariant();
    }

    /// @brief construct a JSON container given an iterator range
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    template < class InputIT, typename std::enable_if <
                   std::is_same<InputIT, typename basic_json_t::iterator>::value ||
                   std::is_same<InputIT, typename basic_json_t::const_iterator>::value, int >::type = 0 >
    basic_json(InputIT first, InputIT last)
    {
        JSON_ASSERT(first.m_object != nullptr);
        JSON_ASSERT(last.m_object != nullptr);

        // make sure iterator fits the current value
        if (JSON_HEDLEY_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(201, "iterators are not compatible", basic_json()));
        }

        // copy type from first iterator
        m_type = first.m_object->m_type;

        // check if iterator range is complete for primitive values
        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (JSON_HEDLEY_UNLIKELY(!first.m_it.primitive_iterator.is_begin()
                                         || !last.m_it.primitive_iterator.is_end()))
                {
                    JSON_THROW(invalid_iterator::create(204, "iterators out of range", *first.m_object));
                }
                break;
            }

            case value_t::null:
            case value_t::object:
            case value_t::array:
            case value_t::binary:
            case value_t::discarded:
            default:
                break;
        }

        switch (m_type)
        {
            case value_t::number_integer:
            {
                m_value.number_integer = first.m_object->m_value.number_integer;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value.number_unsigned = first.m_object->m_value.number_unsigned;
                break;
            }

            case value_t::number_float:
            {
                m_value.number_float = first.m_object->m_value.number_float;
                break;
            }

            case value_t::boolean:
            {
                m_value.boolean = first.m_object->m_value.boolean;
                break;
            }

            case value_t::string:
            {
                m_value = *first.m_object->m_value.string;
                break;
            }

            case value_t::object:
            {
                m_value.object = create<object_t>(first.m_it.object_iterator,
                                                  last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                m_value.array = create<array_t>(first.m_it.array_iterator,
                                                last.m_it.array_iterator);
                break;
            }

            case value_t::binary:
            {
                m_value = *first.m_object->m_value.binary;
                break;
            }

            case value_t::null:
            case value_t::discarded:
            default:
                JSON_THROW(invalid_iterator::create(206, "cannot construct with iterators from " + std::string(first.m_object->type_name()), *first.m_object));
        }

        set_parents();
        assert_invariant();
    }


    ///////////////////////////////////////
    // other constructors and destructor //
    ///////////////////////////////////////

    template<typename JsonRef,
             detail::enable_if_t<detail::conjunction<detail::is_json_ref<JsonRef>,
                                 std::is_same<typename JsonRef::value_type, basic_json>>::value, int> = 0 >
    basic_json(const JsonRef& ref) : basic_json(ref.moved_or_copied()) {}

    /// @brief copy constructor
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(const basic_json& other)
        : m_type(other.m_type)
    {
        // check of passed value is valid
        other.assert_invariant();

        switch (m_type)
        {
            case value_t::object:
            {
                m_value = *other.m_value.object;
                break;
            }

            case value_t::array:
            {
                m_value = *other.m_value.array;
                break;
            }

            case value_t::string:
            {
                m_value = *other.m_value.string;
                break;
            }

            case value_t::boolean:
            {
                m_value = other.m_value.boolean;
                break;
            }

            case value_t::number_integer:
            {
                m_value = other.m_value.number_integer;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value = other.m_value.number_unsigned;
                break;
            }

            case value_t::number_float:
            {
                m_value = other.m_value.number_float;
                break;
            }

            case value_t::binary:
            {
                m_value = *other.m_value.binary;
                break;
            }

            case value_t::null:
            case value_t::discarded:
            default:
                break;
        }

        set_parents();
        assert_invariant();
    }

    /// @brief move constructor
    /// @sa https://json.nlohmann.me/api/basic_json/basic_json/
    basic_json(basic_json&& other) noexcept
        : m_type(std::move(other.m_type)),
          m_value(std::move(other.m_value))
    {
        // check that passed value is valid
        other.assert_invariant(false);

        // invalidate payload
        other.m_type = value_t::null;
        other.m_value = {};

        set_parents();
        assert_invariant();
    }

    /// @brief copy assignment
    /// @sa https://json.nlohmann.me/api/basic_json/operator=/
    basic_json& operator=(basic_json other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value&&
        std::is_nothrow_move_assignable<value_t>::value&&
        std::is_nothrow_move_constructible<json_value>::value&&
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        // check that passed value is valid
        other.assert_invariant();

        using std::swap;
        swap(m_type, other.m_type);
        swap(m_value, other.m_value);

        set_parents();
        assert_invariant();
        return *this;
    }

    /// @brief destructor
    /// @sa https://json.nlohmann.me/api/basic_json/~basic_json/
    ~basic_json() noexcept
    {
        assert_invariant(false);
        m_value.destroy(m_type);
    }

    /// @}

  public:
    ///////////////////////
    // object inspection //
    ///////////////////////

    /// @name object inspection
    /// Functions to inspect the type of a JSON value.
    /// @{

    /// @brief serialization
    /// @sa https://json.nlohmann.me/api/basic_json/dump/
    string_t dump(const int indent = -1,
                  const char indent_char = ' ',
                  const bool ensure_ascii = false,
                  const error_handler_t error_handler = error_handler_t::strict) const
    {
        string_t result;
        serializer s(detail::output_adapter<char, string_t>(result), indent_char, error_handler);

        if (indent >= 0)
        {
            s.dump(*this, true, ensure_ascii, static_cast<unsigned int>(indent));
        }
        else
        {
            s.dump(*this, false, ensure_ascii, 0);
        }

        return result;
    }

    /// @brief return the type of the JSON value (explicit)
    /// @sa https://json.nlohmann.me/api/basic_json/type/
    constexpr value_t type() const noexcept
    {
        return m_type;
    }

    /// @brief return whether type is primitive
    /// @sa https://json.nlohmann.me/api/basic_json/is_primitive/
    constexpr bool is_primitive() const noexcept
    {
        return is_null() || is_string() || is_boolean() || is_number() || is_binary();
    }

    /// @brief return whether type is structured
    /// @sa https://json.nlohmann.me/api/basic_json/is_structured/
    constexpr bool is_structured() const noexcept
    {
        return is_array() || is_object();
    }

    /// @brief return whether value is null
    /// @sa https://json.nlohmann.me/api/basic_json/is_null/
    constexpr bool is_null() const noexcept
    {
        return m_type == value_t::null;
    }

    /// @brief return whether value is a boolean
    /// @sa https://json.nlohmann.me/api/basic_json/is_boolean/
    constexpr bool is_boolean() const noexcept
    {
        return m_type == value_t::boolean;
    }

    /// @brief return whether value is a number
    /// @sa https://json.nlohmann.me/api/basic_json/is_number/
    constexpr bool is_number() const noexcept
    {
        return is_number_integer() || is_number_float();
    }

    /// @brief return whether value is an integer number
    /// @sa https://json.nlohmann.me/api/basic_json/is_number_integer/
    constexpr bool is_number_integer() const noexcept
    {
        return m_type == value_t::number_integer || m_type == value_t::number_unsigned;
    }

    /// @brief return whether value is an unsigned integer number
    /// @sa https://json.nlohmann.me/api/basic_json/is_number_unsigned/
    constexpr bool is_number_unsigned() const noexcept
    {
        return m_type == value_t::number_unsigned;
    }

    /// @brief return whether value is a floating-point number
    /// @sa https://json.nlohmann.me/api/basic_json/is_number_float/
    constexpr bool is_number_float() const noexcept
    {
        return m_type == value_t::number_float;
    }

    /// @brief return whether value is an object
    /// @sa https://json.nlohmann.me/api/basic_json/is_object/
    constexpr bool is_object() const noexcept
    {
        return m_type == value_t::object;
    }

    /// @brief return whether value is an array
    /// @sa https://json.nlohmann.me/api/basic_json/is_array/
    constexpr bool is_array() const noexcept
    {
        return m_type == value_t::array;
    }

    /// @brief return whether value is a string
    /// @sa https://json.nlohmann.me/api/basic_json/is_string/
    constexpr bool is_string() const noexcept
    {
        return m_type == value_t::string;
    }

    /// @brief return whether value is a binary array
    /// @sa https://json.nlohmann.me/api/basic_json/is_binary/
    constexpr bool is_binary() const noexcept
    {
        return m_type == value_t::binary;
    }

    /// @brief return whether value is discarded
    /// @sa https://json.nlohmann.me/api/basic_json/is_discarded/
    constexpr bool is_discarded() const noexcept
    {
        return m_type == value_t::discarded;
    }

    /// @brief return the type of the JSON value (implicit)
    /// @sa https://json.nlohmann.me/api/basic_json/operator_value_t/
    constexpr operator value_t() const noexcept
    {
        return m_type;
    }

    /// @}

  private:
    //////////////////
    // value access //
    //////////////////

    /// get a boolean (explicit)
    boolean_t get_impl(boolean_t* /*unused*/) const
    {
        if (JSON_HEDLEY_LIKELY(is_boolean()))
        {
            return m_value.boolean;
        }

        JSON_THROW(type_error::create(302, "type must be boolean, but is " + std::string(type_name()), *this));
    }

    /// get a pointer to the value (object)
    object_t* get_impl_ptr(object_t* /*unused*/) noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    /// get a pointer to the value (object)
    constexpr const object_t* get_impl_ptr(const object_t* /*unused*/) const noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    /// get a pointer to the value (array)
    array_t* get_impl_ptr(array_t* /*unused*/) noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    /// get a pointer to the value (array)
    constexpr const array_t* get_impl_ptr(const array_t* /*unused*/) const noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    /// get a pointer to the value (string)
    string_t* get_impl_ptr(string_t* /*unused*/) noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    /// get a pointer to the value (string)
    constexpr const string_t* get_impl_ptr(const string_t* /*unused*/) const noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    /// get a pointer to the value (boolean)
    boolean_t* get_impl_ptr(boolean_t* /*unused*/) noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    /// get a pointer to the value (boolean)
    constexpr const boolean_t* get_impl_ptr(const boolean_t* /*unused*/) const noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    /// get a pointer to the value (integer number)
    number_integer_t* get_impl_ptr(number_integer_t* /*unused*/) noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    /// get a pointer to the value (integer number)
    constexpr const number_integer_t* get_impl_ptr(const number_integer_t* /*unused*/) const noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    /// get a pointer to the value (unsigned number)
    number_unsigned_t* get_impl_ptr(number_unsigned_t* /*unused*/) noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    /// get a pointer to the value (unsigned number)
    constexpr const number_unsigned_t* get_impl_ptr(const number_unsigned_t* /*unused*/) const noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    /// get a pointer to the value (floating-point number)
    number_float_t* get_impl_ptr(number_float_t* /*unused*/) noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    /// get a pointer to the value (floating-point number)
    constexpr const number_float_t* get_impl_ptr(const number_float_t* /*unused*/) const noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    /// get a pointer to the value (binary)
    binary_t* get_impl_ptr(binary_t* /*unused*/) noexcept
    {
        return is_binary() ? m_value.binary : nullptr;
    }

    /// get a pointer to the value (binary)
    constexpr const binary_t* get_impl_ptr(const binary_t* /*unused*/) const noexcept
    {
        return is_binary() ? m_value.binary : nullptr;
    }

    /*!
    @brief helper function to implement get_ref()

    This function helps to implement get_ref() without code duplication for
    const and non-const overloads

    @tparam ThisType will be deduced as `basic_json` or `const basic_json`

    @throw type_error.303 if ReferenceType does not match underlying value
    type of the current JSON
    */
    template<typename ReferenceType, typename ThisType>
    static ReferenceType get_ref_impl(ThisType& obj)
    {
        // delegate the call to get_ptr<>()
        auto* ptr = obj.template get_ptr<typename std::add_pointer<ReferenceType>::type>();

        if (JSON_HEDLEY_LIKELY(ptr != nullptr))
        {
            return *ptr;
        }

        JSON_THROW(type_error::create(303, "incompatible ReferenceType for get_ref, actual type is " + std::string(obj.type_name()), obj));
    }

  public:
    /// @name value access
    /// Direct access to the stored value of a JSON value.
    /// @{

    /// @brief get a pointer value (implicit)
    /// @sa https://json.nlohmann.me/api/basic_json/get_ptr/
    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    auto get_ptr() noexcept -> decltype(std::declval<basic_json_t&>().get_impl_ptr(std::declval<PointerType>()))
    {
        // delegate the call to get_impl_ptr<>()
        return get_impl_ptr(static_cast<PointerType>(nullptr));
    }

    /// @brief get a pointer value (implicit)
    /// @sa https://json.nlohmann.me/api/basic_json/get_ptr/
    template < typename PointerType, typename std::enable_if <
                   std::is_pointer<PointerType>::value&&
                   std::is_const<typename std::remove_pointer<PointerType>::type>::value, int >::type = 0 >
    constexpr auto get_ptr() const noexcept -> decltype(std::declval<const basic_json_t&>().get_impl_ptr(std::declval<PointerType>()))
    {
        // delegate the call to get_impl_ptr<>() const
        return get_impl_ptr(static_cast<PointerType>(nullptr));
    }

  private:
    /*!
    @brief get a value (explicit)

    Explicit type conversion between the JSON value and a compatible value
    which is [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible)
    and [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible).
    The value is converted by calling the @ref json_serializer<ValueType>
    `from_json()` method.

    The function is equivalent to executing
    @code {.cpp}
    ValueType ret;
    JSONSerializer<ValueType>::from_json(*this, ret);
    return ret;
    @endcode

    This overloads is chosen if:
    - @a ValueType is not @ref basic_json,
    - @ref json_serializer<ValueType> has a `from_json()` method of the form
      `void from_json(const basic_json&, ValueType&)`, and
    - @ref json_serializer<ValueType> does not have a `from_json()` method of
      the form `ValueType from_json(const basic_json&)`

    @tparam ValueType the returned value type

    @return copy of the JSON value, converted to @a ValueType

    @throw what @ref json_serializer<ValueType> `from_json()` method throws

    @liveexample{The example below shows several conversions from JSON values
    to other types. There a few things to note: (1) Floating-point numbers can
    be converted to integers\, (2) A JSON array can be converted to a standard
    `std::vector<short>`\, (3) A JSON object can be converted to C++
    associative containers such as `std::unordered_map<std::string\,
    json>`.,get__ValueType_const}

    @since version 2.1.0
    */
    template < typename ValueType,
               detail::enable_if_t <
                   detail::is_default_constructible<ValueType>::value&&
                   detail::has_from_json<basic_json_t, ValueType>::value,
                   int > = 0 >
    ValueType get_impl(detail::priority_tag<0> /*unused*/) const noexcept(noexcept(
                JSONSerializer<ValueType>::from_json(std::declval<const basic_json_t&>(), std::declval<ValueType&>())))
    {
        ValueType ret{};
        JSONSerializer<ValueType>::from_json(*this, ret);
        return ret;
    }

    /*!
    @brief get a value (explicit); special case

    Explicit type conversion between the JSON value and a compatible value
    which is **not** [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible)
    and **not** [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible).
    The value is converted by calling the @ref json_serializer<ValueType>
    `from_json()` method.

    The function is equivalent to executing
    @code {.cpp}
    return JSONSerializer<ValueType>::from_json(*this);
    @endcode

    This overloads is chosen if:
    - @a ValueType is not @ref basic_json and
    - @ref json_serializer<ValueType> has a `from_json()` method of the form
      `ValueType from_json(const basic_json&)`

    @note If @ref json_serializer<ValueType> has both overloads of
    `from_json()`, this one is chosen.

    @tparam ValueType the returned value type

    @return copy of the JSON value, converted to @a ValueType

    @throw what @ref json_serializer<ValueType> `from_json()` method throws

    @since version 2.1.0
    */
    template < typename ValueType,
               detail::enable_if_t <
                   detail::has_non_default_from_json<basic_json_t, ValueType>::value,
                   int > = 0 >
    ValueType get_impl(detail::priority_tag<1> /*unused*/) const noexcept(noexcept(
                JSONSerializer<ValueType>::from_json(std::declval<const basic_json_t&>())))
    {
        return JSONSerializer<ValueType>::from_json(*this);
    }

    /*!
    @brief get special-case overload

    This overloads converts the current @ref basic_json in a different
    @ref basic_json type

    @tparam BasicJsonType == @ref basic_json

    @return a copy of *this, converted into @a BasicJsonType

    @complexity Depending on the implementation of the called `from_json()`
                method.

    @since version 3.2.0
    */
    template < typename BasicJsonType,
               detail::enable_if_t <
                   detail::is_basic_json<BasicJsonType>::value,
                   int > = 0 >
    BasicJsonType get_impl(detail::priority_tag<2> /*unused*/) const
    {
        return *this;
    }

    /*!
    @brief get special-case overload

    This overloads avoids a lot of template boilerplate, it can be seen as the
    identity method

    @tparam BasicJsonType == @ref basic_json

    @return a copy of *this

    @complexity Constant.

    @since version 2.1.0
    */
    template<typename BasicJsonType,
             detail::enable_if_t<
                 std::is_same<BasicJsonType, basic_json_t>::value,
                 int> = 0>
    basic_json get_impl(detail::priority_tag<3> /*unused*/) const
    {
        return *this;
    }

    /*!
    @brief get a pointer value (explicit)
    @copydoc get()
    */
    template<typename PointerType,
             detail::enable_if_t<
                 std::is_pointer<PointerType>::value,
                 int> = 0>
    constexpr auto get_impl(detail::priority_tag<4> /*unused*/) const noexcept
    -> decltype(std::declval<const basic_json_t&>().template get_ptr<PointerType>())
    {
        // delegate the call to get_ptr
        return get_ptr<PointerType>();
    }

  public:
    /*!
    @brief get a (pointer) value (explicit)

    Performs explicit type conversion between the JSON value and a compatible value if required.

    - If the requested type is a pointer to the internally stored JSON value that pointer is returned.
    No copies are made.

    - If the requested type is the current @ref basic_json, or a different @ref basic_json convertible
    from the current @ref basic_json.

    - Otherwise the value is converted by calling the @ref json_serializer<ValueType> `from_json()`
    method.

    @tparam ValueTypeCV the provided value type
    @tparam ValueType the returned value type

    @return copy of the JSON value, converted to @tparam ValueType if necessary

    @throw what @ref json_serializer<ValueType> `from_json()` method throws if conversion is required

    @since version 2.1.0
    */
    template < typename ValueTypeCV, typename ValueType = detail::uncvref_t<ValueTypeCV>>
#if defined(JSON_HAS_CPP_14)
    constexpr
#endif
    auto get() const noexcept(
    noexcept(std::declval<const basic_json_t&>().template get_impl<ValueType>(detail::priority_tag<4> {})))
    -> decltype(std::declval<const basic_json_t&>().template get_impl<ValueType>(detail::priority_tag<4> {}))
    {
        // we cannot static_assert on ValueTypeCV being non-const, because
        // there is support for get<const basic_json_t>(), which is why we
        // still need the uncvref
        static_assert(!std::is_reference<ValueTypeCV>::value,
                      "get() cannot be used with reference types, you might want to use get_ref()");
        return get_impl<ValueType>(detail::priority_tag<4> {});
    }

    /*!
    @brief get a pointer value (explicit)

    Explicit pointer access to the internally stored JSON value. No copies are
    made.

    @warning The pointer becomes invalid if the underlying JSON object
    changes.

    @tparam PointerType pointer type; must be a pointer to @ref array_t, @ref
    object_t, @ref string_t, @ref boolean_t, @ref number_integer_t,
    @ref number_unsigned_t, or @ref number_float_t.

    @return pointer to the internally stored JSON value if the requested
    pointer type @a PointerType fits to the JSON value; `nullptr` otherwise

    @complexity Constant.

    @liveexample{The example below shows how pointers to internal values of a
    JSON value can be requested. Note that no type conversions are made and a
    `nullptr` is returned if the value and the requested pointer type does not
    match.,get__PointerType}

    @sa see @ref get_ptr() for explicit pointer-member access

    @since version 1.0.0
    */
    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    auto get() noexcept -> decltype(std::declval<basic_json_t&>().template get_ptr<PointerType>())
    {
        // delegate the call to get_ptr
        return get_ptr<PointerType>();
    }

    /// @brief get a value (explicit)
    /// @sa https://json.nlohmann.me/api/basic_json/get_to/
    template < typename ValueType,
               detail::enable_if_t <
                   !detail::is_basic_json<ValueType>::value&&
                   detail::has_from_json<basic_json_t, ValueType>::value,
                   int > = 0 >
    ValueType & get_to(ValueType& v) const noexcept(noexcept(
                JSONSerializer<ValueType>::from_json(std::declval<const basic_json_t&>(), v)))
    {
        JSONSerializer<ValueType>::from_json(*this, v);
        return v;
    }

    // specialization to allow to call get_to with a basic_json value
    // see https://github.com/nlohmann/json/issues/2175
    template<typename ValueType,
             detail::enable_if_t <
                 detail::is_basic_json<ValueType>::value,
                 int> = 0>
    ValueType & get_to(ValueType& v) const
    {
        v = *this;
        return v;
    }

    template <
        typename T, std::size_t N,
        typename Array = T (&)[N], // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        detail::enable_if_t <
            detail::has_from_json<basic_json_t, Array>::value, int > = 0 >
    Array get_to(T (&v)[N]) const // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    noexcept(noexcept(JSONSerializer<Array>::from_json(
                          std::declval<const basic_json_t&>(), v)))
    {
        JSONSerializer<Array>::from_json(*this, v);
        return v;
    }

    /*!
    @brief get a reference value (implicit)

    Implicit reference access to the internally stored JSON value. No copies
    are made.

    @warning Writing data to the referee of the result yields an undefined
    state.

    @tparam ReferenceType reference type; must be a reference to @ref array_t,
    @ref object_t, @ref string_t, @ref boolean_t, @ref number_integer_t, or
    @ref number_float_t. Enforced by static assertion.

    @return reference to the internally stored JSON value if the requested
    reference type @a ReferenceType fits to the JSON value; throws
    type_error.303 otherwise

    @throw type_error.303 in case passed type @a ReferenceType is incompatible
    with the stored JSON value; see example below

    @complexity Constant.

    @liveexample{The example shows several calls to `get_ref()`.,get_ref}

    @since version 1.1.0
    */
    template<typename ReferenceType, typename std::enable_if<
                 std::is_reference<ReferenceType>::value, int>::type = 0>
    ReferenceType get_ref()
    {
        // delegate call to get_ref_impl
        return get_ref_impl<ReferenceType>(*this);
    }

    /*!
    @brief get a reference value (implicit)
    @copydoc get_ref()
    */
    template < typename ReferenceType, typename std::enable_if <
                   std::is_reference<ReferenceType>::value&&
                   std::is_const<typename std::remove_reference<ReferenceType>::type>::value, int >::type = 0 >
    ReferenceType get_ref() const
    {
        // delegate call to get_ref_impl
        return get_ref_impl<ReferenceType>(*this);
    }

    /*!
    @brief get a value (implicit)

    Implicit type conversion between the JSON value and a compatible value.
    The call is realized by calling @ref get() const.

    @tparam ValueType non-pointer type compatible to the JSON value, for
    instance `int` for JSON integer numbers, `bool` for JSON booleans, or
    `std::vector` types for JSON arrays. The character type of @ref string_t
    as well as an initializer list of this type is excluded to avoid
    ambiguities as these types implicitly convert to `std::string`.

    @return copy of the JSON value, converted to type @a ValueType

    @throw type_error.302 in case passed type @a ValueType is incompatible
    to the JSON value type (e.g., the JSON value is of type boolean, but a
    string is requested); see example below

    @complexity Linear in the size of the JSON value.

    @liveexample{The example below shows several conversions from JSON values
    to other types. There a few things to note: (1) Floating-point numbers can
    be converted to integers\, (2) A JSON array can be converted to a standard
    `std::vector<short>`\, (3) A JSON object can be converted to C++
    associative containers such as `std::unordered_map<std::string\,
    json>`.,operator__ValueType}

    @since version 1.0.0
    */
    template < typename ValueType, typename std::enable_if <
                   detail::conjunction <
                       detail::negation<std::is_pointer<ValueType>>,
                       detail::negation<std::is_same<ValueType, detail::json_ref<basic_json>>>,
                                        detail::negation<std::is_same<ValueType, typename string_t::value_type>>,
                                        detail::negation<detail::is_basic_json<ValueType>>,
                                        detail::negation<std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>>,

#if defined(JSON_HAS_CPP_17) && (defined(__GNUC__) || (defined(_MSC_VER) && _MSC_VER >= 1910 && _MSC_VER <= 1914))
                                                detail::negation<std::is_same<ValueType, std::string_view>>,
#endif
                                                detail::is_detected_lazy<detail::get_template_function, const basic_json_t&, ValueType>
                                                >::value, int >::type = 0 >
                                        JSON_EXPLICIT operator ValueType() const
    {
        // delegate the call to get<>() const
        return get<ValueType>();
    }

    /// @brief get a binary value
    /// @sa https://json.nlohmann.me/api/basic_json/get_binary/
    binary_t& get_binary()
    {
        if (!is_binary())
        {
            JSON_THROW(type_error::create(302, "type must be binary, but is " + std::string(type_name()), *this));
        }

        return *get_ptr<binary_t*>();
    }

    /// @brief get a binary value
    /// @sa https://json.nlohmann.me/api/basic_json/get_binary/
    const binary_t& get_binary() const
    {
        if (!is_binary())
        {
            JSON_THROW(type_error::create(302, "type must be binary, but is " + std::string(type_name()), *this));
        }

        return *get_ptr<const binary_t*>();
    }

    /// @}


    ////////////////////
    // element access //
    ////////////////////

    /// @name element access
    /// Access to the JSON value.
    /// @{

    /*!
    @brief access specified array element with bounds checking

    Returns a reference to the element at specified location @a idx, with
    bounds checking.

    @param[in] idx  index of the element to access

    @return reference to the element at index @a idx

    @throw type_error.304 if the JSON value is not an array; in this case,
    calling `at` with an index makes no sense. See example below.
    @throw out_of_range.401 if the index @a idx is out of range of the array;
    that is, `idx >= size()`. See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Constant.

    @since version 1.0.0

    @liveexample{The example below shows how array elements can be read and
    written using `at()`. It also demonstrates the different exceptions that
    can be thrown.,at__size_type}
    */
    reference at(size_type idx)
    {
        // at only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            JSON_TRY
            {
                return set_parent(m_value.array->at(idx));
            }
            JSON_CATCH (std::out_of_range&)
            {
                // create better exception explanation
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range", *this));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief access specified array element with bounds checking

    Returns a const reference to the element at specified location @a idx,
    with bounds checking.

    @param[in] idx  index of the element to access

    @return const reference to the element at index @a idx

    @throw type_error.304 if the JSON value is not an array; in this case,
    calling `at` with an index makes no sense. See example below.
    @throw out_of_range.401 if the index @a idx is out of range of the array;
    that is, `idx >= size()`. See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Constant.

    @since version 1.0.0

    @liveexample{The example below shows how array elements can be read using
    `at()`. It also demonstrates the different exceptions that can be thrown.,
    at__size_type_const}
    */
    const_reference at(size_type idx) const
    {
        // at only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            JSON_TRY
            {
                return m_value.array->at(idx);
            }
            JSON_CATCH (std::out_of_range&)
            {
                // create better exception explanation
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range", *this));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief access specified object element with bounds checking

    Returns a reference to the element at with specified key @a key, with
    bounds checking.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw type_error.304 if the JSON value is not an object; in this case,
    calling `at` with a key makes no sense. See example below.
    @throw out_of_range.403 if the key @a key is is not stored in the object;
    that is, `find(key) == end()`. See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Logarithmic in the size of the container.

    @sa see @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference
    @sa see @ref value() for access by value with a default value

    @since version 1.0.0

    @liveexample{The example below shows how object elements can be read and
    written using `at()`. It also demonstrates the different exceptions that
    can be thrown.,at__object_t_key_type}
    */
    reference at(const typename object_t::key_type& key)
    {
        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            JSON_TRY
            {
                return set_parent(m_value.object->at(key));
            }
            JSON_CATCH (std::out_of_range&)
            {
                // create better exception explanation
                JSON_THROW(out_of_range::create(403, "key '" + key + "' not found", *this));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief access specified object element with bounds checking

    Returns a const reference to the element at with specified key @a key,
    with bounds checking.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @throw type_error.304 if the JSON value is not an object; in this case,
    calling `at` with a key makes no sense. See example below.
    @throw out_of_range.403 if the key @a key is is not stored in the object;
    that is, `find(key) == end()`. See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Logarithmic in the size of the container.

    @sa see @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference
    @sa see @ref value() for access by value with a default value

    @since version 1.0.0

    @liveexample{The example below shows how object elements can be read using
    `at()`. It also demonstrates the different exceptions that can be thrown.,
    at__object_t_key_type_const}
    */
    const_reference at(const typename object_t::key_type& key) const
    {
        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            JSON_TRY
            {
                return m_value.object->at(key);
            }
            JSON_CATCH (std::out_of_range&)
            {
                // create better exception explanation
                JSON_THROW(out_of_range::create(403, "key '" + key + "' not found", *this));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief access specified array element

    Returns a reference to the element at specified location @a idx.

    @note If @a idx is beyond the range of the array (i.e., `idx >= size()`),
    then the array is silently filled up with `null` values to make `idx` a
    valid reference to the last stored element.

    @param[in] idx  index of the element to access

    @return reference to the element at index @a idx

    @throw type_error.305 if the JSON value is not an array or null; in that
    cases, using the [] operator with an index makes no sense.

    @complexity Constant if @a idx is in the range of the array. Otherwise
    linear in `idx - size()`.

    @liveexample{The example below shows how array elements can be read and
    written using `[]` operator. Note the addition of `null`
    values.,operatorarray__size_type}

    @since version 1.0.0
    */
    reference operator[](size_type idx)
    {
        // implicitly convert null value to an empty array
        if (is_null())
        {
            m_type = value_t::array;
            m_value.array = create<array_t>();
            assert_invariant();
        }

        // operator[] only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            // fill up array with null values if given idx is outside range
            if (idx >= m_value.array->size())
            {
#if JSON_DIAGNOSTICS
                // remember array size & capacity before resizing
                const auto old_size = m_value.array->size();
                const auto old_capacity = m_value.array->capacity();
#endif
                m_value.array->resize(idx + 1);

#if JSON_DIAGNOSTICS
                if (JSON_HEDLEY_UNLIKELY(m_value.array->capacity() != old_capacity))
                {
                    // capacity has changed: update all parents
                    set_parents();
                }
                else
                {
                    // set parent for values added above
                    set_parents(begin() + static_cast<typename iterator::difference_type>(old_size), static_cast<typename iterator::difference_type>(idx + 1 - old_size));
                }
#endif
                assert_invariant();
            }

            return m_value.array->operator[](idx);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a numeric argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief access specified array element

    Returns a const reference to the element at specified location @a idx.

    @param[in] idx  index of the element to access

    @return const reference to the element at index @a idx

    @throw type_error.305 if the JSON value is not an array; in that case,
    using the [] operator with an index makes no sense.

    @complexity Constant.

    @liveexample{The example below shows how array elements can be read using
    the `[]` operator.,operatorarray__size_type_const}

    @since version 1.0.0
    */
    const_reference operator[](size_type idx) const
    {
        // const operator[] only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            return m_value.array->operator[](idx);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a numeric argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief access specified object element

    Returns a reference to the element at with specified key @a key.

    @note If @a key is not found in the object, then it is silently added to
    the object and filled with a `null` value to make `key` a valid reference.
    In case the value was `null` before, it is converted to an object.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw type_error.305 if the JSON value is not an object or null; in that
    cases, using the [] operator with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using the `[]` operator.,operatorarray__key_type}

    @sa see @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa see @ref value() for access by value with a default value

    @since version 1.0.0
    */
    reference operator[](const typename object_t::key_type& key)
    {
        // implicitly convert null value to an empty object
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        // operator[] only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            return set_parent(m_value.object->operator[](key));
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a string argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief read-only access specified object element

    Returns a const reference to the element at with specified key @a key. No
    bounds checking is performed.

    @warning If the element with key @a key does not exist, the behavior is
    undefined.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @pre The element with key @a key must exist. **This precondition is
         enforced with an assertion.**

    @throw type_error.305 if the JSON value is not an object; in that case,
    using the [] operator with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    the `[]` operator.,operatorarray__key_type_const}

    @sa see @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa see @ref value() for access by value with a default value

    @since version 1.0.0
    */
    const_reference operator[](const typename object_t::key_type& key) const
    {
        // const operator[] only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            JSON_ASSERT(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a string argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief access specified object element

    Returns a reference to the element at with specified key @a key.

    @note If @a key is not found in the object, then it is silently added to
    the object and filled with a `null` value to make `key` a valid reference.
    In case the value was `null` before, it is converted to an object.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw type_error.305 if the JSON value is not an object or null; in that
    cases, using the [] operator with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using the `[]` operator.,operatorarray__key_type}

    @sa see @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa see @ref value() for access by value with a default value

    @since version 1.1.0
    */
    template<typename T>
    JSON_HEDLEY_NON_NULL(2)
    reference operator[](T* key)
    {
        // implicitly convert null to object
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            return set_parent(m_value.object->operator[](key));
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a string argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief read-only access specified object element

    Returns a const reference to the element at with specified key @a key. No
    bounds checking is performed.

    @warning If the element with key @a key does not exist, the behavior is
    undefined.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @pre The element with key @a key must exist. **This precondition is
         enforced with an assertion.**

    @throw type_error.305 if the JSON value is not an object; in that case,
    using the [] operator with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    the `[]` operator.,operatorarray__key_type_const}

    @sa see @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa see @ref value() for access by value with a default value

    @since version 1.1.0
    */
    template<typename T>
    JSON_HEDLEY_NON_NULL(2)
    const_reference operator[](T* key) const
    {
        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            JSON_ASSERT(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with a string argument with " + std::string(type_name()), *this));
    }

    /*!
    @brief access specified object element with default value

    Returns either a copy of an object's element at the specified key @a key
    or a given default value if no element with key @a key exists.

    The function is basically equivalent to executing
    @code {.cpp}
    try {
        return at(key);
    } catch(out_of_range) {
        return default_value;
    }
    @endcode

    @note Unlike @ref at(const typename object_t::key_type&), this function
    does not throw if the given key @a key was not found.

    @note Unlike @ref operator[](const typename object_t::key_type& key), this
    function does not implicitly add an element to the position defined by @a
    key. This function is furthermore also applicable to const objects.

    @param[in] key  key of the element to access
    @param[in] default_value  the value to return if @a key is not found

    @tparam ValueType type compatible to JSON values, for instance `int` for
    JSON integer numbers, `bool` for JSON booleans, or `std::vector` types for
    JSON arrays. Note the type of the expected value at @a key and the default
    value @a default_value must be compatible.

    @return copy of the element at key @a key or @a default_value if @a key
    is not found

    @throw type_error.302 if @a default_value does not match the type of the
    value at @a key
    @throw type_error.306 if the JSON value is not an object; in that case,
    using `value()` with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be queried
    with a default value.,basic_json__value}

    @sa see @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa see @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference

    @since version 1.0.0
    */
    // using std::is_convertible in a std::enable_if will fail when using explicit conversions
    template < class ValueType, typename std::enable_if <
                   detail::is_getable<basic_json_t, ValueType>::value
                   && !std::is_same<value_t, ValueType>::value, int >::type = 0 >
    ValueType value(const typename object_t::key_type& key, const ValueType& default_value) const
    {
        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            // if key is found, return value and given default value otherwise
            const auto it = find(key);
            if (it != end())
            {
                return it->template get<ValueType>();
            }

            return default_value;
        }

        JSON_THROW(type_error::create(306, "cannot use value() with " + std::string(type_name()), *this));
    }

    /*!
    @brief overload for a default value of type const char*
    @copydoc basic_json::value(const typename object_t::key_type&, const ValueType&) const
    */
    string_t value(const typename object_t::key_type& key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    /*!
    @brief access specified object element via JSON Pointer with default value

    Returns either a copy of an object's element at the specified key @a key
    or a given default value if no element with key @a key exists.

    The function is basically equivalent to executing
    @code {.cpp}
    try {
        return at(ptr);
    } catch(out_of_range) {
        return default_value;
    }
    @endcode

    @note Unlike @ref at(const json_pointer&), this function does not throw
    if the given key @a key was not found.

    @param[in] ptr  a JSON pointer to the element to access
    @param[in] default_value  the value to return if @a ptr found no value

    @tparam ValueType type compatible to JSON values, for instance `int` for
    JSON integer numbers, `bool` for JSON booleans, or `std::vector` types for
    JSON arrays. Note the type of the expected value at @a key and the default
    value @a default_value must be compatible.

    @return copy of the element at key @a key or @a default_value if @a key
    is not found

    @throw type_error.302 if @a default_value does not match the type of the
    value at @a ptr
    @throw type_error.306 if the JSON value is not an object; in that case,
    using `value()` with a key makes no sense.

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be queried
    with a default value.,basic_json__value_ptr}

    @sa see @ref operator[](const json_pointer&) for unchecked access by reference

    @since version 2.0.2
    */
    template<class ValueType, typename std::enable_if<
                 detail::is_getable<basic_json_t, ValueType>::value, int>::type = 0>
    ValueType value(const json_pointer& ptr, const ValueType& default_value) const
    {
        // at only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            // if pointer resolves a value, return it or use default value
            JSON_TRY
            {
                return ptr.get_checked(this).template get<ValueType>();
            }
            JSON_INTERNAL_CATCH (out_of_range&)
            {
                return default_value;
            }
        }

        JSON_THROW(type_error::create(306, "cannot use value() with " + std::string(type_name()), *this));
    }

    /*!
    @brief overload for a default value of type const char*
    @copydoc basic_json::value(const json_pointer&, ValueType) const
    */
    JSON_HEDLEY_NON_NULL(3)
    string_t value(const json_pointer& ptr, const char* default_value) const
    {
        return value(ptr, string_t(default_value));
    }

    /// @brief access the first element
    /// @sa https://json.nlohmann.me/api/basic_json/front/
    reference front()
    {
        return *begin();
    }

    /// @brief access the first element
    /// @sa https://json.nlohmann.me/api/basic_json/front/
    const_reference front() const
    {
        return *cbegin();
    }

    /// @brief access the last element
    /// @sa https://json.nlohmann.me/api/basic_json/back/
    reference back()
    {
        auto tmp = end();
        --tmp;
        return *tmp;
    }

    /// @brief access the last element
    /// @sa https://json.nlohmann.me/api/basic_json/back/
    const_reference back() const
    {
        auto tmp = cend();
        --tmp;
        return *tmp;
    }

    /*!
    @brief remove element given an iterator

    Removes the element specified by iterator @a pos. The iterator @a pos must
    be valid and dereferenceable. Thus the `end()` iterator (which is valid,
    but is not dereferenceable) cannot be used as a value for @a pos.

    If called on a primitive type other than `null`, the resulting JSON value
    will be `null`.

    @param[in] pos iterator to the element to remove
    @return Iterator following the last removed element. If the iterator @a
    pos refers to the last element, the `end()` iterator is returned.

    @tparam IteratorType an @ref iterator or @ref const_iterator

    @post Invalidates iterators and references at or after the point of the
    erase, including the `end()` iterator.

    @throw type_error.307 if called on a `null` value; example: `"cannot use
    erase() with null"`
    @throw invalid_iterator.202 if called on an iterator which does not belong
    to the current JSON value; example: `"iterator does not fit current
    value"`
    @throw invalid_iterator.205 if called on a primitive type with invalid
    iterator (i.e., any iterator which is not `begin()`); example: `"iterator
    out of range"`

    @complexity The complexity depends on the type:
    - objects: amortized constant
    - arrays: linear in distance between @a pos and the end of the container
    - strings and binary: linear in the length of the member
    - other types: constant

    @liveexample{The example shows the result of `erase()` for different JSON
    types.,erase__IteratorType}

    @sa see @ref erase(IteratorType, IteratorType) -- removes the elements in
    the given range
    @sa see @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key
    @sa see @ref erase(const size_type) -- removes the element from an array at
    the given index

    @since version 1.0.0
    */
    template < class IteratorType, typename std::enable_if <
                   std::is_same<IteratorType, typename basic_json_t::iterator>::value ||
                   std::is_same<IteratorType, typename basic_json_t::const_iterator>::value, int >::type
               = 0 >
    IteratorType erase(IteratorType pos)
    {
        // make sure iterator fits the current value
        if (JSON_HEDLEY_UNLIKELY(this != pos.m_object))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value", *this));
        }

        IteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            case value_t::binary:
            {
                if (JSON_HEDLEY_UNLIKELY(!pos.m_it.primitive_iterator.is_begin()))
                {
                    JSON_THROW(invalid_iterator::create(205, "iterator out of range", *this));
                }

                if (is_string())
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.string, 1);
                    m_value.string = nullptr;
                }
                else if (is_binary())
                {
                    AllocatorType<binary_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.binary);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.binary, 1);
                    m_value.binary = nullptr;
                }

                m_type = value_t::null;
                assert_invariant();
                break;
            }

            case value_t::object:
            {
                result.m_it.object_iterator = m_value.object->erase(pos.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                result.m_it.array_iterator = m_value.array->erase(pos.m_it.array_iterator);
                break;
            }

            case value_t::null:
            case value_t::discarded:
            default:
                JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name()), *this));
        }

        return result;
    }

    /*!
    @brief remove elements given an iterator range

    Removes the element specified by the range `[first; last)`. The iterator
    @a first does not need to be dereferenceable if `first == last`: erasing
    an empty range is a no-op.

    If called on a primitive type other than `null`, the resulting JSON value
    will be `null`.

    @param[in] first iterator to the beginning of the range to remove
    @param[in] last iterator past the end of the range to remove
    @return Iterator following the last removed element. If the iterator @a
    second refers to the last element, the `end()` iterator is returned.

    @tparam IteratorType an @ref iterator or @ref const_iterator

    @post Invalidates iterators and references at or after the point of the
    erase, including the `end()` iterator.

    @throw type_error.307 if called on a `null` value; example: `"cannot use
    erase() with null"`
    @throw invalid_iterator.203 if called on iterators which does not belong
    to the current JSON value; example: `"iterators do not fit current value"`
    @throw invalid_iterator.204 if called on a primitive type with invalid
    iterators (i.e., if `first != begin()` and `last != end()`); example:
    `"iterators out of range"`

    @complexity The complexity depends on the type:
    - objects: `log(size()) + std::distance(first, last)`
    - arrays: linear in the distance between @a first and @a last, plus linear
      in the distance between @a last and end of the container
    - strings and binary: linear in the length of the member
    - other types: constant

    @liveexample{The example shows the result of `erase()` for different JSON
    types.,erase__IteratorType_IteratorType}

    @sa see @ref erase(IteratorType) -- removes the element at a given position
    @sa see @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key
    @sa see @ref erase(const size_type) -- removes the element from an array at
    the given index

    @since version 1.0.0
    */
    template < class IteratorType, typename std::enable_if <
                   std::is_same<IteratorType, typename basic_json_t::iterator>::value ||
                   std::is_same<IteratorType, typename basic_json_t::const_iterator>::value, int >::type
               = 0 >
    IteratorType erase(IteratorType first, IteratorType last)
    {
        // make sure iterator fits the current value
        if (JSON_HEDLEY_UNLIKELY(this != first.m_object || this != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(203, "iterators do not fit current value", *this));
        }

        IteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            case value_t::binary:
            {
                if (JSON_HEDLEY_LIKELY(!first.m_it.primitive_iterator.is_begin()
                                       || !last.m_it.primitive_iterator.is_end()))
                {
                    JSON_THROW(invalid_iterator::create(204, "iterators out of range", *this));
                }

                if (is_string())
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.string, 1);
                    m_value.string = nullptr;
                }
                else if (is_binary())
                {
                    AllocatorType<binary_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.binary);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.binary, 1);
                    m_value.binary = nullptr;
                }

                m_type = value_t::null;
                assert_invariant();
                break;
            }

            case value_t::object:
            {
                result.m_it.object_iterator = m_value.object->erase(first.m_it.object_iterator,
                                              last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                result.m_it.array_iterator = m_value.array->erase(first.m_it.array_iterator,
                                             last.m_it.array_iterator);
                break;
            }

            case value_t::null:
            case value_t::discarded:
            default:
                JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name()), *this));
        }

        return result;
    }

    /*!
    @brief remove element from a JSON object given a key

    Removes elements from a JSON object with the key value @a key.

    @param[in] key value of the elements to remove

    @return Number of elements removed. If @a ObjectType is the default
    `std::map` type, the return value will always be `0` (@a key was not
    found) or `1` (@a key was found).

    @post References and iterators to the erased elements are invalidated.
    Other references and iterators are not affected.

    @throw type_error.307 when called on a type other than JSON object;
    example: `"cannot use erase() with null"`

    @complexity `log(size()) + count(key)`

    @liveexample{The example shows the effect of `erase()`.,erase__key_type}

    @sa see @ref erase(IteratorType) -- removes the element at a given position
    @sa see @ref erase(IteratorType, IteratorType) -- removes the elements in
    the given range
    @sa see @ref erase(const size_type) -- removes the element from an array at
    the given index

    @since version 1.0.0
    */
    size_type erase(const typename object_t::key_type& key)
    {
        // this erase only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            return m_value.object->erase(key);
        }

        JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name()), *this));
    }

    /*!
    @brief remove element from a JSON array given an index

    Removes element from a JSON array at the index @a idx.

    @param[in] idx index of the element to remove

    @throw type_error.307 when called on a type other than JSON object;
    example: `"cannot use erase() with null"`
    @throw out_of_range.401 when `idx >= size()`; example: `"array index 17
    is out of range"`

    @complexity Linear in distance between @a idx and the end of the container.

    @liveexample{The example shows the effect of `erase()`.,erase__size_type}

    @sa see @ref erase(IteratorType) -- removes the element at a given position
    @sa see @ref erase(IteratorType, IteratorType) -- removes the elements in
    the given range
    @sa see @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key

    @since version 1.0.0
    */
    void erase(const size_type idx)
    {
        // this erase only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            if (JSON_HEDLEY_UNLIKELY(idx >= size()))
            {
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range", *this));
            }

            m_value.array->erase(m_value.array->begin() + static_cast<difference_type>(idx));
        }
        else
        {
            JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name()), *this));
        }
    }

    /// @}


    ////////////
    // lookup //
    ////////////

    /// @name lookup
    /// @{

    /// @brief find an element in a JSON object
    /// @sa https://json.nlohmann.me/api/basic_json/find/
    template<typename KeyT>
    iterator find(KeyT&& key)
    {
        auto result = end();

        if (is_object())
        {
            result.m_it.object_iterator = m_value.object->find(std::forward<KeyT>(key));
        }

        return result;
    }

    /// @brief find an element in a JSON object
    /// @sa https://json.nlohmann.me/api/basic_json/find/
    template<typename KeyT>
    const_iterator find(KeyT&& key) const
    {
        auto result = cend();

        if (is_object())
        {
            result.m_it.object_iterator = m_value.object->find(std::forward<KeyT>(key));
        }

        return result;
    }

    /// @brief returns the number of occurrences of a key in a JSON object
    /// @sa https://json.nlohmann.me/api/basic_json/count/
    template<typename KeyT>
    size_type count(KeyT&& key) const
    {
        // return 0 for all nonobject types
        return is_object() ? m_value.object->count(std::forward<KeyT>(key)) : 0;
    }

    /// @brief check the existence of an element in a JSON object
    /// @sa https://json.nlohmann.me/api/basic_json/contains/
    template < typename KeyT, typename std::enable_if <
                   !std::is_same<typename std::decay<KeyT>::type, json_pointer>::value, int >::type = 0 >
    bool contains(KeyT && key) const
    {
        return is_object() && m_value.object->find(std::forward<KeyT>(key)) != m_value.object->end();
    }

    /// @brief check the existence of an element in a JSON object given a JSON pointer
    /// @sa https://json.nlohmann.me/api/basic_json/contains/
    bool contains(const json_pointer& ptr) const
    {
        return ptr.contains(this);
    }

    /// @}


    ///////////////
    // iterators //
    ///////////////

    /// @name iterators
    /// @{

    /// @brief returns an iterator to the first element
    /// @sa https://json.nlohmann.me/api/basic_json/begin/
    iterator begin() noexcept
    {
        iterator result(this);
        result.set_begin();
        return result;
    }

    /// @brief returns an iterator to the first element
    /// @sa https://json.nlohmann.me/api/basic_json/begin/
    const_iterator begin() const noexcept
    {
        return cbegin();
    }

    /// @brief returns a const iterator to the first element
    /// @sa https://json.nlohmann.me/api/basic_json/cbegin/
    const_iterator cbegin() const noexcept
    {
        const_iterator result(this);
        result.set_begin();
        return result;
    }

    /// @brief returns an iterator to one past the last element
    /// @sa https://json.nlohmann.me/api/basic_json/end/
    iterator end() noexcept
    {
        iterator result(this);
        result.set_end();
        return result;
    }

    /// @brief returns an iterator to one past the last element
    /// @sa https://json.nlohmann.me/api/basic_json/end/
    const_iterator end() const noexcept
    {
        return cend();
    }

    /// @brief returns an iterator to one past the last element
    /// @sa https://json.nlohmann.me/api/basic_json/cend/
    const_iterator cend() const noexcept
    {
        const_iterator result(this);
        result.set_end();
        return result;
    }

    /// @brief returns an iterator to the reverse-beginning
    /// @sa https://json.nlohmann.me/api/basic_json/rbegin/
    reverse_iterator rbegin() noexcept
    {
        return reverse_iterator(end());
    }

    /// @brief returns an iterator to the reverse-beginning
    /// @sa https://json.nlohmann.me/api/basic_json/rbegin/
    const_reverse_iterator rbegin() const noexcept
    {
        return crbegin();
    }

    /// @brief returns an iterator to the reverse-end
    /// @sa https://json.nlohmann.me/api/basic_json/rend/
    reverse_iterator rend() noexcept
    {
        return reverse_iterator(begin());
    }

    /// @brief returns an iterator to the reverse-end
    /// @sa https://json.nlohmann.me/api/basic_json/rend/
    const_reverse_iterator rend() const noexcept
    {
        return crend();
    }

    /// @brief returns a const reverse iterator to the last element
    /// @sa https://json.nlohmann.me/api/basic_json/crbegin/
    const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(cend());
    }

    /// @brief returns a const reverse iterator to one before the first
    /// @sa https://json.nlohmann.me/api/basic_json/crend/
    const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(cbegin());
    }

  public:
    /*!
    @brief wrapper to access iterator member functions in range-based for
    @sa https://json.nlohmann.me/api/basic_json/items/
    @deprecated This function is deprecated since 3.1.0 and will be removed in
                version 4.0.0 of the library. Please use @ref items() instead;
                that is, replace `json::iterator_wrapper(j)` with `j.items()`.
    */
    JSON_HEDLEY_DEPRECATED_FOR(3.1.0, items())
    static iteration_proxy<iterator> iterator_wrapper(reference ref) noexcept
    {
        return ref.items();
    }

    /*!
    @copydoc iterator_wrapper(reference)
    */
    JSON_HEDLEY_DEPRECATED_FOR(3.1.0, items())
    static iteration_proxy<const_iterator> iterator_wrapper(const_reference ref) noexcept
    {
        return ref.items();
    }

    /// @brief helper to access iterator member functions in range-based for
    /// @sa https://json.nlohmann.me/api/basic_json/items/
    iteration_proxy<iterator> items() noexcept
    {
        return iteration_proxy<iterator>(*this);
    }

    /// @brief helper to access iterator member functions in range-based for
    /// @sa https://json.nlohmann.me/api/basic_json/items/
    iteration_proxy<const_iterator> items() const noexcept
    {
        return iteration_proxy<const_iterator>(*this);
    }

    /// @}


    //////////////
    // capacity //
    //////////////

    /// @name capacity
    /// @{

    /// @brief checks whether the container is empty.
    /// @sa https://json.nlohmann.me/api/basic_json/empty/
    bool empty() const noexcept
    {
        switch (m_type)
        {
            case value_t::null:
            {
                // null values are empty
                return true;
            }

            case value_t::array:
            {
                // delegate call to array_t::empty()
                return m_value.array->empty();
            }

            case value_t::object:
            {
                // delegate call to object_t::empty()
                return m_value.object->empty();
            }

            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
            {
                // all other types are nonempty
                return false;
            }
        }
    }

    /// @brief returns the number of elements
    /// @sa https://json.nlohmann.me/api/basic_json/size/
    size_type size() const noexcept
    {
        switch (m_type)
        {
            case value_t::null:
            {
                // null values are empty
                return 0;
            }

            case value_t::array:
            {
                // delegate call to array_t::size()
                return m_value.array->size();
            }

            case value_t::object:
            {
                // delegate call to object_t::size()
                return m_value.object->size();
            }

            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
            {
                // all other types have size 1
                return 1;
            }
        }
    }

    /// @brief returns the maximum possible number of elements
    /// @sa https://json.nlohmann.me/api/basic_json/max_size/
    size_type max_size() const noexcept
    {
        switch (m_type)
        {
            case value_t::array:
            {
                // delegate call to array_t::max_size()
                return m_value.array->max_size();
            }

            case value_t::object:
            {
                // delegate call to object_t::max_size()
                return m_value.object->max_size();
            }

            case value_t::null:
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
            {
                // all other types have max_size() == size()
                return size();
            }
        }
    }

    /// @}


    ///////////////
    // modifiers //
    ///////////////

    /// @name modifiers
    /// @{

    /// @brief clears the contents
    /// @sa https://json.nlohmann.me/api/basic_json/clear/
    void clear() noexcept
    {
        switch (m_type)
        {
            case value_t::number_integer:
            {
                m_value.number_integer = 0;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value.number_unsigned = 0;
                break;
            }

            case value_t::number_float:
            {
                m_value.number_float = 0.0;
                break;
            }

            case value_t::boolean:
            {
                m_value.boolean = false;
                break;
            }

            case value_t::string:
            {
                m_value.string->clear();
                break;
            }

            case value_t::binary:
            {
                m_value.binary->clear();
                break;
            }

            case value_t::array:
            {
                m_value.array->clear();
                break;
            }

            case value_t::object:
            {
                m_value.object->clear();
                break;
            }

            case value_t::null:
            case value_t::discarded:
            default:
                break;
        }
    }

    /*!
    @brief add an object to an array

    Appends the given element @a val to the end of the JSON value. If the
    function is called on a JSON null value, an empty array is created before
    appending @a val.

    @param[in] val the value to add to the JSON array

    @throw type_error.308 when called on a type other than JSON array or
    null; example: `"cannot use push_back() with number"`

    @complexity Amortized constant.

    @liveexample{The example shows how `push_back()` and `+=` can be used to
    add elements to a JSON array. Note how the `null` value was silently
    converted to a JSON array.,push_back}

    @since version 1.0.0
    */
    void push_back(basic_json&& val)
    {
        // push_back only works for null objects or arrays
        if (JSON_HEDLEY_UNLIKELY(!(is_null() || is_array())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name()), *this));
        }

        // transform null object into an array
        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        // add element to array (move semantics)
        const auto old_capacity = m_value.array->capacity();
        m_value.array->push_back(std::move(val));
        set_parent(m_value.array->back(), old_capacity);
        // if val is moved from, basic_json move constructor marks it null so we do not call the destructor
    }

    /*!
    @brief add an object to an array
    @copydoc push_back(basic_json&&)
    */
    reference operator+=(basic_json&& val)
    {
        push_back(std::move(val));
        return *this;
    }

    /*!
    @brief add an object to an array
    @copydoc push_back(basic_json&&)
    */
    void push_back(const basic_json& val)
    {
        // push_back only works for null objects or arrays
        if (JSON_HEDLEY_UNLIKELY(!(is_null() || is_array())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name()), *this));
        }

        // transform null object into an array
        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        // add element to array
        const auto old_capacity = m_value.array->capacity();
        m_value.array->push_back(val);
        set_parent(m_value.array->back(), old_capacity);
    }

    /*!
    @brief add an object to an array
    @copydoc push_back(basic_json&&)
    */
    reference operator+=(const basic_json& val)
    {
        push_back(val);
        return *this;
    }

    /*!
    @brief add an object to an object

    Inserts the given element @a val to the JSON object. If the function is
    called on a JSON null value, an empty object is created before inserting
    @a val.

    @param[in] val the value to add to the JSON object

    @throw type_error.308 when called on a type other than JSON object or
    null; example: `"cannot use push_back() with number"`

    @complexity Logarithmic in the size of the container, O(log(`size()`)).

    @liveexample{The example shows how `push_back()` and `+=` can be used to
    add elements to a JSON object. Note how the `null` value was silently
    converted to a JSON object.,push_back__object_t__value}

    @since version 1.0.0
    */
    void push_back(const typename object_t::value_type& val)
    {
        // push_back only works for null objects or objects
        if (JSON_HEDLEY_UNLIKELY(!(is_null() || is_object())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name()), *this));
        }

        // transform null object into an object
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        // add element to object
        auto res = m_value.object->insert(val);
        set_parent(res.first->second);
    }

    /*!
    @brief add an object to an object
    @copydoc push_back(const typename object_t::value_type&)
    */
    reference operator+=(const typename object_t::value_type& val)
    {
        push_back(val);
        return *this;
    }

    /*!
    @brief add an object to an object

    This function allows to use `push_back` with an initializer list. In case

    1. the current value is an object,
    2. the initializer list @a init contains only two elements, and
    3. the first element of @a init is a string,

    @a init is converted into an object element and added using
    @ref push_back(const typename object_t::value_type&). Otherwise, @a init
    is converted to a JSON value and added using @ref push_back(basic_json&&).

    @param[in] init  an initializer list

    @complexity Linear in the size of the initializer list @a init.

    @note This function is required to resolve an ambiguous overload error,
          because pairs like `{"key", "value"}` can be both interpreted as
          `object_t::value_type` or `std::initializer_list<basic_json>`, see
          https://github.com/nlohmann/json/issues/235 for more information.

    @liveexample{The example shows how initializer lists are treated as
    objects when possible.,push_back__initializer_list}
    */
    void push_back(initializer_list_t init)
    {
        if (is_object() && init.size() == 2 && (*init.begin())->is_string())
        {
            basic_json&& key = init.begin()->moved_or_copied();
            push_back(typename object_t::value_type(
                          std::move(key.get_ref<string_t&>()), (init.begin() + 1)->moved_or_copied()));
        }
        else
        {
            push_back(basic_json(init));
        }
    }

    /*!
    @brief add an object to an object
    @copydoc push_back(initializer_list_t)
    */
    reference operator+=(initializer_list_t init)
    {
        push_back(init);
        return *this;
    }

    /// @brief add an object to an array
    /// @sa https://json.nlohmann.me/api/basic_json/emplace_back/
    template<class... Args>
    reference emplace_back(Args&& ... args)
    {
        // emplace_back only works for null objects or arrays
        if (JSON_HEDLEY_UNLIKELY(!(is_null() || is_array())))
        {
            JSON_THROW(type_error::create(311, "cannot use emplace_back() with " + std::string(type_name()), *this));
        }

        // transform null object into an array
        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        // add element to array (perfect forwarding)
        const auto old_capacity = m_value.array->capacity();
        m_value.array->emplace_back(std::forward<Args>(args)...);
        return set_parent(m_value.array->back(), old_capacity);
    }

    /// @brief add an object to an object if key does not exist
    /// @sa https://json.nlohmann.me/api/basic_json/emplace/
    template<class... Args>
    std::pair<iterator, bool> emplace(Args&& ... args)
    {
        // emplace only works for null objects or arrays
        if (JSON_HEDLEY_UNLIKELY(!(is_null() || is_object())))
        {
            JSON_THROW(type_error::create(311, "cannot use emplace() with " + std::string(type_name()), *this));
        }

        // transform null object into an object
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        // add element to array (perfect forwarding)
        auto res = m_value.object->emplace(std::forward<Args>(args)...);
        set_parent(res.first->second);

        // create result iterator and set iterator to the result of emplace
        auto it = begin();
        it.m_it.object_iterator = res.first;

        // return pair of iterator and boolean
        return {it, res.second};
    }

    /// Helper for insertion of an iterator
    /// @note: This uses std::distance to support GCC 4.8,
    ///        see https://github.com/nlohmann/json/pull/1257
    template<typename... Args>
    iterator insert_iterator(const_iterator pos, Args&& ... args)
    {
        iterator result(this);
        JSON_ASSERT(m_value.array != nullptr);

        auto insert_pos = std::distance(m_value.array->begin(), pos.m_it.array_iterator);
        m_value.array->insert(pos.m_it.array_iterator, std::forward<Args>(args)...);
        result.m_it.array_iterator = m_value.array->begin() + insert_pos;

        // This could have been written as:
        // result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, cnt, val);
        // but the return value of insert is missing in GCC 4.8, so it is written this way instead.

        set_parents();
        return result;
    }

    /*!
    @brief inserts element

    Inserts element @a val before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] val element to insert
    @return iterator pointing to the inserted @a val.

    @throw type_error.309 if called on JSON values other than arrays;
    example: `"cannot use insert() with string"`
    @throw invalid_iterator.202 if @a pos is not an iterator of *this;
    example: `"iterator does not fit current value"`

    @complexity Constant plus linear in the distance between @a pos and end of
    the container.

    @liveexample{The example shows how `insert()` is used.,insert}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, const basic_json& val)
    {
        // insert only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            // check if iterator pos fits to this JSON value
            if (JSON_HEDLEY_UNLIKELY(pos.m_object != this))
            {
                JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value", *this));
            }

            // insert to array and return iterator
            return insert_iterator(pos, val);
        }

        JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name()), *this));
    }

    /*!
    @brief inserts element
    @copydoc insert(const_iterator, const basic_json&)
    */
    iterator insert(const_iterator pos, basic_json&& val)
    {
        return insert(pos, val);
    }

    /*!
    @brief inserts elements

    Inserts @a cnt copies of @a val before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] cnt number of copies of @a val to insert
    @param[in] val element to insert
    @return iterator pointing to the first element inserted, or @a pos if
    `cnt==0`

    @throw type_error.309 if called on JSON values other than arrays; example:
    `"cannot use insert() with string"`
    @throw invalid_iterator.202 if @a pos is not an iterator of *this;
    example: `"iterator does not fit current value"`

    @complexity Linear in @a cnt plus linear in the distance between @a pos
    and end of the container.

    @liveexample{The example shows how `insert()` is used.,insert__count}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, size_type cnt, const basic_json& val)
    {
        // insert only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            // check if iterator pos fits to this JSON value
            if (JSON_HEDLEY_UNLIKELY(pos.m_object != this))
            {
                JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value", *this));
            }

            // insert to array and return iterator
            return insert_iterator(pos, cnt, val);
        }

        JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name()), *this));
    }

    /*!
    @brief inserts elements

    Inserts elements from range `[first, last)` before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] first begin of the range of elements to insert
    @param[in] last end of the range of elements to insert

    @throw type_error.309 if called on JSON values other than arrays; example:
    `"cannot use insert() with string"`
    @throw invalid_iterator.202 if @a pos is not an iterator of *this;
    example: `"iterator does not fit current value"`
    @throw invalid_iterator.210 if @a first and @a last do not belong to the
    same JSON value; example: `"iterators do not fit"`
    @throw invalid_iterator.211 if @a first or @a last are iterators into
    container for which insert is called; example: `"passed iterators may not
    belong to container"`

    @return iterator pointing to the first element inserted, or @a pos if
    `first==last`

    @complexity Linear in `std::distance(first, last)` plus linear in the
    distance between @a pos and end of the container.

    @liveexample{The example shows how `insert()` is used.,insert__range}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, const_iterator first, const_iterator last)
    {
        // insert only works for arrays
        if (JSON_HEDLEY_UNLIKELY(!is_array()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name()), *this));
        }

        // check if iterator pos fits to this JSON value
        if (JSON_HEDLEY_UNLIKELY(pos.m_object != this))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value", *this));
        }

        // check if range iterators belong to the same JSON object
        if (JSON_HEDLEY_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit", *this));
        }

        if (JSON_HEDLEY_UNLIKELY(first.m_object == this))
        {
            JSON_THROW(invalid_iterator::create(211, "passed iterators may not belong to container", *this));
        }

        // insert to array and return iterator
        return insert_iterator(pos, first.m_it.array_iterator, last.m_it.array_iterator);
    }

    /*!
    @brief inserts elements

    Inserts elements from initializer list @a ilist before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] ilist initializer list to insert the values from

    @throw type_error.309 if called on JSON values other than arrays; example:
    `"cannot use insert() with string"`
    @throw invalid_iterator.202 if @a pos is not an iterator of *this;
    example: `"iterator does not fit current value"`

    @return iterator pointing to the first element inserted, or @a pos if
    `ilist` is empty

    @complexity Linear in `ilist.size()` plus linear in the distance between
    @a pos and end of the container.

    @liveexample{The example shows how `insert()` is used.,insert__ilist}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, initializer_list_t ilist)
    {
        // insert only works for arrays
        if (JSON_HEDLEY_UNLIKELY(!is_array()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name()), *this));
        }

        // check if iterator pos fits to this JSON value
        if (JSON_HEDLEY_UNLIKELY(pos.m_object != this))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value", *this));
        }

        // insert to array and return iterator
        return insert_iterator(pos, ilist.begin(), ilist.end());
    }

    /*!
    @brief inserts elements

    Inserts elements from range `[first, last)`.

    @param[in] first begin of the range of elements to insert
    @param[in] last end of the range of elements to insert

    @throw type_error.309 if called on JSON values other than objects; example:
    `"cannot use insert() with string"`
    @throw invalid_iterator.202 if iterator @a first or @a last does does not
    point to an object; example: `"iterators first and last must point to
    objects"`
    @throw invalid_iterator.210 if @a first and @a last do not belong to the
    same JSON value; example: `"iterators do not fit"`

    @complexity Logarithmic: `O(N*log(size() + N))`, where `N` is the number
    of elements to insert.

    @liveexample{The example shows how `insert()` is used.,insert__range_object}

    @since version 3.0.0
    */
    void insert(const_iterator first, const_iterator last)
    {
        // insert only works for objects
        if (JSON_HEDLEY_UNLIKELY(!is_object()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name()), *this));
        }

        // check if range iterators belong to the same JSON object
        if (JSON_HEDLEY_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit", *this));
        }

        // passed iterators must belong to objects
        if (JSON_HEDLEY_UNLIKELY(!first.m_object->is_object()))
        {
            JSON_THROW(invalid_iterator::create(202, "iterators first and last must point to objects", *this));
        }

        m_value.object->insert(first.m_it.object_iterator, last.m_it.object_iterator);
    }

    /*!
    @brief updates a JSON object from another object, overwriting existing keys

    Inserts all values from JSON object @a j and overwrites existing keys.

    @param[in] j  JSON object to read values from

    @throw type_error.312 if called on JSON values other than objects; example:
    `"cannot use update() with string"`

    @complexity O(N*log(size() + N)), where N is the number of elements to
                insert.

    @liveexample{The example shows how `update()` is used.,update}

    @sa https://docs.python.org/3.6/library/stdtypes.html#dict.update

    @since version 3.0.0
    */
    void update(const_reference j)
    {
        // implicitly convert null value to an empty object
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        if (JSON_HEDLEY_UNLIKELY(!is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(type_name()), *this));
        }
        if (JSON_HEDLEY_UNLIKELY(!j.is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(j.type_name()), *this));
        }

        for (auto it = j.cbegin(); it != j.cend(); ++it)
        {
            m_value.object->operator[](it.key()) = it.value();
#if JSON_DIAGNOSTICS
            m_value.object->operator[](it.key()).m_parent = this;
#endif
        }
    }

    /*!
    @brief updates a JSON object from another object, overwriting existing keys

    Inserts all values from from range `[first, last)` and overwrites existing
    keys.

    @param[in] first begin of the range of elements to insert
    @param[in] last end of the range of elements to insert

    @throw type_error.312 if called on JSON values other than objects; example:
    `"cannot use update() with string"`
    @throw invalid_iterator.202 if iterator @a first or @a last does does not
    point to an object; example: `"iterators first and last must point to
    objects"`
    @throw invalid_iterator.210 if @a first and @a last do not belong to the
    same JSON value; example: `"iterators do not fit"`

    @complexity O(N*log(size() + N)), where N is the number of elements to
                insert.

    @liveexample{The example shows how `update()` is used__range.,update}

    @sa https://docs.python.org/3.6/library/stdtypes.html#dict.update

    @since version 3.0.0
    */
    void update(const_iterator first, const_iterator last)
    {
        // implicitly convert null value to an empty object
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        if (JSON_HEDLEY_UNLIKELY(!is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(type_name()), *this));
        }

        // check if range iterators belong to the same JSON object
        if (JSON_HEDLEY_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit", *this));
        }

        // passed iterators must belong to objects
        if (JSON_HEDLEY_UNLIKELY(!first.m_object->is_object()
                                 || !last.m_object->is_object()))
        {
            JSON_THROW(invalid_iterator::create(202, "iterators first and last must point to objects", *this));
        }

        for (auto it = first; it != last; ++it)
        {
            m_value.object->operator[](it.key()) = it.value();
#if JSON_DIAGNOSTICS
            m_value.object->operator[](it.key()).m_parent = this;
#endif
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of the JSON value with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other JSON value to exchange the contents with

    @complexity Constant.

    @liveexample{The example below shows how JSON values can be swapped with
    `swap()`.,swap__reference}

    @since version 1.0.0
    */
    void swap(reference other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value&&
        std::is_nothrow_move_assignable<value_t>::value&&
        std::is_nothrow_move_constructible<json_value>::value&&
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        std::swap(m_type, other.m_type);
        std::swap(m_value, other.m_value);

        set_parents();
        other.set_parents();
        assert_invariant();
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of the JSON value from @a left with those of @a right. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated. implemented as a friend function callable via ADL.

    @param[in,out] left JSON value to exchange the contents with
    @param[in,out] right JSON value to exchange the contents with

    @complexity Constant.

    @liveexample{The example below shows how JSON values can be swapped with
    `swap()`.,swap__reference}

    @since version 1.0.0
    */
    friend void swap(reference left, reference right) noexcept (
        std::is_nothrow_move_constructible<value_t>::value&&
        std::is_nothrow_move_assignable<value_t>::value&&
        std::is_nothrow_move_constructible<json_value>::value&&
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        left.swap(right);
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON array with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other array to exchange the contents with

    @throw type_error.310 when JSON value is not an array; example: `"cannot
    use swap() with string"`

    @complexity Constant.

    @liveexample{The example below shows how arrays can be swapped with
    `swap()`.,swap__array_t}

    @since version 1.0.0
    */
    void swap(array_t& other) // NOLINT(bugprone-exception-escape)
    {
        // swap only works for arrays
        if (JSON_HEDLEY_LIKELY(is_array()))
        {
            std::swap(*(m_value.array), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON object with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other object to exchange the contents with

    @throw type_error.310 when JSON value is not an object; example:
    `"cannot use swap() with string"`

    @complexity Constant.

    @liveexample{The example below shows how objects can be swapped with
    `swap()`.,swap__object_t}

    @since version 1.0.0
    */
    void swap(object_t& other) // NOLINT(bugprone-exception-escape)
    {
        // swap only works for objects
        if (JSON_HEDLEY_LIKELY(is_object()))
        {
            std::swap(*(m_value.object), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON string with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other string to exchange the contents with

    @throw type_error.310 when JSON value is not a string; example: `"cannot
    use swap() with boolean"`

    @complexity Constant.

    @liveexample{The example below shows how strings can be swapped with
    `swap()`.,swap__string_t}

    @since version 1.0.0
    */
    void swap(string_t& other) // NOLINT(bugprone-exception-escape)
    {
        // swap only works for strings
        if (JSON_HEDLEY_LIKELY(is_string()))
        {
            std::swap(*(m_value.string), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name()), *this));
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON string with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other binary to exchange the contents with

    @throw type_error.310 when JSON value is not a string; example: `"cannot
    use swap() with boolean"`

    @complexity Constant.

    @liveexample{The example below shows how strings can be swapped with
    `swap()`.,swap__binary_t}

    @since version 3.8.0
    */
    void swap(binary_t& other) // NOLINT(bugprone-exception-escape)
    {
        // swap only works for strings
        if (JSON_HEDLEY_LIKELY(is_binary()))
        {
            std::swap(*(m_value.binary), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name()), *this));
        }
    }

    /// @copydoc swap(binary_t&)
    void swap(typename binary_t::container_type& other) // NOLINT(bugprone-exception-escape)
    {
        // swap only works for strings
        if (JSON_HEDLEY_LIKELY(is_binary()))
        {
            std::swap(*(m_value.binary), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name()), *this));
        }
    }

    /// @}

  public:
    //////////////////////////////////////////
    // lexicographical comparison operators //
    //////////////////////////////////////////

    /// @name lexicographical comparison operators
    /// @{

    /// @brief comparison: equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_eq/
    friend bool operator==(const_reference lhs, const_reference rhs) noexcept
    {
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
#endif
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                    return *lhs.m_value.array == *rhs.m_value.array;

                case value_t::object:
                    return *lhs.m_value.object == *rhs.m_value.object;

                case value_t::null:
                    return true;

                case value_t::string:
                    return *lhs.m_value.string == *rhs.m_value.string;

                case value_t::boolean:
                    return lhs.m_value.boolean == rhs.m_value.boolean;

                case value_t::number_integer:
                    return lhs.m_value.number_integer == rhs.m_value.number_integer;

                case value_t::number_unsigned:
                    return lhs.m_value.number_unsigned == rhs.m_value.number_unsigned;

                case value_t::number_float:
                    return lhs.m_value.number_float == rhs.m_value.number_float;

                case value_t::binary:
                    return *lhs.m_value.binary == *rhs.m_value.binary;

                case value_t::discarded:
                default:
                    return false;
            }
        }
        else if (lhs_type == value_t::number_integer && rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_integer) == rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float && rhs_type == value_t::number_integer)
        {
            return lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_unsigned && rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float && rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_unsigned && rhs_type == value_t::number_integer)
        {
            return static_cast<number_integer_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_integer;
        }
        else if (lhs_type == value_t::number_integer && rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_integer == static_cast<number_integer_t>(rhs.m_value.number_unsigned);
        }

        return false;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
    }

    /// @brief comparison: equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_eq/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator==(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs == basic_json(rhs);
    }

    /// @brief comparison: equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_eq/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator==(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) == rhs;
    }

    /// @brief comparison: not equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ne/
    friend bool operator!=(const_reference lhs, const_reference rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// @brief comparison: not equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ne/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator!=(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs != basic_json(rhs);
    }

    /// @brief comparison: not equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ne/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator!=(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) != rhs;
    }

    /// @brief comparison: less than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_lt/
    friend bool operator<(const_reference lhs, const_reference rhs) noexcept
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                    // note parentheses are necessary, see
                    // https://github.com/nlohmann/json/issues/1530
                    return (*lhs.m_value.array) < (*rhs.m_value.array);

                case value_t::object:
                    return (*lhs.m_value.object) < (*rhs.m_value.object);

                case value_t::null:
                    return false;

                case value_t::string:
                    return (*lhs.m_value.string) < (*rhs.m_value.string);

                case value_t::boolean:
                    return (lhs.m_value.boolean) < (rhs.m_value.boolean);

                case value_t::number_integer:
                    return (lhs.m_value.number_integer) < (rhs.m_value.number_integer);

                case value_t::number_unsigned:
                    return (lhs.m_value.number_unsigned) < (rhs.m_value.number_unsigned);

                case value_t::number_float:
                    return (lhs.m_value.number_float) < (rhs.m_value.number_float);

                case value_t::binary:
                    return (*lhs.m_value.binary) < (*rhs.m_value.binary);

                case value_t::discarded:
                default:
                    return false;
            }
        }
        else if (lhs_type == value_t::number_integer && rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float && rhs_type == value_t::number_integer)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_unsigned && rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float && rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_integer && rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_integer < static_cast<number_integer_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_unsigned && rhs_type == value_t::number_integer)
        {
            return static_cast<number_integer_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_integer;
        }

        // We only reach this line if we cannot compare values. In that case,
        // we compare types. Note we have to call the operator explicitly,
        // because MSVC has problems otherwise.
        return operator<(lhs_type, rhs_type);
    }

    /// @brief comparison: less than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_lt/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs < basic_json(rhs);
    }

    /// @brief comparison: less than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_lt/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) < rhs;
    }

    /// @brief comparison: less than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_le/
    friend bool operator<=(const_reference lhs, const_reference rhs) noexcept
    {
        return !(rhs < lhs);
    }

    /// @brief comparison: less than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_le/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<=(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs <= basic_json(rhs);
    }

    /// @brief comparison: less than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_le/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<=(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) <= rhs;
    }

    /// @brief comparison: greater than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_gt/
    friend bool operator>(const_reference lhs, const_reference rhs) noexcept
    {
        return !(lhs <= rhs);
    }

    /// @brief comparison: greater than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_gt/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs > basic_json(rhs);
    }

    /// @brief comparison: greater than
    /// @sa https://json.nlohmann.me/api/basic_json/operator_gt/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) > rhs;
    }

    /// @brief comparison: greater than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ge/
    friend bool operator>=(const_reference lhs, const_reference rhs) noexcept
    {
        return !(lhs < rhs);
    }

    /// @brief comparison: greater than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ge/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>=(const_reference lhs, ScalarType rhs) noexcept
    {
        return lhs >= basic_json(rhs);
    }

    /// @brief comparison: greater than or equal
    /// @sa https://json.nlohmann.me/api/basic_json/operator_ge/
    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>=(ScalarType lhs, const_reference rhs) noexcept
    {
        return basic_json(lhs) >= rhs;
    }

    /// @}

    ///////////////////
    // serialization //
    ///////////////////

    /// @name serialization
    /// @{
#ifndef JSON_NO_IO
    /*!
    @brief serialize to stream

    Serialize the given JSON value @a j to the output stream @a o. The JSON
    value will be serialized using the @ref dump member function.

    - The indentation of the output can be controlled with the member variable
      `width` of the output stream @a o. For instance, using the manipulator
      `std::setw(4)` on @a o sets the indentation level to `4` and the
      serialization result is the same as calling `dump(4)`.

    - The indentation character can be controlled with the member variable
      `fill` of the output stream @a o. For instance, the manipulator
      `std::setfill('\\t')` sets indentation to use a tab character rather than
      the default space character.

    @param[in,out] o  stream to serialize to
    @param[in] j  JSON value to serialize

    @return the stream @a o

    @throw type_error.316 if a string stored inside the JSON value is not
                          UTF-8 encoded

    @complexity Linear.

    @liveexample{The example below shows the serialization with different
    parameters to `width` to adjust the indentation level.,operator_serialize}

    @since version 1.0.0; indentation character added in version 3.0.0
    */
    friend std::ostream& operator<<(std::ostream& o, const basic_json& j)
    {
        // read width member and use it as indentation parameter if nonzero
        const bool pretty_print = o.width() > 0;
        const auto indentation = pretty_print ? o.width() : 0;

        // reset width to 0 for subsequent calls to this stream
        o.width(0);

        // do the actual serialization
        serializer s(detail::output_adapter<char>(o), o.fill());
        s.dump(j, pretty_print, false, static_cast<unsigned int>(indentation));
        return o;
    }

    /*!
    @brief serialize to stream
    @deprecated This stream operator is deprecated and will be removed in
                future 4.0.0 of the library. Please use
                @ref operator<<(std::ostream&, const basic_json&)
                instead; that is, replace calls like `j >> o;` with `o << j;`.
    @since version 1.0.0; deprecated since version 3.0.0
    */
    JSON_HEDLEY_DEPRECATED_FOR(3.0.0, operator<<(std::ostream&, const basic_json&))
    friend std::ostream& operator>>(const basic_json& j, std::ostream& o)
    {
        return o << j;
    }
#endif  // JSON_NO_IO
    /// @}


    /////////////////////
    // deserialization //
    /////////////////////

    /// @name deserialization
    /// @{

    /*!
    @brief deserialize from a compatible input

    @tparam InputType A compatible input, for instance
    - an std::istream object
    - a FILE pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object obj for which begin(obj) and end(obj) produces a valid pair of
      iterators.

    @param[in] i  input to read from
    @param[in] cb  a parser callback function of type @ref parser_callback_t
    which is used to control the deserialization by filtering unwanted values
    (optional)
    @param[in] allow_exceptions  whether to throw exceptions in case of a
    parse error (optional, true by default)
    @param[in] ignore_comments  whether comments should be ignored and treated
    like whitespace (true) or yield a parse error (true); (optional, false by
    default)

    @return deserialized JSON value; in case of a parse error and
            @a allow_exceptions set to `false`, the return value will be
            value_t::discarded.

    @throw parse_error.101 if a parse error occurs; example: `""unexpected end
    of input; expected string literal""`
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser. The complexity can be higher if the parser callback function
    @a cb or reading from the input @a i has a super-linear complexity.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates the `parse()` function reading
    from an array.,parse__array__parser_callback_t}

    @liveexample{The example below demonstrates the `parse()` function with
    and without callback function.,parse__string__parser_callback_t}

    @liveexample{The example below demonstrates the `parse()` function with
    and without callback function.,parse__istream__parser_callback_t}

    @liveexample{The example below demonstrates the `parse()` function reading
    from a contiguous container.,parse__contiguouscontainer__parser_callback_t}

    @since version 2.0.3 (contiguous containers); version 3.9.0 allowed to
    ignore comments.
    */
    template<typename InputType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json parse(InputType&& i,
                            const parser_callback_t cb = nullptr,
                            const bool allow_exceptions = true,
                            const bool ignore_comments = false)
    {
        basic_json result;
        parser(detail::input_adapter(std::forward<InputType>(i)), cb, allow_exceptions, ignore_comments).parse(true, result);
        return result;
    }

    /*!
    @brief deserialize from a pair of character iterators

    The value_type of the iterator must be a integral type with size of 1, 2 or
    4 bytes, which will be interpreted respectively as UTF-8, UTF-16 and UTF-32.

    @param[in] first iterator to start of character range
    @param[in] last  iterator to end of character range
    @param[in] cb  a parser callback function of type @ref parser_callback_t
    which is used to control the deserialization by filtering unwanted values
    (optional)
    @param[in] allow_exceptions  whether to throw exceptions in case of a
    parse error (optional, true by default)
    @param[in] ignore_comments  whether comments should be ignored and treated
    like whitespace (true) or yield a parse error (true); (optional, false by
    default)

    @return deserialized JSON value; in case of a parse error and
            @a allow_exceptions set to `false`, the return value will be
            value_t::discarded.

    @throw parse_error.101 if a parse error occurs; example: `""unexpected end
    of input; expected string literal""`
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails
    */
    template<typename IteratorType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json parse(IteratorType first,
                            IteratorType last,
                            const parser_callback_t cb = nullptr,
                            const bool allow_exceptions = true,
                            const bool ignore_comments = false)
    {
        basic_json result;
        parser(detail::input_adapter(std::move(first), std::move(last)), cb, allow_exceptions, ignore_comments).parse(true, result);
        return result;
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, parse(ptr, ptr + len))
    static basic_json parse(detail::span_input_adapter&& i,
                            const parser_callback_t cb = nullptr,
                            const bool allow_exceptions = true,
                            const bool ignore_comments = false)
    {
        basic_json result;
        parser(i.get(), cb, allow_exceptions, ignore_comments).parse(true, result);
        return result;
    }

    /*!
    @brief check if the input is valid JSON

    Unlike the @ref parse(InputType&&, const parser_callback_t,const bool)
    function, this function neither throws an exception in case of invalid JSON
    input (i.e., a parse error) nor creates diagnostic information.

    @tparam InputType A compatible input, for instance
    - an std::istream object
    - a FILE pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object obj for which begin(obj) and end(obj) produces a valid pair of
      iterators.

    @param[in] i input to read from
    @param[in] ignore_comments  whether comments should be ignored and treated
    like whitespace (true) or yield a parse error (true); (optional, false by
    default)

    @return Whether the input read from @a i is valid JSON.

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates the `accept()` function reading
    from a string.,accept__string}
    */
    template<typename InputType>
    static bool accept(InputType&& i,
                       const bool ignore_comments = false)
    {
        return parser(detail::input_adapter(std::forward<InputType>(i)), nullptr, false, ignore_comments).accept(true);
    }

    template<typename IteratorType>
    static bool accept(IteratorType first, IteratorType last,
                       const bool ignore_comments = false)
    {
        return parser(detail::input_adapter(std::move(first), std::move(last)), nullptr, false, ignore_comments).accept(true);
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, accept(ptr, ptr + len))
    static bool accept(detail::span_input_adapter&& i,
                       const bool ignore_comments = false)
    {
        return parser(i.get(), nullptr, false, ignore_comments).accept(true);
    }

    /*!
    @brief generate SAX events

    The SAX event lister must follow the interface of @ref json_sax.

    This function reads from a compatible input. Examples are:
    - an std::istream object
    - a FILE pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object obj for which begin(obj) and end(obj) produces a valid pair of
      iterators.

    @param[in] i  input to read from
    @param[in,out] sax  SAX event listener
    @param[in] format  the format to parse (JSON, CBOR, MessagePack, or UBJSON)
    @param[in] strict  whether the input has to be consumed completely
    @param[in] ignore_comments  whether comments should be ignored and treated
    like whitespace (true) or yield a parse error (true); (optional, false by
    default); only applies to the JSON file format.

    @return return value of the last processed SAX event

    @throw parse_error.101 if a parse error occurs; example: `""unexpected end
    of input; expected string literal""`
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser. The complexity can be higher if the SAX consumer @a sax has
    a super-linear complexity.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates the `sax_parse()` function
    reading from string and processing the events with a user-defined SAX
    event consumer.,sax_parse}

    @since version 3.2.0
    */
    template <typename InputType, typename SAX>
    JSON_HEDLEY_NON_NULL(2)
    static bool sax_parse(InputType&& i, SAX* sax,
                          input_format_t format = input_format_t::json,
                          const bool strict = true,
                          const bool ignore_comments = false)
    {
        auto ia = detail::input_adapter(std::forward<InputType>(i));
        return format == input_format_t::json
               ? parser(std::move(ia), nullptr, true, ignore_comments).sax_parse(sax, strict)
               : detail::binary_reader<basic_json, decltype(ia), SAX>(std::move(ia)).sax_parse(format, sax, strict);
    }

    template<class IteratorType, class SAX>
    JSON_HEDLEY_NON_NULL(3)
    static bool sax_parse(IteratorType first, IteratorType last, SAX* sax,
                          input_format_t format = input_format_t::json,
                          const bool strict = true,
                          const bool ignore_comments = false)
    {
        auto ia = detail::input_adapter(std::move(first), std::move(last));
        return format == input_format_t::json
               ? parser(std::move(ia), nullptr, true, ignore_comments).sax_parse(sax, strict)
               : detail::binary_reader<basic_json, decltype(ia), SAX>(std::move(ia)).sax_parse(format, sax, strict);
    }

    template <typename SAX>
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, sax_parse(ptr, ptr + len, ...))
    JSON_HEDLEY_NON_NULL(2)
    static bool sax_parse(detail::span_input_adapter&& i, SAX* sax,
                          input_format_t format = input_format_t::json,
                          const bool strict = true,
                          const bool ignore_comments = false)
    {
        auto ia = i.get();
        return format == input_format_t::json
               // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
               ? parser(std::move(ia), nullptr, true, ignore_comments).sax_parse(sax, strict)
               // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
               : detail::binary_reader<basic_json, decltype(ia), SAX>(std::move(ia)).sax_parse(format, sax, strict);
    }
#ifndef JSON_NO_IO
    /*!
    @brief deserialize from stream
    @deprecated This stream operator is deprecated and will be removed in
                version 4.0.0 of the library. Please use
                @ref operator>>(std::istream&, basic_json&)
                instead; that is, replace calls like `j << i;` with `i >> j;`.
    @since version 1.0.0; deprecated since version 3.0.0
    */
    JSON_HEDLEY_DEPRECATED_FOR(3.0.0, operator>>(std::istream&, basic_json&))
    friend std::istream& operator<<(basic_json& j, std::istream& i)
    {
        return operator>>(i, j);
    }

    /*!
    @brief deserialize from stream

    Deserializes an input stream to a JSON value.

    @param[in,out] i  input stream to read a serialized JSON value from
    @param[in,out] j  JSON value to write the deserialized input to

    @throw parse_error.101 in case of an unexpected token
    @throw parse_error.102 if to_unicode fails or surrogate error
    @throw parse_error.103 if to_unicode fails

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below shows how a JSON value is constructed by
    reading a serialization from a stream.,operator_deserialize}

    @sa parse(std::istream&, const parser_callback_t) for a variant with a
    parser callback function to filter values while parsing

    @since version 1.0.0
    */
    friend std::istream& operator>>(std::istream& i, basic_json& j)
    {
        parser(detail::input_adapter(i)).parse(false, j);
        return i;
    }
#endif  // JSON_NO_IO
    /// @}

    ///////////////////////////
    // convenience functions //
    ///////////////////////////

    /*!
    @brief return the type as string

    Returns the type name as string to be used in error messages - usually to
    indicate that a function was called on a wrong JSON type.

    @return a string representation of a the @a m_type member:
            Value type  | return value
            ----------- | -------------
            null        | `"null"`
            boolean     | `"boolean"`
            string      | `"string"`
            number      | `"number"` (for all number types)
            object      | `"object"`
            array       | `"array"`
            binary      | `"binary"`
            discarded   | `"discarded"`

    @exceptionsafety No-throw guarantee: this function never throws exceptions.

    @complexity Constant.

    @liveexample{The following code exemplifies `type_name()` for all JSON
    types.,type_name}

    @sa see @ref type() -- return the type of the JSON value
    @sa see @ref operator value_t() -- return the type of the JSON value (implicit)

    @since version 1.0.0, public since 2.1.0, `const char*` and `noexcept`
    since 3.0.0
    */
    JSON_HEDLEY_RETURNS_NON_NULL
    const char* type_name() const noexcept
    {
        {
            switch (m_type)
            {
                case value_t::null:
                    return "null";
                case value_t::object:
                    return "object";
                case value_t::array:
                    return "array";
                case value_t::string:
                    return "string";
                case value_t::boolean:
                    return "boolean";
                case value_t::binary:
                    return "binary";
                case value_t::discarded:
                    return "discarded";
                case value_t::number_integer:
                case value_t::number_unsigned:
                case value_t::number_float:
                default:
                    return "number";
            }
        }
    }


  JSON_PRIVATE_UNLESS_TESTED:
    //////////////////////
    // member variables //
    //////////////////////

    /// the type of the current element
    value_t m_type = value_t::null;

    /// the value of the current element
    json_value m_value = {};

#if JSON_DIAGNOSTICS
    /// a pointer to a parent value (for debugging purposes)
    basic_json* m_parent = nullptr;
#endif

    //////////////////////////////////////////
    // binary serialization/deserialization //
    //////////////////////////////////////////

    /// @name binary serialization/deserialization support
    /// @{

  public:
    /*!
    @brief create a CBOR serialization of a given JSON value

    Serializes a given JSON value @a j to a byte vector using the CBOR (Concise
    Binary Object Representation) serialization format. CBOR is a binary
    serialization format which aims to be more compact than JSON itself, yet
    more efficient to parse.

    The library uses the following mapping from JSON values types to
    CBOR types according to the CBOR specification (RFC 7049):

    JSON value type | value/range                                | CBOR type                          | first byte
    --------------- | ------------------------------------------ | ---------------------------------- | ---------------
    null            | `null`                                     | Null                               | 0xF6
    boolean         | `true`                                     | True                               | 0xF5
    boolean         | `false`                                    | False                              | 0xF4
    number_integer  | -9223372036854775808..-2147483649          | Negative integer (8 bytes follow)  | 0x3B
    number_integer  | -2147483648..-32769                        | Negative integer (4 bytes follow)  | 0x3A
    number_integer  | -32768..-129                               | Negative integer (2 bytes follow)  | 0x39
    number_integer  | -128..-25                                  | Negative integer (1 byte follow)   | 0x38
    number_integer  | -24..-1                                    | Negative integer                   | 0x20..0x37
    number_integer  | 0..23                                      | Integer                            | 0x00..0x17
    number_integer  | 24..255                                    | Unsigned integer (1 byte follow)   | 0x18
    number_integer  | 256..65535                                 | Unsigned integer (2 bytes follow)  | 0x19
    number_integer  | 65536..4294967295                          | Unsigned integer (4 bytes follow)  | 0x1A
    number_integer  | 4294967296..18446744073709551615           | Unsigned integer (8 bytes follow)  | 0x1B
    number_unsigned | 0..23                                      | Integer                            | 0x00..0x17
    number_unsigned | 24..255                                    | Unsigned integer (1 byte follow)   | 0x18
    number_unsigned | 256..65535                                 | Unsigned integer (2 bytes follow)  | 0x19
    number_unsigned | 65536..4294967295                          | Unsigned integer (4 bytes follow)  | 0x1A
    number_unsigned | 4294967296..18446744073709551615           | Unsigned integer (8 bytes follow)  | 0x1B
    number_float    | *any value representable by a float*       | Single-Precision Float             | 0xFA
    number_float    | *any value NOT representable by a float*   | Double-Precision Float             | 0xFB
    string          | *length*: 0..23                            | UTF-8 string                       | 0x60..0x77
    string          | *length*: 23..255                          | UTF-8 string (1 byte follow)       | 0x78
    string          | *length*: 256..65535                       | UTF-8 string (2 bytes follow)      | 0x79
    string          | *length*: 65536..4294967295                | UTF-8 string (4 bytes follow)      | 0x7A
    string          | *length*: 4294967296..18446744073709551615 | UTF-8 string (8 bytes follow)      | 0x7B
    array           | *size*: 0..23                              | array                              | 0x80..0x97
    array           | *size*: 23..255                            | array (1 byte follow)              | 0x98
    array           | *size*: 256..65535                         | array (2 bytes follow)             | 0x99
    array           | *size*: 65536..4294967295                  | array (4 bytes follow)             | 0x9A
    array           | *size*: 4294967296..18446744073709551615   | array (8 bytes follow)             | 0x9B
    object          | *size*: 0..23                              | map                                | 0xA0..0xB7
    object          | *size*: 23..255                            | map (1 byte follow)                | 0xB8
    object          | *size*: 256..65535                         | map (2 bytes follow)               | 0xB9
    object          | *size*: 65536..4294967295                  | map (4 bytes follow)               | 0xBA
    object          | *size*: 4294967296..18446744073709551615   | map (8 bytes follow)               | 0xBB
    binary          | *size*: 0..23                              | byte string                        | 0x40..0x57
    binary          | *size*: 23..255                            | byte string (1 byte follow)        | 0x58
    binary          | *size*: 256..65535                         | byte string (2 bytes follow)       | 0x59
    binary          | *size*: 65536..4294967295                  | byte string (4 bytes follow)       | 0x5A
    binary          | *size*: 4294967296..18446744073709551615   | byte string (8 bytes follow)       | 0x5B

    Binary values with subtype are mapped to tagged values (0xD8..0xDB)
    depending on the subtype, followed by a byte string, see "binary" cells
    in the table above.

    @note The mapping is **complete** in the sense that any JSON value type
          can be converted to a CBOR value.

    @note If NaN or Infinity are stored inside a JSON number, they are
          serialized properly. This behavior differs from the @ref dump()
          function which serializes NaN or Infinity to `null`.

    @note The following CBOR types are not used in the conversion:
          - UTF-8 strings terminated by "break" (0x7F)
          - arrays terminated by "break" (0x9F)
          - maps terminated by "break" (0xBF)
          - byte strings terminated by "break" (0x5F)
          - date/time (0xC0..0xC1)
          - bignum (0xC2..0xC3)
          - decimal fraction (0xC4)
          - bigfloat (0xC5)
          - expected conversions (0xD5..0xD7)
          - simple values (0xE0..0xF3, 0xF8)
          - undefined (0xF7)
          - half-precision floats (0xF9)
          - break (0xFF)

    @param[in] j  JSON value to serialize
    @return CBOR serialization as byte vector

    @complexity Linear in the size of the JSON value @a j.

    @liveexample{The example shows the serialization of a JSON value to a byte
    vector in CBOR format.,to_cbor}

    @sa http://cbor.io
    @sa see @ref from_cbor(InputType&&, const bool, const bool, const cbor_tag_handler_t) for the
        analogous deserialization
    @sa see @ref to_msgpack(const basic_json&) for the related MessagePack format
    @sa see @ref to_ubjson(const basic_json&, const bool, const bool) for the
             related UBJSON format

    @since version 2.0.9; compact representation of floating-point numbers
           since version 3.8.0
    */
    static std::vector<std::uint8_t> to_cbor(const basic_json& j)
    {
        std::vector<std::uint8_t> result;
        to_cbor(j, result);
        return result;
    }

    static void to_cbor(const basic_json& j, detail::output_adapter<std::uint8_t> o)
    {
        binary_writer<std::uint8_t>(o).write_cbor(j);
    }

    static void to_cbor(const basic_json& j, detail::output_adapter<char> o)
    {
        binary_writer<char>(o).write_cbor(j);
    }

    /*!
    @brief create a MessagePack serialization of a given JSON value

    Serializes a given JSON value @a j to a byte vector using the MessagePack
    serialization format. MessagePack is a binary serialization format which
    aims to be more compact than JSON itself, yet more efficient to parse.

    The library uses the following mapping from JSON values types to
    MessagePack types according to the MessagePack specification:

    JSON value type | value/range                       | MessagePack type | first byte
    --------------- | --------------------------------- | ---------------- | ----------
    null            | `null`                            | nil              | 0xC0
    boolean         | `true`                            | true             | 0xC3
    boolean         | `false`                           | false            | 0xC2
    number_integer  | -9223372036854775808..-2147483649 | int64            | 0xD3
    number_integer  | -2147483648..-32769               | int32            | 0xD2
    number_integer  | -32768..-129                      | int16            | 0xD1
    number_integer  | -128..-33                         | int8             | 0xD0
    number_integer  | -32..-1                           | negative fixint  | 0xE0..0xFF
    number_integer  | 0..127                            | positive fixint  | 0x00..0x7F
    number_integer  | 128..255                          | uint 8           | 0xCC
    number_integer  | 256..65535                        | uint 16          | 0xCD
    number_integer  | 65536..4294967295                 | uint 32          | 0xCE
    number_integer  | 4294967296..18446744073709551615  | uint 64          | 0xCF
    number_unsigned | 0..127                            | positive fixint  | 0x00..0x7F
    number_unsigned | 128..255                          | uint 8           | 0xCC
    number_unsigned | 256..65535                        | uint 16          | 0xCD
    number_unsigned | 65536..4294967295                 | uint 32          | 0xCE
    number_unsigned | 4294967296..18446744073709551615  | uint 64          | 0xCF
    number_float    | *any value representable by a float*     | float 32 | 0xCA
    number_float    | *any value NOT representable by a float* | float 64 | 0xCB
    string          | *length*: 0..31                   | fixstr           | 0xA0..0xBF
    string          | *length*: 32..255                 | str 8            | 0xD9
    string          | *length*: 256..65535              | str 16           | 0xDA
    string          | *length*: 65536..4294967295       | str 32           | 0xDB
    array           | *size*: 0..15                     | fixarray         | 0x90..0x9F
    array           | *size*: 16..65535                 | array 16         | 0xDC
    array           | *size*: 65536..4294967295         | array 32         | 0xDD
    object          | *size*: 0..15                     | fix map          | 0x80..0x8F
    object          | *size*: 16..65535                 | map 16           | 0xDE
    object          | *size*: 65536..4294967295         | map 32           | 0xDF
    binary          | *size*: 0..255                    | bin 8            | 0xC4
    binary          | *size*: 256..65535                | bin 16           | 0xC5
    binary          | *size*: 65536..4294967295         | bin 32           | 0xC6

    @note The mapping is **complete** in the sense that any JSON value type
          can be converted to a MessagePack value.

    @note The following values can **not** be converted to a MessagePack value:
          - strings with more than 4294967295 bytes
          - byte strings with more than 4294967295 bytes
          - arrays with more than 4294967295 elements
          - objects with more than 4294967295 elements

    @note Any MessagePack output created @ref to_msgpack can be successfully
          parsed by @ref from_msgpack.

    @note If NaN or Infinity are stored inside a JSON number, they are
          serialized properly. This behavior differs from the @ref dump()
          function which serializes NaN or Infinity to `null`.

    @param[in] j  JSON value to serialize
    @return MessagePack serialization as byte vector

    @complexity Linear in the size of the JSON value @a j.

    @liveexample{The example shows the serialization of a JSON value to a byte
    vector in MessagePack format.,to_msgpack}

    @sa http://msgpack.org
    @sa see @ref from_msgpack for the analogous deserialization
    @sa see @ref to_cbor(const basic_json& for the related CBOR format
    @sa see @ref to_ubjson(const basic_json&, const bool, const bool) for the
             related UBJSON format

    @since version 2.0.9
    */
    static std::vector<std::uint8_t> to_msgpack(const basic_json& j)
    {
        std::vector<std::uint8_t> result;
        to_msgpack(j, result);
        return result;
    }

    static void to_msgpack(const basic_json& j, detail::output_adapter<std::uint8_t> o)
    {
        binary_writer<std::uint8_t>(o).write_msgpack(j);
    }

    static void to_msgpack(const basic_json& j, detail::output_adapter<char> o)
    {
        binary_writer<char>(o).write_msgpack(j);
    }

    /*!
    @brief create a UBJSON serialization of a given JSON value

    Serializes a given JSON value @a j to a byte vector using the UBJSON
    (Universal Binary JSON) serialization format. UBJSON aims to be more compact
    than JSON itself, yet more efficient to parse.

    The library uses the following mapping from JSON values types to
    UBJSON types according to the UBJSON specification:

    JSON value type | value/range                       | UBJSON type | marker
    --------------- | --------------------------------- | ----------- | ------
    null            | `null`                            | null        | `Z`
    boolean         | `true`                            | true        | `T`
    boolean         | `false`                           | false       | `F`
    number_integer  | -9223372036854775808..-2147483649 | int64       | `L`
    number_integer  | -2147483648..-32769               | int32       | `l`
    number_integer  | -32768..-129                      | int16       | `I`
    number_integer  | -128..127                         | int8        | `i`
    number_integer  | 128..255                          | uint8       | `U`
    number_integer  | 256..32767                        | int16       | `I`
    number_integer  | 32768..2147483647                 | int32       | `l`
    number_integer  | 2147483648..9223372036854775807   | int64       | `L`
    number_unsigned | 0..127                            | int8        | `i`
    number_unsigned | 128..255                          | uint8       | `U`
    number_unsigned | 256..32767                        | int16       | `I`
    number_unsigned | 32768..2147483647                 | int32       | `l`
    number_unsigned | 2147483648..9223372036854775807   | int64       | `L`
    number_unsigned | 2147483649..18446744073709551615  | high-precision | `H`
    number_float    | *any value*                       | float64     | `D`
    string          | *with shortest length indicator*  | string      | `S`
    array           | *see notes on optimized format*   | array       | `[`
    object          | *see notes on optimized format*   | map         | `{`

    @note The mapping is **complete** in the sense that any JSON value type
          can be converted to a UBJSON value.

    @note The following values can **not** be converted to a UBJSON value:
          - strings with more than 9223372036854775807 bytes (theoretical)

    @note The following markers are not used in the conversion:
          - `Z`: no-op values are not created.
          - `C`: single-byte strings are serialized with `S` markers.

    @note Any UBJSON output created @ref to_ubjson can be successfully parsed
          by @ref from_ubjson.

    @note If NaN or Infinity are stored inside a JSON number, they are
          serialized properly. This behavior differs from the @ref dump()
          function which serializes NaN or Infinity to `null`.

    @note The optimized formats for containers are supported: Parameter
          @a use_size adds size information to the beginning of a container and
          removes the closing marker. Parameter @a use_type further checks
          whether all elements of a container have the same type and adds the
          type marker to the beginning of the container. The @a use_type
          parameter must only be used together with @a use_size = true. Note
          that @a use_size = true alone may result in larger representations -
          the benefit of this parameter is that the receiving side is
          immediately informed on the number of elements of the container.

    @note If the JSON data contains the binary type, the value stored is a list
          of integers, as suggested by the UBJSON documentation.  In particular,
          this means that serialization and the deserialization of a JSON
          containing binary values into UBJSON and back will result in a
          different JSON object.

    @param[in] j  JSON value to serialize
    @param[in] use_size  whether to add size annotations to container types
    @param[in] use_type  whether to add type annotations to container types
                         (must be combined with @a use_size = true)
    @return UBJSON serialization as byte vector

    @complexity Linear in the size of the JSON value @a j.

    @liveexample{The example shows the serialization of a JSON value to a byte
    vector in UBJSON format.,to_ubjson}

    @sa http://ubjson.org
    @sa see @ref from_ubjson(InputType&&, const bool, const bool) for the
        analogous deserialization
    @sa see @ref to_cbor(const basic_json& for the related CBOR format
    @sa see @ref to_msgpack(const basic_json&) for the related MessagePack format

    @since version 3.1.0
    */
    static std::vector<std::uint8_t> to_ubjson(const basic_json& j,
            const bool use_size = false,
            const bool use_type = false)
    {
        std::vector<std::uint8_t> result;
        to_ubjson(j, result, use_size, use_type);
        return result;
    }

    static void to_ubjson(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                          const bool use_size = false, const bool use_type = false)
    {
        binary_writer<std::uint8_t>(o).write_ubjson(j, use_size, use_type);
    }

    static void to_ubjson(const basic_json& j, detail::output_adapter<char> o,
                          const bool use_size = false, const bool use_type = false)
    {
        binary_writer<char>(o).write_ubjson(j, use_size, use_type);
    }


    /*!
    @brief Serializes the given JSON object `j` to BSON and returns a vector
           containing the corresponding BSON-representation.

    BSON (Binary JSON) is a binary format in which zero or more ordered key/value pairs are
    stored as a single entity (a so-called document).

    The library uses the following mapping from JSON values types to BSON types:

    JSON value type | value/range                       | BSON type   | marker
    --------------- | --------------------------------- | ----------- | ------
    null            | `null`                            | null        | 0x0A
    boolean         | `true`, `false`                   | boolean     | 0x08
    number_integer  | -9223372036854775808..-2147483649 | int64       | 0x12
    number_integer  | -2147483648..2147483647           | int32       | 0x10
    number_integer  | 2147483648..9223372036854775807   | int64       | 0x12
    number_unsigned | 0..2147483647                     | int32       | 0x10
    number_unsigned | 2147483648..9223372036854775807   | int64       | 0x12
    number_unsigned | 9223372036854775808..18446744073709551615| --   | --
    number_float    | *any value*                       | double      | 0x01
    string          | *any value*                       | string      | 0x02
    array           | *any value*                       | document    | 0x04
    object          | *any value*                       | document    | 0x03
    binary          | *any value*                       | binary      | 0x05

    @warning The mapping is **incomplete**, since only JSON-objects (and things
    contained therein) can be serialized to BSON.
    Also, integers larger than 9223372036854775807 cannot be serialized to BSON,
    and the keys may not contain U+0000, since they are serialized a
    zero-terminated c-strings.

    @throw out_of_range.407  if `j.is_number_unsigned() && j.get<std::uint64_t>() > 9223372036854775807`
    @throw out_of_range.409  if a key in `j` contains a NULL (U+0000)
    @throw type_error.317    if `!j.is_object()`

    @pre The input `j` is required to be an object: `j.is_object() == true`.

    @note Any BSON output created via @ref to_bson can be successfully parsed
          by @ref from_bson.

    @param[in] j  JSON value to serialize
    @return BSON serialization as byte vector

    @complexity Linear in the size of the JSON value @a j.

    @liveexample{The example shows the serialization of a JSON value to a byte
    vector in BSON format.,to_bson}

    @sa http://bsonspec.org/spec.html
    @sa see @ref from_bson(detail::input_adapter&&, const bool strict) for the
        analogous deserialization
    @sa see @ref to_ubjson(const basic_json&, const bool, const bool) for the
             related UBJSON format
    @sa see @ref to_cbor(const basic_json&) for the related CBOR format
    @sa see @ref to_msgpack(const basic_json&) for the related MessagePack format
    */
    static std::vector<std::uint8_t> to_bson(const basic_json& j)
    {
        std::vector<std::uint8_t> result;
        to_bson(j, result);
        return result;
    }

    /*!
    @brief Serializes the given JSON object `j` to BSON and forwards the
           corresponding BSON-representation to the given output_adapter `o`.
    @param j The JSON object to convert to BSON.
    @param o The output adapter that receives the binary BSON representation.
    @pre The input `j` shall be an object: `j.is_object() == true`
    @sa see @ref to_bson(const basic_json&)
    */
    static void to_bson(const basic_json& j, detail::output_adapter<std::uint8_t> o)
    {
        binary_writer<std::uint8_t>(o).write_bson(j);
    }

    /*!
    @copydoc to_bson(const basic_json&, detail::output_adapter<std::uint8_t>)
    */
    static void to_bson(const basic_json& j, detail::output_adapter<char> o)
    {
        binary_writer<char>(o).write_bson(j);
    }


    /*!
    @brief create a JSON value from an input in CBOR format

    Deserializes a given input @a i to a JSON value using the CBOR (Concise
    Binary Object Representation) serialization format.

    The library maps CBOR types to JSON value types as follows:

    CBOR type              | JSON value type | first byte
    ---------------------- | --------------- | ----------
    Integer                | number_unsigned | 0x00..0x17
    Unsigned integer       | number_unsigned | 0x18
    Unsigned integer       | number_unsigned | 0x19
    Unsigned integer       | number_unsigned | 0x1A
    Unsigned integer       | number_unsigned | 0x1B
    Negative integer       | number_integer  | 0x20..0x37
    Negative integer       | number_integer  | 0x38
    Negative integer       | number_integer  | 0x39
    Negative integer       | number_integer  | 0x3A
    Negative integer       | number_integer  | 0x3B
    Byte string            | binary          | 0x40..0x57
    Byte string            | binary          | 0x58
    Byte string            | binary          | 0x59
    Byte string            | binary          | 0x5A
    Byte string            | binary          | 0x5B
    UTF-8 string           | string          | 0x60..0x77
    UTF-8 string           | string          | 0x78
    UTF-8 string           | string          | 0x79
    UTF-8 string           | string          | 0x7A
    UTF-8 string           | string          | 0x7B
    UTF-8 string           | string          | 0x7F
    array                  | array           | 0x80..0x97
    array                  | array           | 0x98
    array                  | array           | 0x99
    array                  | array           | 0x9A
    array                  | array           | 0x9B
    array                  | array           | 0x9F
    map                    | object          | 0xA0..0xB7
    map                    | object          | 0xB8
    map                    | object          | 0xB9
    map                    | object          | 0xBA
    map                    | object          | 0xBB
    map                    | object          | 0xBF
    False                  | `false`         | 0xF4
    True                   | `true`          | 0xF5
    Null                   | `null`          | 0xF6
    Half-Precision Float   | number_float    | 0xF9
    Single-Precision Float | number_float    | 0xFA
    Double-Precision Float | number_float    | 0xFB

    @warning The mapping is **incomplete** in the sense that not all CBOR
             types can be converted to a JSON value. The following CBOR types
             are not supported and will yield parse errors (parse_error.112):
             - date/time (0xC0..0xC1)
             - bignum (0xC2..0xC3)
             - decimal fraction (0xC4)
             - bigfloat (0xC5)
             - expected conversions (0xD5..0xD7)
             - simple values (0xE0..0xF3, 0xF8)
             - undefined (0xF7)

    @warning CBOR allows map keys of any type, whereas JSON only allows
             strings as keys in object values. Therefore, CBOR maps with keys
             other than UTF-8 strings are rejected (parse_error.113).

    @note Any CBOR output created @ref to_cbor can be successfully parsed by
          @ref from_cbor.

    @param[in] i  an input in CBOR format convertible to an input adapter
    @param[in] strict  whether to expect the input to be consumed until EOF
                       (true by default)
    @param[in] allow_exceptions  whether to throw exceptions in case of a
    parse error (optional, true by default)
    @param[in] tag_handler how to treat CBOR tags (optional, error by default)

    @return deserialized JSON value; in case of a parse error and
            @a allow_exceptions set to `false`, the return value will be
            value_t::discarded.

    @throw parse_error.110 if the given input ends prematurely or the end of
    file was not reached when @a strict was set to true
    @throw parse_error.112 if unsupported features from CBOR were
    used in the given input @a v or if the input is not valid CBOR
    @throw parse_error.113 if a string was expected as map key, but not found

    @complexity Linear in the size of the input @a i.

    @liveexample{The example shows the deserialization of a byte vector in CBOR
    format to a JSON value.,from_cbor}

    @sa http://cbor.io
    @sa see @ref to_cbor(const basic_json&) for the analogous serialization
    @sa see @ref from_msgpack(InputType&&, const bool, const bool) for the
        related MessagePack format
    @sa see @ref from_ubjson(InputType&&, const bool, const bool) for the
        related UBJSON format

    @since version 2.0.9; parameter @a start_index since 2.1.1; changed to
           consume input adapters, removed start_index parameter, and added
           @a strict parameter since 3.0.0; added @a allow_exceptions parameter
           since 3.2.0; added @a tag_handler parameter since 3.9.0.
    */
    template<typename InputType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_cbor(InputType&& i,
                                const bool strict = true,
                                const bool allow_exceptions = true,
                                const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::forward<InputType>(i));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::cbor, &sdp, strict, tag_handler);
        return res ? result : basic_json(value_t::discarded);
    }

    /*!
    @copydoc from_cbor(InputType&&, const bool, const bool, const cbor_tag_handler_t)
    */
    template<typename IteratorType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_cbor(IteratorType first, IteratorType last,
                                const bool strict = true,
                                const bool allow_exceptions = true,
                                const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::move(first), std::move(last));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::cbor, &sdp, strict, tag_handler);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename T>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_cbor(ptr, ptr + len))
    static basic_json from_cbor(const T* ptr, std::size_t len,
                                const bool strict = true,
                                const bool allow_exceptions = true,
                                const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        return from_cbor(ptr, ptr + len, strict, allow_exceptions, tag_handler);
    }


    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_cbor(ptr, ptr + len))
    static basic_json from_cbor(detail::span_input_adapter&& i,
                                const bool strict = true,
                                const bool allow_exceptions = true,
                                const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = i.get();
        // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::cbor, &sdp, strict, tag_handler);
        return res ? result : basic_json(value_t::discarded);
    }

    /*!
    @brief create a JSON value from an input in MessagePack format

    Deserializes a given input @a i to a JSON value using the MessagePack
    serialization format.

    The library maps MessagePack types to JSON value types as follows:

    MessagePack type | JSON value type | first byte
    ---------------- | --------------- | ----------
    positive fixint  | number_unsigned | 0x00..0x7F
    fixmap           | object          | 0x80..0x8F
    fixarray         | array           | 0x90..0x9F
    fixstr           | string          | 0xA0..0xBF
    nil              | `null`          | 0xC0
    false            | `false`         | 0xC2
    true             | `true`          | 0xC3
    float 32         | number_float    | 0xCA
    float 64         | number_float    | 0xCB
    uint 8           | number_unsigned | 0xCC
    uint 16          | number_unsigned | 0xCD
    uint 32          | number_unsigned | 0xCE
    uint 64          | number_unsigned | 0xCF
    int 8            | number_integer  | 0xD0
    int 16           | number_integer  | 0xD1
    int 32           | number_integer  | 0xD2
    int 64           | number_integer  | 0xD3
    str 8            | string          | 0xD9
    str 16           | string          | 0xDA
    str 32           | string          | 0xDB
    array 16         | array           | 0xDC
    array 32         | array           | 0xDD
    map 16           | object          | 0xDE
    map 32           | object          | 0xDF
    bin 8            | binary          | 0xC4
    bin 16           | binary          | 0xC5
    bin 32           | binary          | 0xC6
    ext 8            | binary          | 0xC7
    ext 16           | binary          | 0xC8
    ext 32           | binary          | 0xC9
    fixext 1         | binary          | 0xD4
    fixext 2         | binary          | 0xD5
    fixext 4         | binary          | 0xD6
    fixext 8         | binary          | 0xD7
    fixext 16        | binary          | 0xD8
    negative fixint  | number_integer  | 0xE0-0xFF

    @note Any MessagePack output created @ref to_msgpack can be successfully
          parsed by @ref from_msgpack.

    @param[in] i  an input in MessagePack format convertible to an input
                  adapter
    @param[in] strict  whether to expect the input to be consumed until EOF
                       (true by default)
    @param[in] allow_exceptions  whether to throw exceptions in case of a
    parse error (optional, true by default)

    @return deserialized JSON value; in case of a parse error and
            @a allow_exceptions set to `false`, the return value will be
            value_t::discarded.

    @throw parse_error.110 if the given input ends prematurely or the end of
    file was not reached when @a strict was set to true
    @throw parse_error.112 if unsupported features from MessagePack were
    used in the given input @a i or if the input is not valid MessagePack
    @throw parse_error.113 if a string was expected as map key, but not found

    @complexity Linear in the size of the input @a i.

    @liveexample{The example shows the deserialization of a byte vector in
    MessagePack format to a JSON value.,from_msgpack}

    @sa http://msgpack.org
    @sa see @ref to_msgpack(const basic_json&) for the analogous serialization
    @sa see @ref from_cbor(InputType&&, const bool, const bool, const cbor_tag_handler_t) for the
        related CBOR format
    @sa see @ref from_ubjson(InputType&&, const bool, const bool) for
        the related UBJSON format
    @sa see @ref from_bson(InputType&&, const bool, const bool) for
        the related BSON format

    @since version 2.0.9; parameter @a start_index since 2.1.1; changed to
           consume input adapters, removed start_index parameter, and added
           @a strict parameter since 3.0.0; added @a allow_exceptions parameter
           since 3.2.0
    */
    template<typename InputType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_msgpack(InputType&& i,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::forward<InputType>(i));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::msgpack, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    /*!
    @copydoc from_msgpack(InputType&&, const bool, const bool)
    */
    template<typename IteratorType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_msgpack(IteratorType first, IteratorType last,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::move(first), std::move(last));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::msgpack, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }


    template<typename T>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_msgpack(ptr, ptr + len))
    static basic_json from_msgpack(const T* ptr, std::size_t len,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        return from_msgpack(ptr, ptr + len, strict, allow_exceptions);
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_msgpack(ptr, ptr + len))
    static basic_json from_msgpack(detail::span_input_adapter&& i,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = i.get();
        // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::msgpack, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }


    /*!
    @brief create a JSON value from an input in UBJSON format

    Deserializes a given input @a i to a JSON value using the UBJSON (Universal
    Binary JSON) serialization format.

    The library maps UBJSON types to JSON value types as follows:

    UBJSON type | JSON value type                         | marker
    ----------- | --------------------------------------- | ------
    no-op       | *no value, next value is read*          | `N`
    null        | `null`                                  | `Z`
    false       | `false`                                 | `F`
    true        | `true`                                  | `T`
    float32     | number_float                            | `d`
    float64     | number_float                            | `D`
    uint8       | number_unsigned                         | `U`
    int8        | number_integer                          | `i`
    int16       | number_integer                          | `I`
    int32       | number_integer                          | `l`
    int64       | number_integer                          | `L`
    high-precision number | number_integer, number_unsigned, or number_float - depends on number string | 'H'
    string      | string                                  | `S`
    char        | string                                  | `C`
    array       | array (optimized values are supported)  | `[`
    object      | object (optimized values are supported) | `{`

    @note The mapping is **complete** in the sense that any UBJSON value can
          be converted to a JSON value.

    @param[in] i  an input in UBJSON format convertible to an input adapter
    @param[in] strict  whether to expect the input to be consumed until EOF
                       (true by default)
    @param[in] allow_exceptions  whether to throw exceptions in case of a
    parse error (optional, true by default)

    @return deserialized JSON value; in case of a parse error and
            @a allow_exceptions set to `false`, the return value will be
            value_t::discarded.

    @throw parse_error.110 if the given input ends prematurely or the end of
    file was not reached when @a strict was set to true
    @throw parse_error.112 if a parse error occurs
    @throw parse_error.113 if a string could not be parsed successfully

    @complexity Linear in the size of the input @a i.

    @liveexample{The example shows the deserialization of a byte vector in
    UBJSON format to a JSON value.,from_ubjson}

    @sa http://ubjson.org
    @sa see @ref to_ubjson(const basic_json&, const bool, const bool) for the
             analogous serialization
    @sa see @ref from_cbor(InputType&&, const bool, const bool, const cbor_tag_handler_t) for the
        related CBOR format
    @sa see @ref from_msgpack(InputType&&, const bool, const bool) for
        the related MessagePack format
    @sa see @ref from_bson(InputType&&, const bool, const bool) for
        the related BSON format

    @since version 3.1.0; added @a allow_exceptions parameter since 3.2.0
    */
    template<typename InputType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_ubjson(InputType&& i,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::forward<InputType>(i));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::ubjson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    /*!
    @copydoc from_ubjson(InputType&&, const bool, const bool)
    */
    template<typename IteratorType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_ubjson(IteratorType first, IteratorType last,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::move(first), std::move(last));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::ubjson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename T>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_ubjson(ptr, ptr + len))
    static basic_json from_ubjson(const T* ptr, std::size_t len,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        return from_ubjson(ptr, ptr + len, strict, allow_exceptions);
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_ubjson(ptr, ptr + len))
    static basic_json from_ubjson(detail::span_input_adapter&& i,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = i.get();
        // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::ubjson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }


    /// @brief Create a JSON value from an input in BSON format
    /// @sa https://json.nlohmann.me/api/basic_json/from_bson/
    template<typename InputType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_bson(InputType&& i,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::forward<InputType>(i));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::bson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    /// @brief Create a JSON value from an input in BSON format
    /// @sa https://json.nlohmann.me/api/basic_json/from_bson/
    template<typename IteratorType>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json from_bson(IteratorType first, IteratorType last,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = detail::input_adapter(std::move(first), std::move(last));
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::bson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename T>
    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_bson(ptr, ptr + len))
    static basic_json from_bson(const T* ptr, std::size_t len,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        return from_bson(ptr, ptr + len, strict, allow_exceptions);
    }

    JSON_HEDLEY_WARN_UNUSED_RESULT
    JSON_HEDLEY_DEPRECATED_FOR(3.8.0, from_bson(ptr, ptr + len))
    static basic_json from_bson(detail::span_input_adapter&& i,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        auto ia = i.get();
        // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
        const bool res = binary_reader<decltype(ia)>(std::move(ia)).sax_parse(input_format_t::bson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }
    /// @}

    //////////////////////////
    // JSON Pointer support //
    //////////////////////////

    /// @name JSON Pointer functions
    /// @{

    /*!
    @brief access specified element via JSON Pointer

    Uses a JSON pointer to retrieve a reference to the respective JSON value.
    No bound checking is performed. Similar to @ref operator[](const typename
    object_t::key_type&), `null` values are created in arrays and objects if
    necessary.

    In particular:
    - If the JSON pointer points to an object key that does not exist, it
      is created an filled with a `null` value before a reference to it
      is returned.
    - If the JSON pointer points to an array index that does not exist, it
      is created an filled with a `null` value before a reference to it
      is returned. All indices between the current maximum and the given
      index are also filled with `null`.
    - The special value `-` is treated as a synonym for the index past the
      end.

    @param[in] ptr  a JSON pointer

    @return reference to the element pointed to by @a ptr

    @complexity Constant.

    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    @throw out_of_range.404  if the JSON pointer can not be resolved

    @liveexample{The behavior is shown in the example.,operatorjson_pointer}

    @since version 2.0.0
    */
    reference operator[](const json_pointer& ptr)
    {
        return ptr.get_unchecked(this);
    }

    /*!
    @brief access specified element via JSON Pointer

    Uses a JSON pointer to retrieve a reference to the respective JSON value.
    No bound checking is performed. The function does not change the JSON
    value; no `null` values are created. In particular, the special value
    `-` yields an exception.

    @param[in] ptr  JSON pointer to the desired element

    @return const reference to the element pointed to by @a ptr

    @complexity Constant.

    @throw parse_error.106   if an array index begins with '0'
    @throw parse_error.109   if an array index was not a number
    @throw out_of_range.402  if the array index '-' is used
    @throw out_of_range.404  if the JSON pointer can not be resolved

    @liveexample{The behavior is shown in the example.,operatorjson_pointer_const}

    @since version 2.0.0
    */
    const_reference operator[](const json_pointer& ptr) const
    {
        return ptr.get_unchecked(this);
    }

    /*!
    @brief access specified element via JSON Pointer

    Returns a reference to the element at with specified JSON pointer @a ptr,
    with bounds checking.

    @param[in] ptr  JSON pointer to the desired element

    @return reference to the element pointed to by @a ptr

    @throw parse_error.106 if an array index in the passed JSON pointer @a ptr
    begins with '0'. See example below.

    @throw parse_error.109 if an array index in the passed JSON pointer @a ptr
    is not a number. See example below.

    @throw out_of_range.401 if an array index in the passed JSON pointer @a ptr
    is out of range. See example below.

    @throw out_of_range.402 if the array index '-' is used in the passed JSON
    pointer @a ptr. As `at` provides checked access (and no elements are
    implicitly inserted), the index '-' is always invalid. See example below.

    @throw out_of_range.403 if the JSON pointer describes a key of an object
    which cannot be found. See example below.

    @throw out_of_range.404 if the JSON pointer @a ptr can not be resolved.
    See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Constant.

    @since version 2.0.0

    @liveexample{The behavior is shown in the example.,at_json_pointer}
    */
    reference at(const json_pointer& ptr)
    {
        return ptr.get_checked(this);
    }

    /*!
    @brief access specified element via JSON Pointer

    Returns a const reference to the element at with specified JSON pointer @a
    ptr, with bounds checking.

    @param[in] ptr  JSON pointer to the desired element

    @return reference to the element pointed to by @a ptr

    @throw parse_error.106 if an array index in the passed JSON pointer @a ptr
    begins with '0'. See example below.

    @throw parse_error.109 if an array index in the passed JSON pointer @a ptr
    is not a number. See example below.

    @throw out_of_range.401 if an array index in the passed JSON pointer @a ptr
    is out of range. See example below.

    @throw out_of_range.402 if the array index '-' is used in the passed JSON
    pointer @a ptr. As `at` provides checked access (and no elements are
    implicitly inserted), the index '-' is always invalid. See example below.

    @throw out_of_range.403 if the JSON pointer describes a key of an object
    which cannot be found. See example below.

    @throw out_of_range.404 if the JSON pointer @a ptr can not be resolved.
    See example below.

    @exceptionsafety Strong guarantee: if an exception is thrown, there are no
    changes in the JSON value.

    @complexity Constant.

    @since version 2.0.0

    @liveexample{The behavior is shown in the example.,at_json_pointer_const}
    */
    const_reference at(const json_pointer& ptr) const
    {
        return ptr.get_checked(this);
    }

    /// @brief return flattened JSON value
    /// @sa https://json.nlohmann.me/api/basic_json/flatten/
    basic_json flatten() const
    {
        basic_json result(value_t::object);
        json_pointer::flatten("", *this, result);
        return result;
    }

    /// @brief unflatten a previously flattened JSON value
    /// @sa https://json.nlohmann.me/api/basic_json/unflatten/
    basic_json unflatten() const
    {
        return json_pointer::unflatten(*this);
    }

    /// @}

    //////////////////////////
    // JSON Patch functions //
    //////////////////////////

    /// @name JSON Patch functions
    /// @{

    /// @brief applies a JSON patch
    /// @sa https://json.nlohmann.me/api/basic_json/patch/
    basic_json patch(const basic_json& json_patch) const
    {
        // make a working copy to apply the patch to
        basic_json result = *this;

        // the valid JSON Patch operations
        enum class patch_operations {add, remove, replace, move, copy, test, invalid};

        const auto get_op = [](const std::string & op)
        {
            if (op == "add")
            {
                return patch_operations::add;
            }
            if (op == "remove")
            {
                return patch_operations::remove;
            }
            if (op == "replace")
            {
                return patch_operations::replace;
            }
            if (op == "move")
            {
                return patch_operations::move;
            }
            if (op == "copy")
            {
                return patch_operations::copy;
            }
            if (op == "test")
            {
                return patch_operations::test;
            }

            return patch_operations::invalid;
        };

        // wrapper for "add" operation; add value at ptr
        const auto operation_add = [&result](json_pointer & ptr, basic_json val)
        {
            // adding to the root of the target document means replacing it
            if (ptr.empty())
            {
                result = val;
                return;
            }

            // make sure the top element of the pointer exists
            json_pointer top_pointer = ptr.top();
            if (top_pointer != ptr)
            {
                result.at(top_pointer);
            }

            // get reference to parent of JSON pointer ptr
            const auto last_path = ptr.back();
            ptr.pop_back();
            basic_json& parent = result[ptr];

            switch (parent.m_type)
            {
                case value_t::null:
                case value_t::object:
                {
                    // use operator[] to add value
                    parent[last_path] = val;
                    break;
                }

                case value_t::array:
                {
                    if (last_path == "-")
                    {
                        // special case: append to back
                        parent.push_back(val);
                    }
                    else
                    {
                        const auto idx = json_pointer::array_index(last_path);
                        if (JSON_HEDLEY_UNLIKELY(idx > parent.size()))
                        {
                            // avoid undefined behavior
                            JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range", parent));
                        }

                        // default case: insert add offset
                        parent.insert(parent.begin() + static_cast<difference_type>(idx), val);
                    }
                    break;
                }

                // if there exists a parent it cannot be primitive
                case value_t::string: // LCOV_EXCL_LINE
                case value_t::boolean: // LCOV_EXCL_LINE
                case value_t::number_integer: // LCOV_EXCL_LINE
                case value_t::number_unsigned: // LCOV_EXCL_LINE
                case value_t::number_float: // LCOV_EXCL_LINE
                case value_t::binary: // LCOV_EXCL_LINE
                case value_t::discarded: // LCOV_EXCL_LINE
                default:            // LCOV_EXCL_LINE
                    JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            }
        };

        // wrapper for "remove" operation; remove value at ptr
        const auto operation_remove = [this, &result](json_pointer & ptr)
        {
            // get reference to parent of JSON pointer ptr
            const auto last_path = ptr.back();
            ptr.pop_back();
            basic_json& parent = result.at(ptr);

            // remove child
            if (parent.is_object())
            {
                // perform range check
                auto it = parent.find(last_path);
                if (JSON_HEDLEY_LIKELY(it != parent.end()))
                {
                    parent.erase(it);
                }
                else
                {
                    JSON_THROW(out_of_range::create(403, "key '" + last_path + "' not found", *this));
                }
            }
            else if (parent.is_array())
            {
                // note erase performs range check
                parent.erase(json_pointer::array_index(last_path));
            }
        };

        // type check: top level value must be an array
        if (JSON_HEDLEY_UNLIKELY(!json_patch.is_array()))
        {
            JSON_THROW(parse_error::create(104, 0, "JSON patch must be an array of objects", json_patch));
        }

        // iterate and apply the operations
        for (const auto& val : json_patch)
        {
            // wrapper to get a value for an operation
            const auto get_value = [&val](const std::string & op,
                                          const std::string & member,
                                          bool string_type) -> basic_json &
            {
                // find value
                auto it = val.m_value.object->find(member);

                // context-sensitive error message
                const auto error_msg = (op == "op") ? "operation" : "operation '" + op + "'";

                // check if desired value is present
                if (JSON_HEDLEY_UNLIKELY(it == val.m_value.object->end()))
                {
                    // NOLINTNEXTLINE(performance-inefficient-string-concatenation)
                    JSON_THROW(parse_error::create(105, 0, error_msg + " must have member '" + member + "'", val));
                }

                // check if result is of type string
                if (JSON_HEDLEY_UNLIKELY(string_type && !it->second.is_string()))
                {
                    // NOLINTNEXTLINE(performance-inefficient-string-concatenation)
                    JSON_THROW(parse_error::create(105, 0, error_msg + " must have string member '" + member + "'", val));
                }

                // no error: return value
                return it->second;
            };

            // type check: every element of the array must be an object
            if (JSON_HEDLEY_UNLIKELY(!val.is_object()))
            {
                JSON_THROW(parse_error::create(104, 0, "JSON patch must be an array of objects", val));
            }

            // collect mandatory members
            const auto op = get_value("op", "op", true).template get<std::string>();
            const auto path = get_value(op, "path", true).template get<std::string>();
            json_pointer ptr(path);

            switch (get_op(op))
            {
                case patch_operations::add:
                {
                    operation_add(ptr, get_value("add", "value", false));
                    break;
                }

                case patch_operations::remove:
                {
                    operation_remove(ptr);
                    break;
                }

                case patch_operations::replace:
                {
                    // the "path" location must exist - use at()
                    result.at(ptr) = get_value("replace", "value", false);
                    break;
                }

                case patch_operations::move:
                {
                    const auto from_path = get_value("move", "from", true).template get<std::string>();
                    json_pointer from_ptr(from_path);

                    // the "from" location must exist - use at()
                    basic_json v = result.at(from_ptr);

                    // The move operation is functionally identical to a
                    // "remove" operation on the "from" location, followed
                    // immediately by an "add" operation at the target
                    // location with the value that was just removed.
                    operation_remove(from_ptr);
                    operation_add(ptr, v);
                    break;
                }

                case patch_operations::copy:
                {
                    const auto from_path = get_value("copy", "from", true).template get<std::string>();
                    const json_pointer from_ptr(from_path);

                    // the "from" location must exist - use at()
                    basic_json v = result.at(from_ptr);

                    // The copy is functionally identical to an "add"
                    // operation at the target location using the value
                    // specified in the "from" member.
                    operation_add(ptr, v);
                    break;
                }

                case patch_operations::test:
                {
                    bool success = false;
                    JSON_TRY
                    {
                        // check if "value" matches the one at "path"
                        // the "path" location must exist - use at()
                        success = (result.at(ptr) == get_value("test", "value", false));
                    }
                    JSON_INTERNAL_CATCH (out_of_range&)
                    {
                        // ignore out of range errors: success remains false
                    }

                    // throw an exception if test fails
                    if (JSON_HEDLEY_UNLIKELY(!success))
                    {
                        JSON_THROW(other_error::create(501, "unsuccessful: " + val.dump(), val));
                    }

                    break;
                }

                case patch_operations::invalid:
                default:
                {
                    // op must be "add", "remove", "replace", "move", "copy", or
                    // "test"
                    JSON_THROW(parse_error::create(105, 0, "operation value '" + op + "' is invalid", val));
                }
            }
        }

        return result;
    }

    /// @brief creates a diff as a JSON patch
    /// @sa https://json.nlohmann.me/api/basic_json/diff/
    JSON_HEDLEY_WARN_UNUSED_RESULT
    static basic_json diff(const basic_json& source, const basic_json& target,
                           const std::string& path = "")
    {
        // the patch
        basic_json result(value_t::array);

        // if the values are the same, return empty patch
        if (source == target)
        {
            return result;
        }

        if (source.type() != target.type())
        {
            // different types: replace value
            result.push_back(
            {
                {"op", "replace"}, {"path", path}, {"value", target}
            });
            return result;
        }

        switch (source.type())
        {
            case value_t::array:
            {
                // first pass: traverse common elements
                std::size_t i = 0;
                while (i < source.size() && i < target.size())
                {
                    // recursive call to compare array values at index i
                    auto temp_diff = diff(source[i], target[i], path + "/" + std::to_string(i));
                    result.insert(result.end(), temp_diff.begin(), temp_diff.end());
                    ++i;
                }

                // i now reached the end of at least one array
                // in a second pass, traverse the remaining elements

                // remove my remaining elements
                const auto end_index = static_cast<difference_type>(result.size());
                while (i < source.size())
                {
                    // add operations in reverse order to avoid invalid
                    // indices
                    result.insert(result.begin() + end_index, object(
                    {
                        {"op", "remove"},
                        {"path", path + "/" + std::to_string(i)}
                    }));
                    ++i;
                }

                // add other remaining elements
                while (i < target.size())
                {
                    result.push_back(
                    {
                        {"op", "add"},
                        {"path", path + "/-"},
                        {"value", target[i]}
                    });
                    ++i;
                }

                break;
            }

            case value_t::object:
            {
                // first pass: traverse this object's elements
                for (auto it = source.cbegin(); it != source.cend(); ++it)
                {
                    // escape the key name to be used in a JSON patch
                    const auto path_key = path + "/" + detail::escape(it.key());

                    if (target.find(it.key()) != target.end())
                    {
                        // recursive call to compare object values at key it
                        auto temp_diff = diff(it.value(), target[it.key()], path_key);
                        result.insert(result.end(), temp_diff.begin(), temp_diff.end());
                    }
                    else
                    {
                        // found a key that is not in o -> remove it
                        result.push_back(object(
                        {
                            {"op", "remove"}, {"path", path_key}
                        }));
                    }
                }

                // second pass: traverse other object's elements
                for (auto it = target.cbegin(); it != target.cend(); ++it)
                {
                    if (source.find(it.key()) == source.end())
                    {
                        // found a key that is not in this -> add it
                        const auto path_key = path + "/" + detail::escape(it.key());
                        result.push_back(
                        {
                            {"op", "add"}, {"path", path_key},
                            {"value", it.value()}
                        });
                    }
                }

                break;
            }

            case value_t::null:
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            case value_t::discarded:
            default:
            {
                // both primitive type: replace value
                result.push_back(
                {
                    {"op", "replace"}, {"path", path}, {"value", target}
                });
                break;
            }
        }

        return result;
    }

    /// @}

    ////////////////////////////////
    // JSON Merge Patch functions //
    ////////////////////////////////

    /// @name JSON Merge Patch functions
    /// @{

    /// @brief applies a JSON Merge Patch
    /// @sa https://json.nlohmann.me/api/basic_json/merge_patch/
    void merge_patch(const basic_json& apply_patch)
    {
        if (apply_patch.is_object())
        {
            if (!is_object())
            {
                *this = object();
            }
            for (auto it = apply_patch.begin(); it != apply_patch.end(); ++it)
            {
                if (it.value().is_null())
                {
                    erase(it.key());
                }
                else
                {
                    operator[](it.key()).merge_patch(it.value());
                }
            }
        }
        else
        {
            *this = apply_patch;
        }
    }

    /// @}
};

/*!
@brief user-defined to_string function for JSON values

This function implements a user-defined to_string  for JSON objects.

@param[in] j  a JSON object
@return a std::string object
*/

NLOHMANN_BASIC_JSON_TPL_DECLARATION
std::string to_string(const NLOHMANN_BASIC_JSON_TPL& j)
{
    return j.dump();
}
} // namespace nlohmann

///////////////////////
// nonmember support //
///////////////////////

// specialization of std::swap, and std::hash
namespace std
{

/// hash value for JSON objects
template<>
struct hash<nlohmann::json>
{
    /*!
    @brief return a hash value for a JSON object

    @since version 1.0.0
    */
    std::size_t operator()(const nlohmann::json& j) const
    {
        return nlohmann::detail::hash(j);
    }
};

/// specialization for std::less<value_t>
/// @note: do not remove the space after '<',
///        see https://github.com/nlohmann/json/pull/679
template<>
struct less<::nlohmann::detail::value_t>
{
    /*!
    @brief compare two value_t enum values
    @since version 3.0.0
    */
    bool operator()(nlohmann::detail::value_t lhs,
                    nlohmann::detail::value_t rhs) const noexcept
    {
        return nlohmann::detail::operator<(lhs, rhs);
    }
};

// C++20 prohibit function specialization in the std namespace.
#ifndef JSON_HAS_CPP_20

/*!
@brief exchanges the values of two JSON objects

@since version 1.0.0
*/
template<>
inline void swap<nlohmann::json>(nlohmann::json& j1, nlohmann::json& j2) noexcept( // NOLINT(readability-inconsistent-declaration-parameter-name)
    is_nothrow_move_constructible<nlohmann::json>::value&&  // NOLINT(misc-redundant-expression)
    is_nothrow_move_assignable<nlohmann::json>::value
                              )
{
    j1.swap(j2);
}

#endif

} // namespace std

/// @brief user-defined string literal for JSON values
/// @sa https://json.nlohmann.me/api/basic_json/operator_literal_json/
JSON_HEDLEY_NON_NULL(1)
inline nlohmann::json operator "" _json(const char* s, std::size_t n)
{
    return nlohmann::json::parse(s, s + n);
}

/// @brief user-defined string literal for JSON pointer
/// @sa https://json.nlohmann.me/api/basic_json/operator_literal_json_pointer/
JSON_HEDLEY_NON_NULL(1)
inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
{
    return nlohmann::json::json_pointer(std::string(s, n));
}

#include <nlohmann/detail/macro_unscope.hpp>

#endif  // INCLUDE_NLOHMANN_JSON_HPP_
