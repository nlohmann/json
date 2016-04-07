/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++
|  |  |__   |  |  | | | |  version 2.0.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

#ifndef NLOHMANN_JSON_HPP
#define NLOHMANN_JSON_HPP

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <ciso646>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// disable float-equal warnings on GCC/clang
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wfloat-equal"
#endif

/*!
@brief namespace for Niels Lohmann
@see https://github.com/nlohmann
@since version 1.0.0
*/
namespace nlohmann
{


/*!
@brief unnamed namespace with internal helper functions
@since version 1.0.0
*/
namespace
{
/*!
@brief Helper to determine whether there's a key_type for T.
@sa http://stackoverflow.com/a/7728728/266378
*/
template<typename T>
struct has_mapped_type
{
  private:
    template<typename C> static char test(typename C::mapped_type*);
    template<typename C> static char (&test(...))[2];
  public:
    static constexpr bool value = sizeof(test<T>(0)) == 1;
};

/*!
@brief helper class to create locales with decimal point
@sa https://github.com/nlohmann/json/issues/51#issuecomment-86869315
*/
class DecimalSeparator : public std::numpunct<char>
{
  protected:
    char do_decimal_point() const
    {
        return '.';
    }
};

}

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
@tparam AllocatorType type of the allocator to use (`std::allocator` by
default)

@requirement The class satisfies the following concept requirements:
- Basic
 - [DefaultConstructible](http://en.cppreference.com/w/cpp/concept/DefaultConstructible):
   JSON values can be default constructed. The result will be a JSON null value.
 - [MoveConstructible](http://en.cppreference.com/w/cpp/concept/MoveConstructible):
   A JSON value can be constructed from an rvalue argument.
 - [CopyConstructible](http://en.cppreference.com/w/cpp/concept/CopyConstructible):
   A JSON value can be copy-constructed from an lvalue expression.
 - [MoveAssignable](http://en.cppreference.com/w/cpp/concept/MoveAssignable):
   A JSON value van be assigned from an rvalue argument.
 - [CopyAssignable](http://en.cppreference.com/w/cpp/concept/CopyAssignable):
   A JSON value can be copy-assigned from an lvalue expression.
 - [Destructible](http://en.cppreference.com/w/cpp/concept/Destructible):
   JSON values can be destructed.
- Layout
 - [StandardLayoutType](http://en.cppreference.com/w/cpp/concept/StandardLayoutType):
   JSON values have
   [standard layout](http://en.cppreference.com/w/cpp/language/data_members#Standard_layout):
   All non-static data members are private and standard layout types, the class
   has no virtual functions or (virtual) base classes.
- Library-wide
 - [EqualityComparable](http://en.cppreference.com/w/cpp/concept/EqualityComparable):
   JSON values can be compared with `==`, see @ref
   operator==(const_reference,const_reference).
 - [LessThanComparable](http://en.cppreference.com/w/cpp/concept/LessThanComparable):
   JSON values can be compared with `<`, see @ref
   operator<(const_reference,const_reference).
 - [Swappable](http://en.cppreference.com/w/cpp/concept/Swappable):
   Any JSON lvalue or rvalue of can be swapped with any lvalue or rvalue of
   other compatible types, using unqualified function call @ref swap().
 - [NullablePointer](http://en.cppreference.com/w/cpp/concept/NullablePointer):
   JSON values can be compared against `std::nullptr_t` objects which are used
   to model the `null` value.
- Container
 - [Container](http://en.cppreference.com/w/cpp/concept/Container):
   JSON values can be used like STL containers and provide iterator access.
 - [ReversibleContainer](http://en.cppreference.com/w/cpp/concept/ReversibleContainer);
   JSON values can be used like STL containers and provide reverse iterator
   access.

@internal
@note ObjectType trick from http://stackoverflow.com/a/9860911
@endinternal

@see [RFC 7159: The JavaScript Object Notation (JSON) Data Interchange
Format](http://rfc7159.net/rfc7159)

@since version 1.0.0

@nosubgrouping
*/
template <
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = std::int64_t,
    class NumberUnsignedType = std::uint64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator
    >
class basic_json
{
  private:
    /// workaround type for MSVC
    using basic_json_t = basic_json<ObjectType,
          ArrayType,
          StringType,
          BooleanType,
          NumberIntegerType,
          NumberUnsignedType,
          NumberFloatType,
          AllocatorType>;

  public:

    /////////////////////
    // container types //
    /////////////////////

    /// @name container types
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

    // forward declaration
    template<typename Base> class json_reverse_iterator;

    /// an iterator for a basic_json container
    class iterator;
    /// a const iterator for a basic_json container
    class const_iterator;
    /// a reverse iterator for a basic_json container
    using reverse_iterator = json_reverse_iterator<typename basic_json::iterator>;
    /// a const reverse iterator for a basic_json container
    using const_reverse_iterator = json_reverse_iterator<typename basic_json::const_iterator>;

    /// @}


    /*!
    @brief returns the allocator associated with the container
    */
    static allocator_type get_allocator()
    {
        return allocator_type();
    }


    ///////////////////////////
    // JSON value data types //
    ///////////////////////////

    /// @name JSON value data types
    /// @{

    /*!
    @brief a type for an object

    [RFC 7159](http://rfc7159.net/rfc7159) describes JSON objects as follows:
    > An object is an unordered collection of zero or more name/value pairs,
    > where a name is a string and a value is a string, number, boolean, null,
    > object, or array.

    To store objects in C++, a type is defined by the template parameters
    described below.

    @tparam ObjectType  the container to store objects (e.g., `std::map` or
    `std::unordered_map`)
    @tparam StringType the type of the keys or names (e.g., `std::string`). The
    comparison function `std::less<StringType>` is used to order elements
    inside the container.
    @tparam AllocatorType the allocator to use for objects (e.g.,
    `std::allocator`)

    #### Default type

    With the default values for @a ObjectType (`std::map`), @a StringType
    (`std::string`), and @a AllocatorType (`std::allocator`), the default value
    for @a object_t is:

    @code {.cpp}
    std::map<
      std::string, // key_type
      basic_json, // value_type
      std::less<std::string>, // key_compare
      std::allocator<std::pair<const std::string, basic_json>> // allocator_type
    >
    @endcode

    #### Behavior

    The choice of @a object_t influences the behavior of the JSON class. With
    the default type, objects have the following behavior:

    - When all names are unique, objects will be interoperable in the sense
      that all software implementations receiving that object will agree on the
      name-value mappings.
    - When the names within an object are not unique, later stored name/value
      pairs overwrite previously stored name/value pairs, leaving the used
      names unique. For instance, `{"key": 1}` and `{"key": 2, "key": 1}` will
      be treated as equal and both stored as `{"key": 1}`.
    - Internally, name/value pairs are stored in lexicographical order of the
      names. Objects will also be serialized (see @ref dump) in this order. For
      instance, `{"b": 1, "a": 2}` and `{"a": 2, "b": 1}` will be stored and
      serialized as `{"a": 2, "b": 1}`.
    - When comparing objects, the order of the name/value pairs is irrelevant.
      This makes objects interoperable in the sense that they will not be
      affected by these differences. For instance, `{"b": 1, "a": 2}` and
      `{"a": 2, "b": 1}` will be treated as equal.

    #### Limits

    [RFC 7159](http://rfc7159.net/rfc7159) specifies:
    > An implementation may set limits on the maximum depth of nesting.

    In this class, the object's limit of nesting is not constraint explicitly.
    However, a maximum depth of nesting may be introduced by the compiler or
    runtime environment. A theoretical limit can be queried by calling the @ref
    max_size function of a JSON object.

    #### Storage

    Objects are stored as pointers in a @ref basic_json type. That is, for any
    access to object values, a pointer of type `object_t*` must be dereferenced.

    @sa @ref array_t -- type for an array value

    @since version 1.0.0

    @note The order name/value pairs are added to the object is *not* preserved
    by the library. Therefore, iterating an object may return name/value pairs
    in a different order than they were originally stored. In fact, keys will
    be traversed in alphabetical order as `std::map` with `std::less` is used
    by default. Please note this behavior conforms to [RFC
    7159](http://rfc7159.net/rfc7159), because any order implements the
    specified "unordered" nature of JSON objects.
    */
    using object_t = ObjectType<StringType,
          basic_json,
          std::less<StringType>,
          AllocatorType<std::pair<const StringType,
          basic_json>>>;

    /*!
    @brief a type for an array

    [RFC 7159](http://rfc7159.net/rfc7159) describes JSON arrays as follows:
    > An array is an ordered sequence of zero or more values.

    To store objects in C++, a type is defined by the template parameters
    explained below.

    @tparam ArrayType  container type to store arrays (e.g., `std::vector` or
    `std::list`)
    @tparam AllocatorType  allocator to use for arrays (e.g., `std::allocator`)

    #### Default type

    With the default values for @a ArrayType (`std::vector`) and @a
    AllocatorType (`std::allocator`), the default value for @a array_t is:

    @code {.cpp}
    std::vector<
      basic_json, // value_type
      std::allocator<basic_json> // allocator_type
    >
    @endcode

    #### Limits

    [RFC 7159](http://rfc7159.net/rfc7159) specifies:
    > An implementation may set limits on the maximum depth of nesting.

    In this class, the array's limit of nesting is not constraint explicitly.
    However, a maximum depth of nesting may be introduced by the compiler or
    runtime environment. A theoretical limit can be queried by calling the @ref
    max_size function of a JSON array.

    #### Storage

    Arrays are stored as pointers in a @ref basic_json type. That is, for any
    access to array values, a pointer of type `array_t*` must be dereferenced.

    @sa @ref object_t -- type for an object value

    @since version 1.0.0
    */
    using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;

    /*!
    @brief a type for a string

    [RFC 7159](http://rfc7159.net/rfc7159) describes JSON strings as follows:
    > A string is a sequence of zero or more Unicode characters.

    To store objects in C++, a type is defined by the template parameter
    described below. Unicode values are split by the JSON class into byte-sized
    characters during deserialization.

    @tparam StringType  the container to store strings (e.g., `std::string`).
    Note this container is used for keys/names in objects, see @ref object_t.

    #### Default type

    With the default values for @a StringType (`std::string`), the default
    value for @a string_t is:

    @code {.cpp}
    std::string
    @endcode

    #### String comparison

    [RFC 7159](http://rfc7159.net/rfc7159) states:
    > Software implementations are typically required to test names of object
    > members for equality. Implementations that transform the textual
    > representation into sequences of Unicode code units and then perform the
    > comparison numerically, code unit by code unit, are interoperable in the
    > sense that implementations will agree in all cases on equality or
    > inequality of two strings. For example, implementations that compare
    > strings with escaped characters unconverted may incorrectly find that
    > `"a\\b"` and `"a\u005Cb"` are not equal.

    This implementation is interoperable as it does compare strings code unit
    by code unit.

    #### Storage

    String values are stored as pointers in a @ref basic_json type. That is,
    for any access to string values, a pointer of type `string_t*` must be
    dereferenced.

    @since version 1.0.0
    */
    using string_t = StringType;

    /*!
    @brief a type for a boolean

    [RFC 7159](http://rfc7159.net/rfc7159) implicitly describes a boolean as a
    type which differentiates the two literals `true` and `false`.

    To store objects in C++, a type is defined by the template parameter @a
    BooleanType which chooses the type to use.

    #### Default type

    With the default values for @a BooleanType (`bool`), the default value for
    @a boolean_t is:

    @code {.cpp}
    bool
    @endcode

    #### Storage

    Boolean values are stored directly inside a @ref basic_json type.

    @since version 1.0.0
    */
    using boolean_t = BooleanType;

    /*!
    @brief a type for a number (integer)

    [RFC 7159](http://rfc7159.net/rfc7159) describes numbers as follows:
    > The representation of numbers is similar to that used in most programming
    > languages. A number is represented in base 10 using decimal digits. It
    > contains an integer component that may be prefixed with an optional minus
    > sign, which may be followed by a fraction part and/or an exponent part.
    > Leading zeros are not allowed. (...) Numeric values that cannot be
    > represented in the grammar below (such as Infinity and NaN) are not
    > permitted.

    This description includes both integer and floating-point numbers. However,
    C++ allows more precise storage if it is known whether the number is a
    signed integer, an unsigned integer or a floating-point number. Therefore,
    three different types, @ref number_integer_t, @ref number_unsigned_t and
    @ref number_float_t are used.

    To store integer numbers in C++, a type is defined by the template
    parameter @a NumberIntegerType which chooses the type to use.

    #### Default type

    With the default values for @a NumberIntegerType (`int64_t`), the default
    value for @a number_integer_t is:

    @code {.cpp}
    int64_t
    @endcode

    #### Default behavior

    - The restrictions about leading zeros is not enforced in C++. Instead,
      leading zeros in integer literals lead to an interpretation as octal
      number. Internally, the value will be stored as decimal number. For
      instance, the C++ integer literal `010` will be serialized to `8`. During
      deserialization, leading zeros yield an error.
    - Not-a-number (NaN) values will be serialized to `null`.

    #### Limits

    [RFC 7159](http://rfc7159.net/rfc7159) specifies:
    > An implementation may set limits on the range and precision of numbers.

    When the default type is used, the maximal integer number that can be
    stored is `9223372036854775807` (INT64_MAX) and the minimal integer number
    that can be stored is `-9223372036854775808` (INT64_MIN). Integer numbers
    that are out of range will yield over/underflow when used in a constructor.
    During deserialization, too large or small integer numbers will be
    automatically be stored as @ref number_unsigned_t or @ref number_float_t.

    [RFC 7159](http://rfc7159.net/rfc7159) further states:
    > Note that when such software is used, numbers that are integers and are
    > in the range \f$[-2^{53}+1, 2^{53}-1]\f$ are interoperable in the sense
    > that implementations will agree exactly on their numeric values.

    As this range is a subrange of the exactly supported range [INT64_MIN,
    INT64_MAX], this class's integer type is interoperable.

    #### Storage

    Integer number values are stored directly inside a @ref basic_json type.

    @sa @ref number_float_t -- type for number values (floating-point)

    @sa @ref number_unsigned_t -- type for number values (unsigned integer)

    @since version 1.0.0
    */
    using number_integer_t = NumberIntegerType;

    /*!
    @brief a type for a number (unsigned)

    [RFC 7159](http://rfc7159.net/rfc7159) describes numbers as follows:
    > The representation of numbers is similar to that used in most programming
    > languages. A number is represented in base 10 using decimal digits. It
    > contains an integer component that may be prefixed with an optional minus
    > sign, which may be followed by a fraction part and/or an exponent part.
    > Leading zeros are not allowed. (...) Numeric values that cannot be
    > represented in the grammar below (such as Infinity and NaN) are not
    > permitted.

    This description includes both integer and floating-point numbers. However,
    C++ allows more precise storage if it is known whether the number is a
    signed integer, an unsigned integer or a floating-point number. Therefore,
    three different types, @ref number_integer_t, @ref number_unsigned_t and
    @ref number_float_t are used.

    To store unsigned integer numbers in C++, a type is defined by the template
    parameter @a NumberUnsignedType which chooses the type to use.

    #### Default type

    With the default values for @a NumberUnsignedType (`uint64_t`), the default
    value for @a number_unsigned_t is:

    @code {.cpp}
    uint64_t
    @endcode

    #### Default behavior

    - The restrictions about leading zeros is not enforced in C++. Instead,
      leading zeros in integer literals lead to an interpretation as octal
      number. Internally, the value will be stored as decimal number. For
      instance, the C++ integer literal `010` will be serialized to `8`. During
      deserialization, leading zeros yield an error.
    - Not-a-number (NaN) values will be serialized to `null`.

    #### Limits

    [RFC 7159](http://rfc7159.net/rfc7159) specifies:
    > An implementation may set limits on the range and precision of numbers.

    When the default type is used, the maximal integer number that can be
    stored is `18446744073709551615` (UINT64_MAX) and the minimal integer
    number that can be stored is `0`. Integer numbers that are out of range
    will yield over/underflow when used in a constructor. During
    deserialization, too large or small integer numbers will be automatically
    be stored as @ref number_integer_t or @ref number_float_t.

    [RFC 7159](http://rfc7159.net/rfc7159) further states:
    > Note that when such software is used, numbers that are integers and are
    > in the range \f$[-2^{53}+1, 2^{53}-1]\f$ are interoperable in the sense
    > that implementations will agree exactly on their numeric values.

    As this range is a subrange (when considered in conjunction with the
    number_integer_t type) of the exactly supported range [0, UINT64_MAX], this
    class's integer type is interoperable.

    #### Storage

    Integer number values are stored directly inside a @ref basic_json type.

    @sa @ref number_float_t -- type for number values (floating-point)

    @sa @ref number_integer_t -- type for number values (integer)

    @since version 2.0.0
    */
    using number_unsigned_t = NumberUnsignedType;

    /*!
    @brief a type for a number (floating-point)

    [RFC 7159](http://rfc7159.net/rfc7159) describes numbers as follows:
    > The representation of numbers is similar to that used in most programming
    > languages. A number is represented in base 10 using decimal digits. It
    > contains an integer component that may be prefixed with an optional minus
    > sign, which may be followed by a fraction part and/or an exponent part.
    > Leading zeros are not allowed. (...) Numeric values that cannot be
    > represented in the grammar below (such as Infinity and NaN) are not
    > permitted.

    This description includes both integer and floating-point numbers. However,
    C++ allows more precise storage if it is known whether the number is a
    signed integer, an unsigned integer or a floating-point number. Therefore,
    three different types, @ref number_integer_t, @ref number_unsigned_t and
    @ref number_float_t are used.

    To store floating-point numbers in C++, a type is defined by the template
    parameter @a NumberFloatType which chooses the type to use.

    #### Default type

    With the default values for @a NumberFloatType (`double`), the default
    value for @a number_float_t is:

    @code {.cpp}
    double
    @endcode

    #### Default behavior

    - The restrictions about leading zeros is not enforced in C++. Instead,
      leading zeros in floating-point literals will be ignored. Internally, the
      value will be stored as decimal number. For instance, the C++
      floating-point literal `01.2` will be serialized to `1.2`. During
      deserialization, leading zeros yield an error.
    - Not-a-number (NaN) values will be serialized to `null`.

    #### Limits

    [RFC 7159](http://rfc7159.net/rfc7159) states:
    > This specification allows implementations to set limits on the range and
    > precision of numbers accepted. Since software that implements IEEE
    > 754-2008 binary64 (double precision) numbers is generally available and
    > widely used, good interoperability can be achieved by implementations that
    > expect no more precision or range than these provide, in the sense that
    > implementations will approximate JSON numbers within the expected
    > precision.

    This implementation does exactly follow this approach, as it uses double
    precision floating-point numbers. Note values smaller than
    `-1.79769313486232e+308` and values greater than `1.79769313486232e+308`
    will be stored as NaN internally and be serialized to `null`.

    #### Storage

    Floating-point number values are stored directly inside a @ref basic_json
    type.

    @sa @ref number_integer_t -- type for number values (integer)

    @sa @ref number_unsigned_t -- type for number values (unsigned integer)

    @since version 1.0.0
    */
    using number_float_t = NumberFloatType;

    /// @}


    ///////////////////////////
    // JSON type enumeration //
    ///////////////////////////

    /*!
    @brief the JSON type enumeration

    This enumeration collects the different JSON types. It is internally used
    to distinguish the stored values, and the functions @ref is_null(), @ref
    is_object(), @ref is_array(), @ref is_string(), @ref is_boolean(), @ref
    is_number(), and @ref is_discarded() rely on it.

    @since version 1.0.0
    */
    enum class value_t : uint8_t
    {
        null,            ///< null value
        object,          ///< object (unordered set of name/value pairs)
        array,           ///< array (ordered collection of values)
        string,          ///< string value
        boolean,         ///< boolean value
        number_integer,  ///< number value (integer)
        number_unsigned, ///< number value (unsigned integer)
        number_float,    ///< number value (floating-point)
        discarded        ///< discarded by the the parser callback function
    };


  private:

    /*!
    @brief a type to hold JSON type information

    This bitfield type holds information about JSON types. It is internally
    used to hold the basic JSON type enumeration, as well as additional
    information in the case of values that have been parsed from a string
    including whether of not it was created directly or parsed, and in the
    case of floating point numbers the number of significant figures in the
    original representaiton and if it was in exponential form, if a '+' was
    included in the exponent and the capitilization of the exponent marker.
    The sole purpose of this information is to permit accurate round trips.

    @since version 2.0.0
    */
    union type_data_t
    {
        struct
        {
            /// the type of the value (@ref value_t)
            uint16_t type : 4;
            /// whether the number was parsed from a string
            uint16_t parsed : 1;
            /// whether parsed number contained an exponent ('e'/'E')
            uint16_t has_exp : 1;
            /// whether parsed number contained a plus in the exponent
            uint16_t exp_plus : 1;
            /// whether parsed number's exponent was capitalized ('E')
            uint16_t exp_cap : 1;
            /// the number of figures for a parsed number
            uint16_t precision : 8;
        } bits;
        uint16_t data;

        /// return the type as value_t
        operator value_t() const
        {
            return static_cast<value_t>(bits.type);
        }

        /// test type for equality (ignore other fields)
        bool operator==(const value_t& rhs) const
        {
            return static_cast<value_t>(bits.type) == rhs;
        }

        /// assignment
        type_data_t& operator=(value_t rhs)
        {
            bits.type = static_cast<uint16_t>(rhs);
            return *this;
        }

        /// construct from value_t
        type_data_t(value_t t) noexcept
        {
            *reinterpret_cast<uint16_t*>(this) = 0;
            bits.type = static_cast<uint16_t>(t);
        }

        /// default constructor
        type_data_t() noexcept
        {
            data = 0;
            bits.type = reinterpret_cast<uint16_t>(value_t::null);
        }
    };

    /// helper for exception-safe object creation
    template<typename T, typename... Args>
    static T* create(Args&& ... args)
    {
        AllocatorType<T> alloc;
        auto deleter = [&](T * object)
        {
            alloc.deallocate(object, 1);
        };
        std::unique_ptr<T, decltype(deleter)> object(alloc.allocate(1), deleter);
        alloc.construct(object.get(), std::forward<Args>(args)...);
        return object.release();
    }

    ////////////////////////
    // JSON value storage //
    ////////////////////////

    /*!
    @brief a JSON value

    The actual storage for a JSON value of the @ref basic_json class.

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

                default:
                {
                    break;
                }
            }
        }

        /// constructor for strings
        json_value(const string_t& value)
        {
            string = create<string_t>(value);
        }

        /// constructor for objects
        json_value(const object_t& value)
        {
            object = create<object_t>(value);
        }

        /// constructor for arrays
        json_value(const array_t& value)
        {
            array = create<array_t>(value);
        }
    };


  public:
    //////////////////////////
    // JSON parser callback //
    //////////////////////////

    /*!
    @brief JSON callback events

    This enumeration lists the parser events that can trigger calling a
    callback function of type @ref parser_callback_t during parsing.

    @since version 1.0.0
    */
    enum class parse_event_t : uint8_t
    {
        /// the parser read `{` and started to process a JSON object
        object_start,
        /// the parser read `}` and finished processing a JSON object
        object_end,
        /// the parser read `[` and started to process a JSON array
        array_start,
        /// the parser read `]` and finished processing a JSON array
        array_end,
        /// the parser read a key of a value in an object
        key,
        /// the parser finished reading a JSON value
        value
    };

    /*!
    @brief per-element parser callback type

    With a parser callback function, the result of parsing a JSON text can be
    influenced. When passed to @ref parse(std::istream&, parser_callback_t) or
    @ref parse(const string_t&, parser_callback_t), it is called on certain
    events (passed as @ref parse_event_t via parameter @a event) with a set
    recursion depth @a depth and context JSON value @a parsed. The return value
    of the callback function is a boolean indicating whether the element that
    emitted the callback shall be kept or not.

    We distinguish six scenarios (determined by the event type) in which the
    callback function can be called. The following table describes the values
    of the parameters @a depth, @a event, and @a parsed.

    parameter @a event | description | parameter @a depth | parameter @a parsed
    ------------------ | ----------- | ------------------ | -------------------
    parse_event_t::object_start | the parser read `{` and started to process a JSON object | depth of the parent of the JSON object | a JSON value with type discarded
    parse_event_t::key | the parser read a key of a value in an object | depth of the currently parsed JSON object | a JSON string containing the key
    parse_event_t::object_end | the parser read `}` and finished processing a JSON object | depth of the parent of the JSON object | the parsed JSON object
    parse_event_t::array_start | the parser read `[` and started to process a JSON array | depth of the parent of the JSON array | a JSON value with type discarded
    parse_event_t::array_end | the parser read `]` and finished processing a JSON array | depth of the parent of the JSON array | the parsed JSON array
    parse_event_t::value | the parser finished reading a JSON value | depth of the value | the parsed JSON value

    Discarding a value (i.e., returning `false`) has different effects
    depending on the context in which function was called:

    - Discarded values in structured types are skipped. That is, the parser
      will behave as if the discarded value was never read.
    - In case a value outside a structured type is skipped, it is replaced with
      `null`. This case happens if the top-level element is skipped.

    @param[in] depth  the depth of the recursion during parsing

    @param[in] event  an event of type parse_event_t indicating the context in
    the callback function has been called

    @param[in,out] parsed  the current intermediate parse result; note that
    writing to this value has no effect for parse_event_t::key events

    @return Whether the JSON value which called the function during parsing
    should be kept (`true`) or not (`false`). In the latter case, it is either
    skipped completely or replaced by an empty discarded object.

    @sa @ref parse(std::istream&, parser_callback_t) or
    @ref parse(const string_t&, parser_callback_t) for examples

    @since version 1.0.0
    */
    using parser_callback_t = std::function<bool(int depth, parse_event_t event, basic_json& parsed)>;


    //////////////////
    // constructors //
    //////////////////

    /// @name constructors and destructors
    /// @{

    /*!
    @brief create an empty value with a given type

    Create an empty JSON value with a given type. The value will be default
    initialized with an empty value which depends on the type:

    Value type  | initial value
    ----------- | -------------
    null        | `null`
    boolean     | `false`
    string      | `""`
    number      | `0`
    object      | `{}`
    array       | `[]`

    @param[in] value_type  the type of the value to create

    @complexity Constant.

    @throw std::bad_alloc if allocation for object, array, or string value
    fails

    @liveexample{The following code shows the constructor for different @ref
    value_t values,basic_json__value_t}

    @sa @ref basic_json(std::nullptr_t) -- create a `null` value
    @sa @ref basic_json(boolean_t value) -- create a boolean value
    @sa @ref basic_json(const string_t&) -- create a string value
    @sa @ref basic_json(const object_t&) -- create a object value
    @sa @ref basic_json(const array_t&) -- create a array value
    @sa @ref basic_json(const number_float_t) -- create a number
    (floating-point) value
    @sa @ref basic_json(const number_integer_t) -- create a number (integer)
    value
    @sa @ref basic_json(const number_unsigned_t) -- create a number (unsigned)
    value

    @since version 1.0.0
    */
    basic_json(const value_t value_type)
        : m_type(value_type), m_value(value_type)
    {}

    /*!
    @brief create a null object (implicitly)

    Create a `null` JSON value. This is the implicit version of the `null`
    value constructor as it takes no parameters.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this constructor never throws
    exceptions.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - As postcondition, it holds: `basic_json().empty() == true`.

    @liveexample{The following code shows the constructor for a `null` JSON
    value.,basic_json}

    @sa @ref basic_json(std::nullptr_t) -- create a `null` value

    @since version 1.0.0
    */
    basic_json() = default;

    /*!
    @brief create a null object (explicitly)

    Create a `null` JSON value. This is the explicitly version of the `null`
    value constructor as it takes a null pointer as parameter. It allows to
    create `null` values by explicitly assigning a `nullptr` to a JSON value.
    The passed null pointer itself is not read -- it is only used to choose the
    right constructor.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this constructor never throws
    exceptions.

    @liveexample{The following code shows the constructor with null pointer
    parameter.,basic_json__nullptr_t}

    @sa @ref basic_json() -- default constructor (implicitly creating a `null`
    value)

    @since version 1.0.0
    */
    basic_json(std::nullptr_t) noexcept
        : basic_json(value_t::null)
    {}

    /*!
    @brief create an object (explicit)

    Create an object JSON value with a given content.

    @param[in] val  a value for the object

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for object value fails

    @liveexample{The following code shows the constructor with an @ref object_t
    parameter.,basic_json__object_t}

    @sa @ref basic_json(const CompatibleObjectType&) -- create an object value
    from a compatible STL container

    @since version 1.0.0
    */
    basic_json(const object_t& val)
        : m_type(value_t::object), m_value(val)
    {}

    /*!
    @brief create an object (implicit)

    Create an object JSON value with a given content. This constructor allows
    any type @a CompatibleObjectType that can be used to construct values of
    type @ref object_t.

    @tparam CompatibleObjectType An object type whose `key_type` and
    `value_type` is compatible to @ref object_t. Examples include `std::map`,
    `std::unordered_map`, `std::multimap`, and `std::unordered_multimap` with
    a `key_type` of `std::string`, and a `value_type` from which a @ref
    basic_json value can be constructed.

    @param[in] val  a value for the object

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for object value fails

    @liveexample{The following code shows the constructor with several
    compatible object type parameters.,basic_json__CompatibleObjectType}

    @sa @ref basic_json(const object_t&) -- create an object value

    @since version 1.0.0
    */
    template <class CompatibleObjectType, typename
              std::enable_if<
                  std::is_constructible<typename object_t::key_type, typename CompatibleObjectType::key_type>::value and
                  std::is_constructible<basic_json, typename CompatibleObjectType::mapped_type>::value, int>::type
              = 0>
    basic_json(const CompatibleObjectType& val)
        : m_type(value_t::object)
    {
        using std::begin;
        using std::end;
        m_value.object = create<object_t>(begin(val), end(val));
    }

    /*!
    @brief create an array (explicit)

    Create an array JSON value with a given content.

    @param[in] val  a value for the array

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for array value fails

    @liveexample{The following code shows the constructor with an @ref array_t
    parameter.,basic_json__array_t}

    @sa @ref basic_json(const CompatibleArrayType&) -- create an array value
    from a compatible STL containers

    @since version 1.0.0
    */
    basic_json(const array_t& val)
        : m_type(value_t::array), m_value(val)
    {}

    /*!
    @brief create an array (implicit)

    Create an array JSON value with a given content. This constructor allows
    any type @a CompatibleArrayType that can be used to construct values of
    type @ref array_t.

    @tparam CompatibleArrayType An object type whose `value_type` is compatible
    to @ref array_t. Examples include `std::vector`, `std::deque`, `std::list`,
    `std::forward_list`, `std::array`, `std::set`, `std::unordered_set`,
    `std::multiset`, and `unordered_multiset` with a `value_type` from which a
    @ref basic_json value can be constructed.

    @param[in] val  a value for the array

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for array value fails

    @liveexample{The following code shows the constructor with several
    compatible array type parameters.,basic_json__CompatibleArrayType}

    @sa @ref basic_json(const array_t&) -- create an array value

    @since version 1.0.0
    */
    template <class CompatibleArrayType, typename
              std::enable_if<
                  not std::is_same<CompatibleArrayType, typename basic_json_t::iterator>::value and
                  not std::is_same<CompatibleArrayType, typename basic_json_t::const_iterator>::value and
                  not std::is_same<CompatibleArrayType, typename basic_json_t::reverse_iterator>::value and
                  not std::is_same<CompatibleArrayType, typename basic_json_t::const_reverse_iterator>::value and
                  not std::is_same<CompatibleArrayType, typename array_t::iterator>::value and
                  not std::is_same<CompatibleArrayType, typename array_t::const_iterator>::value and
                  std::is_constructible<basic_json, typename CompatibleArrayType::value_type>::value, int>::type
              = 0>
    basic_json(const CompatibleArrayType& val)
        : m_type(value_t::array)
    {
        using std::begin;
        using std::end;
        m_value.array = create<array_t>(begin(val), end(val));
    }

    /*!
    @brief create a string (explicit)

    Create an string JSON value with a given content.

    @param[in] val  a value for the string

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for string value fails

    @liveexample{The following code shows the constructor with an @ref string_t
    parameter.,basic_json__string_t}

    @sa @ref basic_json(const typename string_t::value_type*) -- create a
    string value from a character pointer
    @sa @ref basic_json(const CompatibleStringType&) -- create a string value
    from a compatible string container

    @since version 1.0.0
    */
    basic_json(const string_t& val)
        : m_type(value_t::string), m_value(val)
    {}

    /*!
    @brief create a string (explicit)

    Create a string JSON value with a given content.

    @param[in] val  a literal value for the string

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for string value fails

    @liveexample{The following code shows the constructor with string literal
    parameter.,basic_json__string_t_value_type}

    @sa @ref basic_json(const string_t&) -- create a string value
    @sa @ref basic_json(const CompatibleStringType&) -- create a string value
    from a compatible string container

    @since version 1.0.0
    */
    basic_json(const typename string_t::value_type* val)
        : basic_json(string_t(val))
    {}

    /*!
    @brief create a string (implicit)

    Create a string JSON value with a given content.

    @param[in] val  a value for the string

    @tparam CompatibleStringType an string type which is compatible to @ref
    string_t, for instance `std::string`.

    @complexity Linear in the size of the passed @a val.

    @throw std::bad_alloc if allocation for string value fails

    @liveexample{The following code shows the construction of a string value
    from a compatible type.,basic_json__CompatibleStringType}

    @sa @ref basic_json(const string_t&) -- create a string value
    @sa @ref basic_json(const typename string_t::value_type*) -- create a
    string value from a character pointer

    @since version 1.0.0
    */
    template <class CompatibleStringType, typename
              std::enable_if<
                  std::is_constructible<string_t, CompatibleStringType>::value, int>::type
              = 0>
    basic_json(const CompatibleStringType& val)
        : basic_json(string_t(val))
    {}

    /*!
    @brief create a boolean (explicit)

    Creates a JSON boolean type from a given value.

    @param[in] val  a boolean value to store

    @complexity Constant.

    @liveexample{The example below demonstrates boolean
    values.,basic_json__boolean_t}

    @since version 1.0.0
    */
    basic_json(boolean_t val) noexcept
        : m_type(value_t::boolean), m_value(val)
    {}

    /*!
    @brief create an integer number (explicit)

    Create an integer number JSON value with a given content.

    @tparam T A helper type to remove this function via SFINAE in case @ref
    number_integer_t is the same as `int`. In this case, this constructor would
    have the same signature as @ref basic_json(const int value). Note the
    helper type @a T is not visible in this constructor's interface.

    @param[in] val  an integer to create a JSON number from

    @complexity Constant.

    @liveexample{The example below shows the construction of an integer
    number value.,basic_json__number_integer_t}

    @sa @ref basic_json(const int) -- create a number value (integer)
    @sa @ref basic_json(const CompatibleNumberIntegerType) -- create a number
    value (integer) from a compatible number type

    @since version 1.0.0
    */
    template<typename T,
             typename std::enable_if<
                 not (std::is_same<T, int>::value)
                 and std::is_same<T, number_integer_t>::value
                 , int>::type
             = 0>
    basic_json(const number_integer_t val) noexcept
        : m_type(value_t::number_integer), m_value(val)
    {}

    /*!
    @brief create an integer number from an enum type (explicit)

    Create an integer number JSON value with a given content.

    @param[in] val  an integer to create a JSON number from

    @note This constructor allows to pass enums directly to a constructor. As
    C++ has no way of specifying the type of an anonymous enum explicitly, we
    can only rely on the fact that such values implicitly convert to int. As
    int may already be the same type of number_integer_t, we may need to switch
    off the constructor @ref basic_json(const number_integer_t).

    @complexity Constant.

    @liveexample{The example below shows the construction of an integer
    number value from an anonymous enum.,basic_json__const_int}

    @sa @ref basic_json(const number_integer_t) -- create a number value
    (integer)
    @sa @ref basic_json(const CompatibleNumberIntegerType) -- create a number
    value (integer) from a compatible number type

    @since version 1.0.0
    */
    basic_json(const int val) noexcept
        : m_type(value_t::number_integer),
          m_value(static_cast<number_integer_t>(val))
    {}

    /*!
    @brief create an integer number (implicit)

    Create an integer number JSON value with a given content. This constructor
    allows any type @a CompatibleNumberIntegerType that can be used to
    construct values of type @ref number_integer_t.

    @tparam CompatibleNumberIntegerType An integer type which is compatible to
    @ref number_integer_t. Examples include the types `int`, `int32_t`, `long`,
    and `short`.

    @param[in] val  an integer to create a JSON number from

    @complexity Constant.

    @liveexample{The example below shows the construction of several integer
    number values from compatible
    types.,basic_json__CompatibleIntegerNumberType}

    @sa @ref basic_json(const number_integer_t) -- create a number value
    (integer)
    @sa @ref basic_json(const int) -- create a number value (integer)

    @since version 1.0.0
    */
    template<typename CompatibleNumberIntegerType, typename
             std::enable_if<
                 std::is_constructible<number_integer_t, CompatibleNumberIntegerType>::value and
                 std::numeric_limits<CompatibleNumberIntegerType>::is_integer and
                 std::numeric_limits<CompatibleNumberIntegerType>::is_signed,
                 CompatibleNumberIntegerType>::type
             = 0>
    basic_json(const CompatibleNumberIntegerType val) noexcept
        : m_type(value_t::number_integer),
          m_value(static_cast<number_integer_t>(val))
    {}

    /*!
    @brief create an unsigned integer number (explicit)

    Create an unsigned integer number JSON value with a given content.

    @tparam T  helper type to compare number_unsigned_t and unsigned int
    (not visible in) the interface.

    @param[in] val  an integer to create a JSON number from

    @complexity Constant.

    @sa @ref basic_json(const CompatibleNumberUnsignedType) -- create a number
    value (unsigned integer) from a compatible number type

    @since version 2.0.0
    */
    template<typename T,
             typename std::enable_if<
                 not (std::is_same<T, int>::value)
                 and std::is_same<T, number_unsigned_t>::value
                 , int>::type
             = 0>
    basic_json(const number_unsigned_t val) noexcept
        : m_type(value_t::number_unsigned), m_value(val)
    {}

    /*!
    @brief create an unsigned number (implicit)

    Create an unsigned number JSON value with a given content. This constructor
    allows any type @a CompatibleNumberUnsignedType that can be used to
    construct values of type @ref number_unsigned_t.

    @tparam CompatibleNumberUnsignedType An integer type which is compatible to
    @ref number_unsigned_t. Examples may include the types `unsigned int`,
    `uint32_t`, or `unsigned short`.

    @param[in] val  an unsigned integer to create a JSON number from

    @complexity Constant.

    @sa @ref basic_json(const number_unsigned_t) -- create a number value
    (unsigned)

    @since version 2.0.0
    */
    template < typename CompatibleNumberUnsignedType, typename
               std::enable_if <
                   std::is_constructible<number_unsigned_t, CompatibleNumberUnsignedType>::value and
                   std::numeric_limits<CompatibleNumberUnsignedType>::is_integer and
                   !std::numeric_limits<CompatibleNumberUnsignedType>::is_signed,
                   CompatibleNumberUnsignedType >::type
               = 0 >
    basic_json(const CompatibleNumberUnsignedType val) noexcept
        : m_type(value_t::number_unsigned),
          m_value(static_cast<number_unsigned_t>(val))
    {}

    /*!
    @brief create a floating-point number (explicit)

    Create a floating-point number JSON value with a given content.

    @param[in] val  a floating-point value to create a JSON number from

    @note [RFC 7159](http://www.rfc-editor.org/rfc/rfc7159.txt), section 6
    disallows NaN values:
    > Numeric values that cannot be represented in the grammar below (such
    > as Infinity and NaN) are not permitted.
    In case the parameter @a val is not a number, a JSON null value is
    created instead.

    @complexity Constant.

    @liveexample{The following example creates several floating-point
    values.,basic_json__number_float_t}

    @sa @ref basic_json(const CompatibleNumberFloatType) -- create a number
    value (floating-point) from a compatible number type

    @since version 1.0.0
    */
    basic_json(const number_float_t val) noexcept
        : m_type(value_t::number_float), m_value(val)
    {
        // replace infinity and NAN by null
        if (not std::isfinite(val))
        {
            m_type = value_t::null;
            m_value = json_value();
        }
    }

    /*!
    @brief create an floating-point number (implicit)

    Create an floating-point number JSON value with a given content. This
    constructor allows any type @a CompatibleNumberFloatType that can be used
    to construct values of type @ref number_float_t.

    @tparam CompatibleNumberFloatType A floating-point type which is compatible
    to @ref number_float_t. Examples may include the types `float` or `double`.

    @param[in] val  a floating-point to create a JSON number from

    @note [RFC 7159](http://www.rfc-editor.org/rfc/rfc7159.txt), section 6
    disallows NaN values:
    > Numeric values that cannot be represented in the grammar below (such
    > as Infinity and NaN) are not permitted.
    In case the parameter @a val is not a number, a JSON null value is
    created instead.

    @complexity Constant.

    @liveexample{The example below shows the construction of several
    floating-point number values from compatible
    types.,basic_json__CompatibleNumberFloatType}

    @sa @ref basic_json(const number_float_t) -- create a number value
    (floating-point)

    @since version 1.0.0
    */
    template<typename CompatibleNumberFloatType, typename = typename
             std::enable_if<
                 std::is_constructible<number_float_t, CompatibleNumberFloatType>::value and
                 std::is_floating_point<CompatibleNumberFloatType>::value>::type
             >
    basic_json(const CompatibleNumberFloatType val) noexcept
        : basic_json(number_float_t(val))
    {}

    /*!
    @brief create a container (array or object) from an initializer list

    Creates a JSON value of type array or object from the passed initializer
    list @a init. In case @a type_deduction is `true` (default), the type of
    the JSON value to be created is deducted from the initializer list @a init
    according to the following rules:

    1. If the list is empty, an empty JSON object value `{}` is created.
    2. If the list consists of pairs whose first element is a string, a JSON
    object value is created where the first elements of the pairs are treated
    as keys and the second elements are as values.
    3. In all other cases, an array is created.

    The rules aim to create the best fit between a C++ initializer list and
    JSON values. The rationale is as follows:

    1. The empty initializer list is written as `{}` which is exactly an empty
    JSON object.
    2. C++ has now way of describing mapped types other than to list a list of
    pairs. As JSON requires that keys must be of type string, rule 2 is the
    weakest constraint one can pose on initializer lists to interpret them as
    an object.
    3. In all other cases, the initializer list could not be interpreted as
    JSON object type, so interpreting it as JSON array type is safe.

    With the rules described above, the following JSON values cannot be
    expressed by an initializer list:

    - the empty array (`[]`): use @ref array(std::initializer_list<basic_json>)
      with an empty initializer list in this case
    - arrays whose elements satisfy rule 2: use @ref
      array(std::initializer_list<basic_json>) with the same initializer list
      in this case

    @note When used without parentheses around an empty initializer list, @ref
    basic_json() is called instead of this function, yielding the JSON null
    value.

    @param[in] init  initializer list with JSON values

    @param[in] type_deduction internal parameter; when set to `true`, the type
    of the JSON value is deducted from the initializer list @a init; when set
    to `false`, the type provided via @a manual_type is forced. This mode is
    used by the functions @ref array(std::initializer_list<basic_json>) and
    @ref object(std::initializer_list<basic_json>).

    @param[in] manual_type internal parameter; when @a type_deduction is set to
    `false`, the created JSON value will use the provided type (only @ref
    value_t::array and @ref value_t::object are valid); when @a type_deduction
    is set to `true`, this parameter has no effect

    @throw std::domain_error if @a type_deduction is `false`, @a manual_type is
    `value_t::object`, but @a init contains an element which is not a pair
    whose first element is a string; example: `"cannot create object from
    initializer list"`

    @complexity Linear in the size of the initializer list @a init.

    @liveexample{The example below shows how JSON values are created from
    initializer lists.,basic_json__list_init_t}

    @sa @ref array(std::initializer_list<basic_json>) -- create a JSON array
    value from an initializer list
    @sa @ref object(std::initializer_list<basic_json>) -- create a JSON object
    value from an initializer list

    @since version 1.0.0
    */
    basic_json(std::initializer_list<basic_json> init,
               bool type_deduction = true,
               value_t manual_type = value_t::array)
    {
        // the initializer list could describe an object
        bool is_an_object = true;

        // check if each element is an array with two elements whose first
        // element is a string
        for (const auto& element : init)
        {
            if (not element.is_array() or element.size() != 2
                    or not element[0].is_string())
            {
                // we found an element that makes it impossible to use the
                // initializer list as object
                is_an_object = false;
                break;
            }
        }

        // adjust type if type deduction is not wanted
        if (not type_deduction)
        {
            // if array is wanted, do not create an object though possible
            if (manual_type == value_t::array)
            {
                is_an_object = false;
            }

            // if object is wanted but impossible, throw an exception
            if (manual_type == value_t::object and not is_an_object)
            {
                throw std::domain_error("cannot create object from initializer list");
            }
        }

        if (is_an_object)
        {
            // the initializer list is a list of pairs -> create object
            m_type = value_t::object;
            m_value = value_t::object;

            assert(m_value.object != nullptr);

            for (auto& element : init)
            {
                m_value.object->emplace(*(element[0].m_value.string), element[1]);
            }
        }
        else
        {
            // the initializer list describes an array -> create array
            m_type = value_t::array;
            m_value.array = create<array_t>(init);
        }
    }

    /*!
    @brief explicitly create an array from an initializer list

    Creates a JSON array value from a given initializer list. That is, given a
    list of values `a, b, c`, creates the JSON value `[a, b, c]`. If the
    initializer list is empty, the empty array `[]` is created.

    @note This function is only needed to express two edge cases that cannot be
    realized with the initializer list constructor (@ref
    basic_json(std::initializer_list<basic_json>, bool, value_t)). These cases
    are:
    1. creating an array whose elements are all pairs whose first element is a
    string -- in this case, the initializer list constructor would create an
    object, taking the first elements as keys
    2. creating an empty array -- passing the empty initializer list to the
    initializer list constructor yields an empty object

    @param[in] init  initializer list with JSON values to create an array from
    (optional)

    @return JSON array value

    @complexity Linear in the size of @a init.

    @liveexample{The following code shows an example for the `array`
    function.,array}

    @sa @ref basic_json(std::initializer_list<basic_json>, bool, value_t) --
    create a JSON value from an initializer list
    @sa @ref object(std::initializer_list<basic_json>) -- create a JSON object
    value from an initializer list

    @since version 1.0.0
    */
    static basic_json array(std::initializer_list<basic_json> init =
                                std::initializer_list<basic_json>())
    {
        return basic_json(init, false, value_t::array);
    }

    /*!
    @brief explicitly create an object from an initializer list

    Creates a JSON object value from a given initializer list. The initializer
    lists elements must be pairs, and their first elements must be strings. If
    the initializer list is empty, the empty object `{}` is created.

    @note This function is only added for symmetry reasons. In contrast to the
    related function @ref array(std::initializer_list<basic_json>), there are
    no cases which can only be expressed by this function. That is, any
    initializer list @a init can also be passed to the initializer list
    constructor
    @ref basic_json(std::initializer_list<basic_json>, bool, value_t).

    @param[in] init  initializer list to create an object from (optional)

    @return JSON object value

    @throw std::domain_error if @a init is not a pair whose first elements are
    strings; thrown by
    @ref basic_json(std::initializer_list<basic_json>, bool, value_t)

    @complexity Linear in the size of @a init.

    @liveexample{The following code shows an example for the `object`
    function.,object}

    @sa @ref basic_json(std::initializer_list<basic_json>, bool, value_t) --
    create a JSON value from an initializer list
    @sa @ref array(std::initializer_list<basic_json>) -- create a JSON array
    value from an initializer list

    @since version 1.0.0
    */
    static basic_json object(std::initializer_list<basic_json> init =
                                 std::initializer_list<basic_json>())
    {
        return basic_json(init, false, value_t::object);
    }

    /*!
    @brief construct an array with count copies of given value

    Constructs a JSON array value by creating @a cnt copies of a passed
    value. In case @a cnt is `0`, an empty array is created. As postcondition,
    `std::distance(begin(),end()) == cnt` holds.

    @param[in] cnt  the number of JSON copies of @a val to create
    @param[in] val  the JSON value to copy

    @complexity Linear in @a cnt.

    @liveexample{The following code shows examples for the @ref
    basic_json(size_type\, const basic_json&)
    constructor.,basic_json__size_type_basic_json}

    @since version 1.0.0
    */
    basic_json(size_type cnt, const basic_json& val)
        : m_type(value_t::array)
    {
        m_value.array = create<array_t>(cnt, val);
    }

    /*!
    @brief construct a JSON container given an iterator range

    Constructs the JSON value with the contents of the range `[first, last)`.
    The semantics depends on the different types a JSON value can have:
    - In case of primitive types (number, boolean, or string), @a first must
      be `begin()` and @a last must be `end()`. In this case, the value is
      copied. Otherwise, std::out_of_range is thrown.
    - In case of structured types (array, object), the constructor behaves
      as similar versions for `std::vector`.
    - In case of a null type, std::domain_error is thrown.

    @tparam InputIT an input iterator type (@ref iterator or @ref
    const_iterator)

    @param[in] first begin of the range to copy from (included)
    @param[in] last end of the range to copy from (excluded)

    @throw std::domain_error if iterators are not compatible; that is, do not
    belong to the same JSON value; example: `"iterators are not compatible"`
    @throw std::out_of_range if iterators are for a primitive type (number,
    boolean, or string) where an out of range error can be detected easily;
    example: `"iterators out of range"`
    @throw std::bad_alloc if allocation for object, array, or string fails
    @throw std::domain_error if called with a null value; example: `"cannot use
    construct with iterators from null"`

    @complexity Linear in distance between @a first and @a last.

    @liveexample{The example below shows several ways to create JSON values by
    specifying a subrange with iterators.,basic_json__InputIt_InputIt}

    @since version 1.0.0
    */
    template <class InputIT, typename
              std::enable_if<
                  std::is_same<InputIT, typename basic_json_t::iterator>::value or
                  std::is_same<InputIT, typename basic_json_t::const_iterator>::value
                  , int>::type
              = 0>
    basic_json(InputIT first, InputIT last) : m_type(first.m_object->m_type)
    {
        // make sure iterator fits the current value
        if (first.m_object != last.m_object)
        {
            throw std::domain_error("iterators are not compatible");
        }

        // check if iterator range is complete for primitive values
        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (not first.m_it.primitive_iterator.is_begin() or not last.m_it.primitive_iterator.is_end())
                {
                    throw std::out_of_range("iterators out of range");
                }
                break;
            }

            default:
            {
                break;
            }
        }

        switch (m_type)
        {
            case value_t::number_integer:
            {
                assert(first.m_object != nullptr);
                m_value.number_integer = first.m_object->m_value.number_integer;
                break;
            }

            case value_t::number_unsigned:
            {
                assert(first.m_object != nullptr);
                m_value.number_unsigned = first.m_object->m_value.number_unsigned;
                break;
            }

            case value_t::number_float:
            {
                assert(first.m_object != nullptr);
                m_value.number_float = first.m_object->m_value.number_float;
                break;
            }

            case value_t::boolean:
            {
                assert(first.m_object != nullptr);
                m_value.boolean = first.m_object->m_value.boolean;
                break;
            }

            case value_t::string:
            {
                assert(first.m_object != nullptr);
                m_value = *first.m_object->m_value.string;
                break;
            }

            case value_t::object:
            {
                m_value.object = create<object_t>(first.m_it.object_iterator, last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                m_value.array = create<array_t>(first.m_it.array_iterator, last.m_it.array_iterator);
                break;
            }

            default:
            {
                assert(first.m_object != nullptr);
                throw std::domain_error("cannot use construct with iterators from " + first.m_object->type_name());
            }
        }
    }

    /*!
    @brief construct a JSON value given an input stream

    @param[in,out] i  stream to read a serialized JSON value from
    @param[in] cb a parser callback function of type @ref parser_callback_t
    which is used to control the deserialization by filtering unwanted values
    (optional)

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser. The complexity can be higher if the parser callback function
    @a cb has a super-linear complexity.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates constructing a JSON value from
    a `std::stringstream` with and without callback
    function.,basic_json__istream}

    @since version 2.0.0
    */
    explicit basic_json(std::istream& i, parser_callback_t cb = nullptr)
    {
        *this = parser(i, cb).parse();
    }

    ///////////////////////////////////////
    // other constructors and destructor //
    ///////////////////////////////////////

    /*!
    @brief copy constructor

    Creates a copy of a given JSON value.

    @param[in] other  the JSON value to copy

    @complexity Linear in the size of @a other.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is linear.
    - As postcondition, it holds: `other == basic_json(other)`.

    @throw std::bad_alloc if allocation for object, array, or string fails.

    @liveexample{The following code shows an example for the copy
    constructor.,basic_json__basic_json}

    @since version 1.0.0
    */
    basic_json(const basic_json& other)
        : m_type(other.m_type)
    {
        switch (m_type)
        {
            case value_t::object:
            {
                assert(other.m_value.object != nullptr);
                m_value = *other.m_value.object;
                break;
            }

            case value_t::array:
            {
                assert(other.m_value.array != nullptr);
                m_value = *other.m_value.array;
                break;
            }

            case value_t::string:
            {
                assert(other.m_value.string != nullptr);
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

            default:
            {
                break;
            }
        }
    }

    /*!
    @brief move constructor

    Move constructor. Constructs a JSON value with the contents of the given
    value @a other using move semantics. It "steals" the resources from @a
    other and leaves it as JSON null value.

    @param[in,out] other  value to move to this object

    @post @a other is a JSON null value

    @complexity Constant.

    @liveexample{The code below shows the move constructor explicitly called
    via std::move.,basic_json__moveconstructor}

    @since version 1.0.0
    */
    basic_json(basic_json&& other) noexcept
        : m_type(std::move(other.m_type)),
          m_value(std::move(other.m_value))
    {
        // invalidate payload
        other.m_type = value_t::null;
        other.m_value = {};
    }

    /*!
    @brief copy assignment

    Copy assignment operator. Copies a JSON value via the "copy and swap"
    strategy: It is expressed in terms of the copy constructor, destructor, and
    the swap() member function.

    @param[in] other  value to copy from

    @complexity Linear.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is linear.

    @liveexample{The code below shows and example for the copy assignment. It
    creates a copy of value `a` which is then swapped with `b`. Finally\, the
    copy of `a` (which is the null value after the swap) is
    destroyed.,basic_json__copyassignment}

    @since version 1.0.0
    */
    reference& operator=(basic_json other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        using std::swap;
        swap(m_type, other.m_type);
        swap(m_value, other.m_value);
        return *this;
    }

    /*!
    @brief destructor

    Destroys the JSON value and frees all allocated memory.

    @complexity Linear.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is linear.
    - All stored elements are destroyed and all memory is freed.

    @since version 1.0.0
    */
    ~basic_json()
    {
        switch (m_type)
        {
            case value_t::object:
            {
                AllocatorType<object_t> alloc;
                alloc.destroy(m_value.object);
                alloc.deallocate(m_value.object, 1);
                break;
            }

            case value_t::array:
            {
                AllocatorType<array_t> alloc;
                alloc.destroy(m_value.array);
                alloc.deallocate(m_value.array, 1);
                break;
            }

            case value_t::string:
            {
                AllocatorType<string_t> alloc;
                alloc.destroy(m_value.string);
                alloc.deallocate(m_value.string, 1);
                break;
            }

            default:
            {
                // all other types need no specific destructor
                break;
            }
        }
    }

    /// @}

  public:
    ///////////////////////
    // object inspection //
    ///////////////////////

    /// @name object inspection
    /// @{

    /*!
    @brief serialization

    Serialization function for JSON values. The function tries to mimic
    Python's @p json.dumps() function, and currently supports its @p indent
    parameter.

    @param[in] indent if indent is nonnegative, then array elements and object
    members will be pretty-printed with that indent level. An indent level of 0
    will only insert newlines. -1 (the default) selects the most compact
    representation

    @return string containing the serialization of the JSON value

    @complexity Linear.

    @liveexample{The following example shows the effect of different @a indent
    parameters to the result of the serialization.,dump}

    @see https://docs.python.org/2/library/json.html#json.dump

    @since version 1.0.0
    */
    string_t dump(const int indent = -1) const
    {
        std::stringstream ss;

        if (indent >= 0)
        {
            dump(ss, true, static_cast<unsigned int>(indent));
        }
        else
        {
            dump(ss, false, 0);
        }

        return ss.str();
    }

    /*!
    @brief return the type of the JSON value (explicit)

    Return the type of the JSON value as a value from the @ref value_t
    enumeration.

    @return the type of the JSON value

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `type()` for all JSON
    types.,type}

    @since version 1.0.0
    */
    constexpr value_t type() const noexcept
    {
        return m_type;
    }

    /*!
    @brief return whether type is primitive

    This function returns true iff the JSON type is primitive (string, number,
    boolean, or null).

    @return `true` if type is primitive (string, number, boolean, or null),
    `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_primitive()` for all JSON
    types.,is_primitive}

    @sa @ref is_structured() -- returns whether JSON value is structured
    @sa @ref is_null() -- returns whether JSON value is `null`
    @sa @ref is_string() -- returns whether JSON value is a string
    @sa @ref is_boolean() -- returns whether JSON value is a boolean
    @sa @ref is_number() -- returns whether JSON value is a number

    @since version 1.0.0
    */
    constexpr bool is_primitive() const noexcept
    {
        return is_null() or is_string() or is_boolean() or is_number();
    }

    /*!
    @brief return whether type is structured

    This function returns true iff the JSON type is structured (array or
    object).

    @return `true` if type is structured (array or object), `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_structured()` for all JSON
    types.,is_structured}

    @sa @ref is_primitive() -- returns whether value is primitive
    @sa @ref is_array() -- returns whether value is an array
    @sa @ref is_object() -- returns whether value is an object

    @since version 1.0.0
    */
    constexpr bool is_structured() const noexcept
    {
        return is_array() or is_object();
    }

    /*!
    @brief return whether value is null

    This function returns true iff the JSON value is null.

    @return `true` if type is null, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_null()` for all JSON
    types.,is_null}

    @since version 1.0.0
    */
    constexpr bool is_null() const noexcept
    {
        return m_type == value_t::null;
    }

    /*!
    @brief return whether value is a boolean

    This function returns true iff the JSON value is a boolean.

    @return `true` if type is boolean, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_boolean()` for all JSON
    types.,is_boolean}

    @since version 1.0.0
    */
    constexpr bool is_boolean() const noexcept
    {
        return m_type == value_t::boolean;
    }

    /*!
    @brief return whether value is a number

    This function returns true iff the JSON value is a number. This includes
    both integer and floating-point values.

    @return `true` if type is number (regardless whether integer, unsigned
    integer or floating-type), `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_number()` for all JSON
    types.,is_number}

    @sa @ref is_number_integer() -- check if value is an integer or unsigned
    integer number
    @sa @ref is_number_unsigned() -- check if value is an unsigned integer
    number
    @sa @ref is_number_float() -- check if value is a floating-point number

    @since version 1.0.0
    */
    constexpr bool is_number() const noexcept
    {
        return is_number_integer() or is_number_float();
    }

    /*!
    @brief return whether value is an integer number

    This function returns true iff the JSON value is an integer or unsigned
    integer number. This excludes floating-point values.

    @return `true` if type is an integer or unsigned integer number, `false`
    otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_number_integer()` for all
    JSON types.,is_number_integer}

    @sa @ref is_number() -- check if value is a number
    @sa @ref is_number_unsigned() -- check if value is an unsigned integer
    number
    @sa @ref is_number_float() -- check if value is a floating-point number

    @since version 1.0.0
    */
    constexpr bool is_number_integer() const noexcept
    {
        return m_type == value_t::number_integer or m_type == value_t::number_unsigned;
    }

    /*!
    @brief return whether value is an unsigned integer number

    This function returns true iff the JSON value is an unsigned integer
    number. This excludes floating-point and (signed) integer values.

    @return `true` if type is an unsigned integer number, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_number_unsigned()` for all
    JSON types.,is_number_unsigned}

    @sa @ref is_number() -- check if value is a number
    @sa @ref is_number_integer() -- check if value is an integer or unsigned
    integer number
    @sa @ref is_number_float() -- check if value is a floating-point number

    @since version 2.0.0
    */
    constexpr bool is_number_unsigned() const noexcept
    {
        return m_type == value_t::number_unsigned;
    }

    /*!
    @brief return whether value is a floating-point number

    This function returns true iff the JSON value is a floating-point number.
    This excludes integer and unsigned integer values.

    @return `true` if type is a floating-point number, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_number_float()` for all
    JSON types.,is_number_float}

    @sa @ref is_number() -- check if value is number
    @sa @ref is_number_integer() -- check if value is an integer number
    @sa @ref is_number_unsigned() -- check if value is an unsigned integer
    number

    @since version 1.0.0
    */
    constexpr bool is_number_float() const noexcept
    {
        return m_type == value_t::number_float;
    }

    /*!
    @brief return whether value is an object

    This function returns true iff the JSON value is an object.

    @return `true` if type is object, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_object()` for all JSON
    types.,is_object}

    @since version 1.0.0
    */
    constexpr bool is_object() const noexcept
    {
        return m_type == value_t::object;
    }

    /*!
    @brief return whether value is an array

    This function returns true iff the JSON value is an array.

    @return `true` if type is array, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_array()` for all JSON
    types.,is_array}

    @since version 1.0.0
    */
    constexpr bool is_array() const noexcept
    {
        return m_type == value_t::array;
    }

    /*!
    @brief return whether value is a string

    This function returns true iff the JSON value is a string.

    @return `true` if type is string, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_string()` for all JSON
    types.,is_string}

    @since version 1.0.0
    */
    constexpr bool is_string() const noexcept
    {
        return m_type == value_t::string;
    }

    /*!
    @brief return whether value is discarded

    This function returns true iff the JSON value was discarded during parsing
    with a callback function (see @ref parser_callback_t).

    @note This function will always be `false` for JSON values after parsing.
    That is, discarded values can only occur during parsing, but will be
    removed when inside a structured value or replaced by null in other cases.

    @return `true` if type is discarded, `false` otherwise.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies `is_discarded()` for all JSON
    types.,is_discarded}

    @since version 1.0.0
    */
    constexpr bool is_discarded() const noexcept
    {
        return m_type == value_t::discarded;
    }

    /*!
    @brief return the type of the JSON value (implicit)

    Implicitly return the type of the JSON value as a value from the @ref
    value_t enumeration.

    @return the type of the JSON value

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @liveexample{The following code exemplifies the @ref value_t operator for
    all JSON types.,operator__value_t}

    @since version 1.0.0
    */
    constexpr operator value_t() const noexcept
    {
        return m_type;
    }

    /// @}

  private:
    //////////////////
    // value access //
    //////////////////

    /// get an object (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<typename object_t::key_type, typename T::key_type>::value and
                  std::is_convertible<basic_json_t, typename T::mapped_type>::value
                  , int>::type = 0>
    T get_impl(T*) const
    {
        if (is_object())
        {
            assert(m_value.object != nullptr);
            return T(m_value.object->begin(), m_value.object->end());
        }
        else
        {
            throw std::domain_error("type must be object, but is " + type_name());
        }
    }

    /// get an object (explicit)
    object_t get_impl(object_t*) const
    {
        if (is_object())
        {
            assert(m_value.object != nullptr);
            return *(m_value.object);
        }
        else
        {
            throw std::domain_error("type must be object, but is " + type_name());
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<basic_json_t, typename T::value_type>::value and
                  not std::is_same<basic_json_t, typename T::value_type>::value and
                  not std::is_arithmetic<T>::value and
                  not std::is_convertible<std::string, T>::value and
                  not has_mapped_type<T>::value
                  , int>::type = 0>
    T get_impl(T*) const
    {
        if (is_array())
        {
            T to_vector;
            assert(m_value.array != nullptr);
            std::transform(m_value.array->begin(), m_value.array->end(),
                           std::inserter(to_vector, to_vector.end()), [](basic_json i)
            {
                return i.get<typename T::value_type>();
            });
            return to_vector;
        }
        else
        {
            throw std::domain_error("type must be array, but is " + type_name());
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<basic_json_t, T>::value and
                  not std::is_same<basic_json_t, T>::value
                  , int>::type = 0>
    std::vector<T> get_impl(std::vector<T>*) const
    {
        if (is_array())
        {
            std::vector<T> to_vector;
            assert(m_value.array != nullptr);
            to_vector.reserve(m_value.array->size());
            std::transform(m_value.array->begin(), m_value.array->end(),
                           std::inserter(to_vector, to_vector.end()), [](basic_json i)
            {
                return i.get<T>();
            });
            return to_vector;
        }
        else
        {
            throw std::domain_error("type must be array, but is " + type_name());
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_same<basic_json, typename T::value_type>::value and
                  not has_mapped_type<T>::value
                  , int>::type = 0>
    T get_impl(T*) const
    {
        if (is_array())
        {
            assert(m_value.array != nullptr);
            return T(m_value.array->begin(), m_value.array->end());
        }
        else
        {
            throw std::domain_error("type must be array, but is " + type_name());
        }
    }

    /// get an array (explicit)
    array_t get_impl(array_t*) const
    {
        if (is_array())
        {
            assert(m_value.array != nullptr);
            return *(m_value.array);
        }
        else
        {
            throw std::domain_error("type must be array, but is " + type_name());
        }
    }

    /// get a string (explicit)
    template <typename T, typename
              std::enable_if<
                  std::is_convertible<string_t, T>::value
                  , int>::type = 0>
    T get_impl(T*) const
    {
        if (is_string())
        {
            assert(m_value.string != nullptr);
            return *m_value.string;
        }
        else
        {
            throw std::domain_error("type must be string, but is " + type_name());
        }
    }

    /// get a number (explicit)
    template<typename T, typename
             std::enable_if<
                 std::is_arithmetic<T>::value
                 , int>::type = 0>
    T get_impl(T*) const
    {
        switch (m_type)
        {
            case value_t::number_integer:
            {
                return static_cast<T>(m_value.number_integer);
            }

            case value_t::number_unsigned:
            {
                return static_cast<T>(m_value.number_unsigned);
            }

            case value_t::number_float:
            {
                return static_cast<T>(m_value.number_float);
            }

            default:
            {
                throw std::domain_error("type must be number, but is " + type_name());
            }
        }
    }

    /// get a boolean (explicit)
    constexpr boolean_t get_impl(boolean_t*) const
    {
        return is_boolean()
               ? m_value.boolean
               : throw std::domain_error("type must be boolean, but is " + type_name());
    }

    /// get a pointer to the value (object)
    object_t* get_impl_ptr(object_t*) noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    /// get a pointer to the value (object)
    constexpr const object_t* get_impl_ptr(const object_t*) const noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    /// get a pointer to the value (array)
    array_t* get_impl_ptr(array_t*) noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    /// get a pointer to the value (array)
    constexpr const array_t* get_impl_ptr(const array_t*) const noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    /// get a pointer to the value (string)
    string_t* get_impl_ptr(string_t*) noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    /// get a pointer to the value (string)
    constexpr const string_t* get_impl_ptr(const string_t*) const noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    /// get a pointer to the value (boolean)
    boolean_t* get_impl_ptr(boolean_t*) noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    /// get a pointer to the value (boolean)
    constexpr const boolean_t* get_impl_ptr(const boolean_t*) const noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    /// get a pointer to the value (integer number)
    number_integer_t* get_impl_ptr(number_integer_t*) noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    /// get a pointer to the value (integer number)
    constexpr const number_integer_t* get_impl_ptr(const number_integer_t*) const noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    /// get a pointer to the value (unsigned number)
    number_unsigned_t* get_impl_ptr(number_unsigned_t*) noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    /// get a pointer to the value (unsigned number)
    constexpr const number_unsigned_t* get_impl_ptr(const number_unsigned_t*) const noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    /// get a pointer to the value (floating-point number)
    number_float_t* get_impl_ptr(number_float_t*) noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    /// get a pointer to the value (floating-point number)
    constexpr const number_float_t* get_impl_ptr(const number_float_t*) const noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    /*!
    @brief helper function to implement get_ref()

    This funcion helps to implement get_ref() without code duplication for
    const and non-const overloads

    @tparam ThisType will be deduced as `basic_json` or `const basic_json`

    @throw std::domain_error if ReferenceType does not match underlying value
    type of the current JSON
    */
    template<typename ReferenceType, typename ThisType>
    static ReferenceType get_ref_impl(ThisType& obj)
    {
        // delegate the call to get_ptr<>()
        using PointerType = typename std::add_pointer<ReferenceType>::type;
        auto ptr = obj.template get_ptr<PointerType>();

        if (ptr != nullptr)
        {
            return *ptr;
        }
        else
        {
            throw std::domain_error("incompatible ReferenceType for get_ref, actual type is " +
                                    obj.type_name());
        }
    }

  public:

    /// @name value access
    /// @{

    /*!
    @brief get a value (explicit)

    Explicit type conversion between the JSON value and a compatible value.

    @tparam ValueType non-pointer type compatible to the JSON value, for
    instance `int` for JSON integer numbers, `bool` for JSON booleans, or
    `std::vector` types for JSON arrays

    @return copy of the JSON value, converted to type @a ValueType

    @throw std::domain_error in case passed type @a ValueType is incompatible
    to JSON; example: `"type must be object, but is null"`

    @complexity Linear in the size of the JSON value.

    @liveexample{The example below shows several conversions from JSON values
    to other types. There a few things to note: (1) Floating-point numbers can
    be converted to integers\, (2) A JSON array can be converted to a standard
    `std::vector<short>`\, (3) A JSON object can be converted to C++
    associative containers such as `std::unordered_map<std::string\,
    json>`.,get__ValueType_const}

    @internal
    The idea of using a casted null pointer to choose the correct
    implementation is from <http://stackoverflow.com/a/8315197/266378>.
    @endinternal

    @sa @ref operator ValueType() const for implicit conversion
    @sa @ref get() for pointer-member access

    @since version 1.0.0
    */
    template<typename ValueType, typename
             std::enable_if<
                 not std::is_pointer<ValueType>::value
                 , int>::type = 0>
    ValueType get() const
    {
        return get_impl(static_cast<ValueType*>(nullptr));
    }

    /*!
    @brief get a pointer value (explicit)

    Explicit pointer access to the internally stored JSON value. No copies are
    made.

    @warning The pointer becomes invalid if the underlying JSON object changes.

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

    @sa @ref get_ptr() for explicit pointer-member access

    @since version 1.0.0
    */
    template<typename PointerType, typename
             std::enable_if<
                 std::is_pointer<PointerType>::value
                 , int>::type = 0>
    PointerType get() noexcept
    {
        // delegate the call to get_ptr
        return get_ptr<PointerType>();
    }

    /*!
    @brief get a pointer value (explicit)
    @copydoc get()
    */
    template<typename PointerType, typename
             std::enable_if<
                 std::is_pointer<PointerType>::value
                 , int>::type = 0>
    constexpr const PointerType get() const noexcept
    {
        // delegate the call to get_ptr
        return get_ptr<PointerType>();
    }

    /*!
    @brief get a pointer value (implicit)

    Implicit pointer access to the internally stored JSON value. No copies are
    made.

    @warning Writing data to the pointee of the result yields an undefined
    state.

    @tparam PointerType pointer type; must be a pointer to @ref array_t, @ref
    object_t, @ref string_t, @ref boolean_t, @ref number_integer_t,
    @ref number_unsigned_t, or @ref number_float_t.

    @return pointer to the internally stored JSON value if the requested
    pointer type @a PointerType fits to the JSON value; `nullptr` otherwise

    @complexity Constant.

    @liveexample{The example below shows how pointers to internal values of a
    JSON value can be requested. Note that no type conversions are made and a
    `nullptr` is returned if the value and the requested pointer type does not
    match.,get_ptr}

    @since version 1.0.0
    */
    template<typename PointerType, typename
             std::enable_if<
                 std::is_pointer<PointerType>::value
                 , int>::type = 0>
    PointerType get_ptr() noexcept
    {
        // delegate the call to get_impl_ptr<>()
        return get_impl_ptr(static_cast<PointerType>(nullptr));
    }

    /*!
    @brief get a pointer value (implicit)
    @copydoc get_ptr()
    */
    template<typename PointerType, typename
             std::enable_if<
                 std::is_pointer<PointerType>::value
                 and std::is_const<typename std::remove_pointer<PointerType>::type>::value
                 , int>::type = 0>
    constexpr const PointerType get_ptr() const noexcept
    {
        // delegate the call to get_impl_ptr<>() const
        return get_impl_ptr(static_cast<const PointerType>(nullptr));
    }

    /*!
    @brief get a reference value (implicit)

    Implict reference access to the internally stored JSON value. No copies are
    made.

    @warning Writing data to the referee of the result yields an undefined
    state.

    @tparam ReferenceType reference type; must be a reference to @ref array_t,
    @ref object_t, @ref string_t, @ref boolean_t, @ref number_integer_t, or
    @ref number_float_t.

    @return reference to the internally stored JSON value if the requested
    reference type @a ReferenceType fits to the JSON value; throws
    std::domain_error otherwise

    @throw std::domain_error in case passed type @a ReferenceType is
    incompatible with the stored JSON value

    @complexity Constant.

    @liveexample{The example shows several calls to `get_ref()`.,get_ref}

    @since version 1.1.0
    */
    template<typename ReferenceType, typename
             std::enable_if<
                 std::is_reference<ReferenceType>::value
                 , int>::type = 0>
    ReferenceType get_ref()
    {
        // delegate call to get_ref_impl
        return get_ref_impl<ReferenceType>(*this);
    }

    /*!
    @brief get a reference value (implicit)
    @copydoc get_ref()
    */
    template<typename ReferenceType, typename
             std::enable_if<
                 std::is_reference<ReferenceType>::value
                 and std::is_const<typename std::remove_reference<ReferenceType>::type>::value
                 , int>::type = 0>
    ReferenceType get_ref() const
    {
        // delegate call to get_ref_impl
        return get_ref_impl<ReferenceType>(*this);
    }

    /*!
    @brief get a value (implicit)

    Implicit type conversion between the JSON value and a compatible value. The
    call is realized by calling @ref get() const.

    @tparam ValueType non-pointer type compatible to the JSON value, for
    instance `int` for JSON integer numbers, `bool` for JSON booleans, or
    `std::vector` types for JSON arrays. The character type of @ref string_t as
    well as an initializer list of this type is excluded to avoid ambiguities
    as these types implicitly convert to `std::string`.

    @return copy of the JSON value, converted to type @a ValueType

    @throw std::domain_error in case passed type @a ValueType is incompatible
    to JSON, thrown by @ref get() const

    @complexity Linear in the size of the JSON value.

    @liveexample{The example below shows several conversions from JSON values
    to other types. There a few things to note: (1) Floating-point numbers can
    be converted to integers\, (2) A JSON array can be converted to a standard
    `std::vector<short>`\, (3) A JSON object can be converted to C++
    associative containers such as `std::unordered_map<std::string\,
    json>`.,operator__ValueType}

    @since version 1.0.0
    */
    template < typename ValueType, typename
               std::enable_if <
                   not std::is_pointer<ValueType>::value
                   and not std::is_same<ValueType, typename string_t::value_type>::value
#ifndef _MSC_VER  // Fix for issue #167 operator<< abiguity under VS2015
                   and not std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>::value
#endif
                   , int >::type = 0 >
    operator ValueType() const
    {
        // delegate the call to get<>() const
        return get<ValueType>();
    }

    /// @}


    ////////////////////
    // element access //
    ////////////////////

    /// @name element access
    /// @{

    /*!
    @brief access specified array element with bounds checking

    Returns a reference to the element at specified location @a idx, with
    bounds checking.

    @param[in] idx  index of the element to access

    @return reference to the element at index @a idx

    @throw std::domain_error if the JSON value is not an array; example:
    `"cannot use at() with string"`
    @throw std::out_of_range if the index @a idx is out of range of the array;
    that is, `idx >= size()`; example: `"array index 7 is out of range"`

    @complexity Constant.

    @liveexample{The example below shows how array elements can be read and
    written using `at()`.,at__size_type}

    @since version 1.0.0
    */
    reference at(size_type idx)
    {
        // at only works for arrays
        if (is_array())
        {
            try
            {
                assert(m_value.array != nullptr);
                return m_value.array->at(idx);
            }
            catch (std::out_of_range&)
            {
                // create better exception explanation
                throw std::out_of_range("array index " + std::to_string(idx) + " is out of range");
            }
        }
        else
        {
            throw std::domain_error("cannot use at() with " + type_name());
        }
    }

    /*!
    @brief access specified array element with bounds checking

    Returns a const reference to the element at specified location @a idx, with
    bounds checking.

    @param[in] idx  index of the element to access

    @return const reference to the element at index @a idx

    @throw std::domain_error if the JSON value is not an array; example:
    `"cannot use at() with string"`
    @throw std::out_of_range if the index @a idx is out of range of the array;
    that is, `idx >= size()`; example: `"array index 7 is out of range"`

    @complexity Constant.

    @liveexample{The example below shows how array elements can be read using
    `at()`.,at__size_type_const}

    @since version 1.0.0
    */
    const_reference at(size_type idx) const
    {
        // at only works for arrays
        if (is_array())
        {
            try
            {
                assert(m_value.array != nullptr);
                return m_value.array->at(idx);
            }
            catch (std::out_of_range&)
            {
                // create better exception explanation
                throw std::out_of_range("array index " + std::to_string(idx) + " is out of range");
            }
        }
        else
        {
            throw std::domain_error("cannot use at() with " + type_name());
        }
    }

    /*!
    @brief access specified object element with bounds checking

    Returns a reference to the element at with specified key @a key, with
    bounds checking.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw std::domain_error if the JSON value is not an object; example:
    `"cannot use at() with boolean"`
    @throw std::out_of_range if the key @a key is is not stored in the object;
    that is, `find(key) == end()`; example: `"key "the fast" not found"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using `at()`.,at__object_t_key_type}

    @sa @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    reference at(const typename object_t::key_type& key)
    {
        // at only works for objects
        if (is_object())
        {
            try
            {
                assert(m_value.object != nullptr);
                return m_value.object->at(key);
            }
            catch (std::out_of_range&)
            {
                // create better exception explanation
                throw std::out_of_range("key '" + key + "' not found");
            }
        }
        else
        {
            throw std::domain_error("cannot use at() with " + type_name());
        }
    }

    /*!
    @brief access specified object element with bounds checking

    Returns a const reference to the element at with specified key @a key, with
    bounds checking.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @throw std::domain_error if the JSON value is not an object; example:
    `"cannot use at() with boolean"`
    @throw std::out_of_range if the key @a key is is not stored in the object;
    that is, `find(key) == end()`; example: `"key "the fast" not found"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    `at()`.,at__object_t_key_type_const}

    @sa @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    const_reference at(const typename object_t::key_type& key) const
    {
        // at only works for objects
        if (is_object())
        {
            try
            {
                assert(m_value.object != nullptr);
                return m_value.object->at(key);
            }
            catch (std::out_of_range&)
            {
                // create better exception explanation
                throw std::out_of_range("key '" + key + "' not found");
            }
        }
        else
        {
            throw std::domain_error("cannot use at() with " + type_name());
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

    @throw std::domain_error if JSON is not an array or null; example: `"cannot
    use operator[] with string"`

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
        }

        // operator[] only works for arrays
        if (is_array())
        {
            // fill up array with null values until given idx is reached
            assert(m_value.array != nullptr);
            for (size_t i = m_value.array->size(); i <= idx; ++i)
            {
                m_value.array->push_back(basic_json());
            }

            return m_value.array->operator[](idx);
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief access specified array element

    Returns a const reference to the element at specified location @a idx.

    @param[in] idx  index of the element to access

    @return const reference to the element at index @a idx

    @throw std::domain_error if JSON is not an array; example: `"cannot use
    operator[] with null"`

    @complexity Constant.

    @liveexample{The example below shows how array elements can be read using
    the `[]` operator.,operatorarray__size_type_const}

    @since version 1.0.0
    */
    const_reference operator[](size_type idx) const
    {
        // const operator[] only works for arrays
        if (is_array())
        {
            assert(m_value.array != nullptr);
            return m_value.array->operator[](idx);
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief access specified object element

    Returns a reference to the element at with specified key @a key.

    @note If @a key is not found in the object, then it is silently added to
    the object and filled with a `null` value to make `key` a valid reference.
    In case the value was `null` before, it is converted to an object.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw std::domain_error if JSON is not an object or null; example:
    `"cannot use operator[] with string"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using the `[]` operator.,operatorarray__key_type}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    reference operator[](const typename object_t::key_type& key)
    {
        // implicitly convert null value to an empty object
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
        }

        // operator[] only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            return m_value.object->operator[](key);
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief read-only access specified object element

    Returns a const reference to the element at with specified key @a key. No
    bounds checking is performed.

    @warning If the element with key @a key does not exist, the behavior is
    undefined.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @throw std::domain_error if JSON is not an object; example: `"cannot use
    operator[] with null"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    the `[]` operator.,operatorarray__key_type_const}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    const_reference operator[](const typename object_t::key_type& key) const
    {
        // const operator[] only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            assert(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief access specified object element

    Returns a reference to the element at with specified key @a key.

    @note If @a key is not found in the object, then it is silently added to
    the object and filled with a `null` value to make `key` a valid reference.
    In case the value was `null` before, it is converted to an object.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw std::domain_error if JSON is not an object or null; example:
    `"cannot use operator[] with string"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using the `[]` operator.,operatorarray__key_type}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    template<typename T, std::size_t n>
    reference operator[](T * (&key)[n])
    {
        return operator[](static_cast<const T>(key));
    }

    /*!
    @brief read-only access specified object element

    Returns a const reference to the element at with specified key @a key. No
    bounds checking is performed.

    @warning If the element with key @a key does not exist, the behavior is
    undefined.

    @note This function is required for compatibility reasons with Clang.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @throw std::domain_error if JSON is not an object; example: `"cannot use
    operator[] with null"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    the `[]` operator.,operatorarray__key_type_const}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.0.0
    */
    template<typename T, std::size_t n>
    const_reference operator[](T * (&key)[n]) const
    {
        return operator[](static_cast<const T>(key));
    }

    /*!
    @brief access specified object element

    Returns a reference to the element at with specified key @a key.

    @note If @a key is not found in the object, then it is silently added to
    the object and filled with a `null` value to make `key` a valid reference.
    In case the value was `null` before, it is converted to an object.

    @param[in] key  key of the element to access

    @return reference to the element at key @a key

    @throw std::domain_error if JSON is not an object or null; example:
    `"cannot use operator[] with string"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read and
    written using the `[]` operator.,operatorarray__key_type}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.1.0
    */
    template<typename T>
    reference operator[](T* key)
    {
        // implicitly convert null to object
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
        }

        // at only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            return m_value.object->operator[](key);
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief read-only access specified object element

    Returns a const reference to the element at with specified key @a key. No
    bounds checking is performed.

    @warning If the element with key @a key does not exist, the behavior is
    undefined.

    @param[in] key  key of the element to access

    @return const reference to the element at key @a key

    @throw std::domain_error if JSON is not an object; example: `"cannot use
    operator[] with null"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be read using
    the `[]` operator.,operatorarray__key_type_const}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref value() for access by value with a default value

    @since version 1.1.0
    */
    template<typename T>
    const_reference operator[](T* key) const
    {
        // at only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            assert(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }
        else
        {
            throw std::domain_error("cannot use operator[] with " + type_name());
        }
    }

    /*!
    @brief access specified object element with default value

    Returns either a copy of an object's element at the specified key @a key or
    a given default value if no element with key @a key exists.

    The function is basically equivalent to executing
    @code {.cpp}
    try {
        return at(key);
    } catch(std::out_of_range) {
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

    @throw std::domain_error if JSON is not an object; example: `"cannot use
    value() with null"`

    @complexity Logarithmic in the size of the container.

    @liveexample{The example below shows how object elements can be queried
    with a default value.,basic_json__value}

    @sa @ref at(const typename object_t::key_type&) for access by reference
    with range checking
    @sa @ref operator[](const typename object_t::key_type&) for unchecked
    access by reference

    @since version 1.0.0
    */
    template <class ValueType, typename
              std::enable_if<
                  std::is_convertible<basic_json_t, ValueType>::value
                  , int>::type = 0>
    ValueType value(const typename object_t::key_type& key, ValueType default_value) const
    {
        // at only works for objects
        if (is_object())
        {
            // if key is found, return value and given default value otherwise
            const auto it = find(key);
            if (it != end())
            {
                return *it;
            }
            else
            {
                return default_value;
            }
        }
        else
        {
            throw std::domain_error("cannot use value() with " + type_name());
        }
    }

    /*!
    @brief overload for a default value of type const char*
    @copydoc basic_json::value()
    */
    string_t value(const typename object_t::key_type& key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    /*!
    @brief access the first element

    Returns a reference to the first element in the container. For a JSON
    container `c`, the expression `c.front()` is equivalent to `*c.begin()`.

    @return In case of a structured type (array or object), a reference to the
    first element is returned. In cast of number, string, or boolean values, a
    reference to the value is returned.

    @complexity Constant.

    @pre The JSON value must not be `null` (would throw `std::out_of_range`) or
    an empty array or object (undefined behavior, guarded by assertions).
    @post The JSON value remains unchanged.

    @throw std::out_of_range when called on `null` value

    @liveexample{The following code shows an example for `front()`.,front}

    @sa @ref back() -- access the last element

    @since version 1.0.0
    */
    reference front()
    {
        return *begin();
    }

    /*!
    @copydoc basic_json::front()
    */
    const_reference front() const
    {
        return *cbegin();
    }

    /*!
    @brief access the last element

    Returns a reference to the last element in the container. For a JSON
    container `c`, the expression `c.back()` is equivalent to
    @code {.cpp}
    auto tmp = c.end();
    --tmp;
    return *tmp;
    @endcode

    @return In case of a structured type (array or object), a reference to the
    last element is returned. In cast of number, string, or boolean values, a
    reference to the value is returned.

    @complexity Constant.

    @pre The JSON value must not be `null` (would throw `std::out_of_range`) or
    an empty array or object (undefined behavior, guarded by assertions).
    @post The JSON value remains unchanged.

    @throw std::out_of_range when called on `null` value.

    @liveexample{The following code shows an example for `back()`.,back}

    @sa @ref front() -- access the first element

    @since version 1.0.0
    */
    reference back()
    {
        auto tmp = end();
        --tmp;
        return *tmp;
    }

    /*!
    @copydoc basic_json::back()
    */
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
    @return Iterator following the last removed element. If the iterator @a pos
    refers to the last element, the `end()` iterator is returned.

    @tparam InteratorType an @ref iterator or @ref const_iterator

    @post Invalidates iterators and references at or after the point of the
    erase, including the `end()` iterator.

    @throw std::domain_error if called on a `null` value; example: `"cannot use
    erase() with null"`
    @throw std::domain_error if called on an iterator which does not belong to
    the current JSON value; example: `"iterator does not fit current value"`
    @throw std::out_of_range if called on a primitive type with invalid
    iterator (i.e., any iterator which is not `begin()`); example: `"iterator
    out of range"`

    @complexity The complexity depends on the type:
    - objects: amortized constant
    - arrays: linear in distance between pos and the end of the container
    - strings: linear in the length of the string
    - other types: constant

    @liveexample{The example shows the result of `erase()` for different JSON
    types.,erase__IteratorType}

    @sa @ref erase(InteratorType, InteratorType) -- removes the elements in the
    given range
    @sa @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key
    @sa @ref erase(const size_type) -- removes the element from an array at the
    given index

    @since version 1.0.0
    */
    template <class InteratorType, typename
              std::enable_if<
                  std::is_same<InteratorType, typename basic_json_t::iterator>::value or
                  std::is_same<InteratorType, typename basic_json_t::const_iterator>::value
                  , int>::type
              = 0>
    InteratorType erase(InteratorType pos)
    {
        // make sure iterator fits the current value
        if (this != pos.m_object)
        {
            throw std::domain_error("iterator does not fit current value");
        }

        InteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (not pos.m_it.primitive_iterator.is_begin())
                {
                    throw std::out_of_range("iterator out of range");
                }

                if (is_string())
                {
                    delete m_value.string;
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
                break;
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                result.m_it.object_iterator = m_value.object->erase(pos.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                assert(m_value.array != nullptr);
                result.m_it.array_iterator = m_value.array->erase(pos.m_it.array_iterator);
                break;
            }

            default:
            {
                throw std::domain_error("cannot use erase() with " + type_name());
            }
        }

        return result;
    }

    /*!
    @brief remove elements given an iterator range

    Removes the element specified by the range `[first; last)`. The iterator @a
    first does not need to be dereferenceable if `first == last`: erasing an
    empty range is a no-op.

    If called on a primitive type other than `null`, the resulting JSON value
    will be `null`.

    @param[in] first iterator to the beginning of the range to remove
    @param[in] last iterator past the end of the range to remove
    @return Iterator following the last removed element. If the iterator @a
    second refers to the last element, the `end()` iterator is returned.

    @tparam InteratorType an @ref iterator or @ref const_iterator

    @post Invalidates iterators and references at or after the point of the
    erase, including the `end()` iterator.

    @throw std::domain_error if called on a `null` value; example: `"cannot use
    erase() with null"`
    @throw std::domain_error if called on iterators which does not belong to
    the current JSON value; example: `"iterators do not fit current value"`
    @throw std::out_of_range if called on a primitive type with invalid
    iterators (i.e., if `first != begin()` and `last != end()`); example:
    `"iterators out of range"`

    @complexity The complexity depends on the type:
    - objects: `log(size()) + std::distance(first, last)`
    - arrays: linear in the distance between @a first and @a last, plus linear
      in the distance between @a last and end of the container
    - strings: linear in the length of the string
    - other types: constant

    @liveexample{The example shows the result of `erase()` for different JSON
    types.,erase__IteratorType_IteratorType}

    @sa @ref erase(InteratorType) -- removes the element at a given position
    @sa @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key
    @sa @ref erase(const size_type) -- removes the element from an array at the
    given index

    @since version 1.0.0
    */
    template <class InteratorType, typename
              std::enable_if<
                  std::is_same<InteratorType, typename basic_json_t::iterator>::value or
                  std::is_same<InteratorType, typename basic_json_t::const_iterator>::value
                  , int>::type
              = 0>
    InteratorType erase(InteratorType first, InteratorType last)
    {
        // make sure iterator fits the current value
        if (this != first.m_object or this != last.m_object)
        {
            throw std::domain_error("iterators do not fit current value");
        }

        InteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (not first.m_it.primitive_iterator.is_begin() or not last.m_it.primitive_iterator.is_end())
                {
                    throw std::out_of_range("iterators out of range");
                }

                if (is_string())
                {
                    delete m_value.string;
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
                break;
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                result.m_it.object_iterator = m_value.object->erase(first.m_it.object_iterator,
                                              last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                assert(m_value.array != nullptr);
                result.m_it.array_iterator = m_value.array->erase(first.m_it.array_iterator,
                                             last.m_it.array_iterator);
                break;
            }

            default:
            {
                throw std::domain_error("cannot use erase() with " + type_name());
            }
        }

        return result;
    }

    /*!
    @brief remove element from a JSON object given a key

    Removes elements from a JSON object with the key value @a key.

    @param[in] key value of the elements to remove

    @return Number of elements removed. If @a ObjectType is the default
    `std::map` type, the return value will always be `0` (@a key was not found)
    or `1` (@a key was found).

    @post References and iterators to the erased elements are invalidated.
    Other references and iterators are not affected.

    @throw std::domain_error when called on a type other than JSON object;
    example: `"cannot use erase() with null"`

    @complexity `log(size()) + count(key)`

    @liveexample{The example shows the effect of `erase()`.,erase__key_type}

    @sa @ref erase(InteratorType) -- removes the element at a given position
    @sa @ref erase(InteratorType, InteratorType) -- removes the elements in the
    given range
    @sa @ref erase(const size_type) -- removes the element from an array at the
    given index

    @since version 1.0.0
    */
    size_type erase(const typename object_t::key_type& key)
    {
        // this erase only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            return m_value.object->erase(key);
        }
        else
        {
            throw std::domain_error("cannot use erase() with " + type_name());
        }
    }

    /*!
    @brief remove element from a JSON array given an index

    Removes element from a JSON array at the index @a idx.

    @param[in] idx index of the element to remove

    @throw std::domain_error when called on a type other than JSON array;
    example: `"cannot use erase() with null"`
    @throw std::out_of_range when `idx >= size()`; example: `"index out of
    range"`

    @complexity Linear in distance between @a idx and the end of the container.

    @liveexample{The example shows the effect of `erase()`.,erase__size_type}

    @sa @ref erase(InteratorType) -- removes the element at a given position
    @sa @ref erase(InteratorType, InteratorType) -- removes the elements in the
    given range
    @sa @ref erase(const typename object_t::key_type&) -- removes the element
    from an object at the given key

    @since version 1.0.0
    */
    void erase(const size_type idx)
    {
        // this erase only works for arrays
        if (is_array())
        {
            if (idx >= size())
            {
                throw std::out_of_range("index out of range");
            }

            assert(m_value.array != nullptr);
            m_value.array->erase(m_value.array->begin() + static_cast<difference_type>(idx));
        }
        else
        {
            throw std::domain_error("cannot use erase() with " + type_name());
        }
    }

    /// @}


    ////////////
    // lookup //
    ////////////

    /// @name lookup
    /// @{

    /*!
    @brief find an element in a JSON object

    Finds an element in a JSON object with key equivalent to @a key. If the
    element is not found or the JSON value is not an object, end() is returned.

    @param[in] key key value of the element to search for

    @return Iterator to an element with key equivalent to @a key. If no such
    element is found, past-the-end (see end()) iterator is returned.

    @complexity Logarithmic in the size of the JSON object.

    @liveexample{The example shows how `find()` is used.,find__key_type}

    @since version 1.0.0
    */
    iterator find(typename object_t::key_type key)
    {
        auto result = end();

        if (is_object())
        {
            assert(m_value.object != nullptr);
            result.m_it.object_iterator = m_value.object->find(key);
        }

        return result;
    }

    /*!
    @brief find an element in a JSON object
    @copydoc find(typename object_t::key_type)
    */
    const_iterator find(typename object_t::key_type key) const
    {
        auto result = cend();

        if (is_object())
        {
            assert(m_value.object != nullptr);
            result.m_it.object_iterator = m_value.object->find(key);
        }

        return result;
    }

    /*!
    @brief returns the number of occurrences of a key in a JSON object

    Returns the number of elements with key @a key. If ObjectType is the
    default `std::map` type, the return value will always be `0` (@a key was
    not found) or `1` (@a key was found).

    @param[in] key key value of the element to count

    @return Number of elements with key @a key. If the JSON value is not an
    object, the return value will be `0`.

    @complexity Logarithmic in the size of the JSON object.

    @liveexample{The example shows how `count()` is used.,count}

    @since version 1.0.0
    */
    size_type count(typename object_t::key_type key) const
    {
        // return 0 for all nonobject types
        assert(not is_object() or m_value.object != nullptr);
        return is_object() ? m_value.object->count(key) : 0;
    }

    /// @}


    ///////////////
    // iterators //
    ///////////////

    /// @name iterators
    /// @{

    /*!
    @brief returns an iterator to the first element

    Returns an iterator to the first element.

    @image html range-begin-end.svg "Illustration from cppreference.com"

    @return iterator to the first element

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.

    @liveexample{The following code shows an example for `begin()`.,begin}

    @sa @ref cbegin() -- returns a const iterator to the beginning
    @sa @ref end() -- returns an iterator to the end
    @sa @ref cend() -- returns a const iterator to the end

    @since version 1.0.0
    */
    iterator begin() noexcept
    {
        iterator result(this);
        result.set_begin();
        return result;
    }

    /*!
    @copydoc basic_json::cbegin()
    */
    const_iterator begin() const noexcept
    {
        return cbegin();
    }

    /*!
    @brief returns a const iterator to the first element

    Returns a const iterator to the first element.

    @image html range-begin-end.svg "Illustration from cppreference.com"

    @return const iterator to the first element

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - Has the semantics of `const_cast<const basic_json&>(*this).begin()`.

    @liveexample{The following code shows an example for `cbegin()`.,cbegin}

    @sa @ref begin() -- returns an iterator to the beginning
    @sa @ref end() -- returns an iterator to the end
    @sa @ref cend() -- returns a const iterator to the end

    @since version 1.0.0
    */
    const_iterator cbegin() const noexcept
    {
        const_iterator result(this);
        result.set_begin();
        return result;
    }

    /*!
    @brief returns an iterator to one past the last element

    Returns an iterator to one past the last element.

    @image html range-begin-end.svg "Illustration from cppreference.com"

    @return iterator one past the last element

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.

    @liveexample{The following code shows an example for `end()`.,end}

    @sa @ref cend() -- returns a const iterator to the end
    @sa @ref begin() -- returns an iterator to the beginning
    @sa @ref cbegin() -- returns a const iterator to the beginning

    @since version 1.0.0
    */
    iterator end() noexcept
    {
        iterator result(this);
        result.set_end();
        return result;
    }

    /*!
    @copydoc basic_json::cend()
    */
    const_iterator end() const noexcept
    {
        return cend();
    }

    /*!
    @brief returns a const iterator to one past the last element

    Returns a const iterator to one past the last element.

    @image html range-begin-end.svg "Illustration from cppreference.com"

    @return const iterator one past the last element

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - Has the semantics of `const_cast<const basic_json&>(*this).end()`.

    @liveexample{The following code shows an example for `cend()`.,cend}

    @sa @ref end() -- returns an iterator to the end
    @sa @ref begin() -- returns an iterator to the beginning
    @sa @ref cbegin() -- returns a const iterator to the beginning

    @since version 1.0.0
    */
    const_iterator cend() const noexcept
    {
        const_iterator result(this);
        result.set_end();
        return result;
    }

    /*!
    @brief returns an iterator to the reverse-beginning

    Returns an iterator to the reverse-beginning; that is, the last element.

    @image html range-rbegin-rend.svg "Illustration from cppreference.com"

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [ReversibleContainer](http://en.cppreference.com/w/cpp/concept/ReversibleContainer)
    requirements:
    - The complexity is constant.
    - Has the semantics of `reverse_iterator(end())`.

    @liveexample{The following code shows an example for `rbegin()`.,rbegin}

    @sa @ref crbegin() -- returns a const reverse iterator to the beginning
    @sa @ref rend() -- returns a reverse iterator to the end
    @sa @ref crend() -- returns a const reverse iterator to the end

    @since version 1.0.0
    */
    reverse_iterator rbegin() noexcept
    {
        return reverse_iterator(end());
    }

    /*!
    @copydoc basic_json::crbegin()
    */
    const_reverse_iterator rbegin() const noexcept
    {
        return crbegin();
    }

    /*!
    @brief returns an iterator to the reverse-end

    Returns an iterator to the reverse-end; that is, one before the first
    element.

    @image html range-rbegin-rend.svg "Illustration from cppreference.com"

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [ReversibleContainer](http://en.cppreference.com/w/cpp/concept/ReversibleContainer)
    requirements:
    - The complexity is constant.
    - Has the semantics of `reverse_iterator(begin())`.

    @liveexample{The following code shows an example for `rend()`.,rend}

    @sa @ref crend() -- returns a const reverse iterator to the end
    @sa @ref rbegin() -- returns a reverse iterator to the beginning
    @sa @ref crbegin() -- returns a const reverse iterator to the beginning

    @since version 1.0.0
    */
    reverse_iterator rend() noexcept
    {
        return reverse_iterator(begin());
    }

    /*!
    @copydoc basic_json::crend()
    */
    const_reverse_iterator rend() const noexcept
    {
        return crend();
    }

    /*!
    @brief returns a const reverse iterator to the last element

    Returns a const iterator to the reverse-beginning; that is, the last
    element.

    @image html range-rbegin-rend.svg "Illustration from cppreference.com"

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [ReversibleContainer](http://en.cppreference.com/w/cpp/concept/ReversibleContainer)
    requirements:
    - The complexity is constant.
    - Has the semantics of `const_cast<const basic_json&>(*this).rbegin()`.

    @liveexample{The following code shows an example for `crbegin()`.,crbegin}

    @sa @ref rbegin() -- returns a reverse iterator to the beginning
    @sa @ref rend() -- returns a reverse iterator to the end
    @sa @ref crend() -- returns a const reverse iterator to the end

    @since version 1.0.0
    */
    const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(cend());
    }

    /*!
    @brief returns a const reverse iterator to one before the first

    Returns a const reverse iterator to the reverse-end; that is, one before
    the first element.

    @image html range-rbegin-rend.svg "Illustration from cppreference.com"

    @complexity Constant.

    @requirement This function helps `basic_json` satisfying the
    [ReversibleContainer](http://en.cppreference.com/w/cpp/concept/ReversibleContainer)
    requirements:
    - The complexity is constant.
    - Has the semantics of `const_cast<const basic_json&>(*this).rend()`.

    @liveexample{The following code shows an example for `crend()`.,crend}

    @sa @ref rend() -- returns a reverse iterator to the end
    @sa @ref rbegin() -- returns a reverse iterator to the beginning
    @sa @ref crbegin() -- returns a const reverse iterator to the beginning

    @since version 1.0.0
    */
    const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(cbegin());
    }

  private:
    // forward declaration
    template<typename IteratorType> class iteration_proxy;

  public:
    /*!
    @brief wrapper to access iterator member functions in range-based for

    This function allows to access @ref iterator::key() and @ref
    iterator::value() during range-based for loops. In these loops, a reference
    to the JSON values is returned, so there is no access to the underlying
    iterator.

    @note The name of this function is not yet final and may change in the
    future.
    */
    static iteration_proxy<iterator> iterator_wrapper(reference cont)
    {
        return iteration_proxy<iterator>(cont);
    }

    /*!
    @copydoc iterator_wrapper(reference)
    */
    static iteration_proxy<const_iterator> iterator_wrapper(const_reference cont)
    {
        return iteration_proxy<const_iterator>(cont);
    }

    /// @}


    //////////////
    // capacity //
    //////////////

    /// @name capacity
    /// @{

    /*!
    @brief checks whether the container is empty

    Checks if a JSON value has no elements.

    @return The return value depends on the different types and is
            defined as follows:
            Value type  | return value
            ----------- | -------------
            null        | `true`
            boolean     | `false`
            string      | `false`
            number      | `false`
            object      | result of function `object_t::empty()`
            array       | result of function `array_t::empty()`

    @complexity Constant, as long as @ref array_t and @ref object_t satisfy the
    Container concept; that is, their `empty()` functions have constant
    complexity.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - Has the semantics of `begin() == end()`.

    @liveexample{The following code uses `empty()` to check if a JSON
    object contains any elements.,empty}

    @sa @ref size() -- returns the number of elements

    @since version 1.0.0
    */
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
                assert(m_value.array != nullptr);
                return m_value.array->empty();
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                return m_value.object->empty();
            }

            default:
            {
                // all other types are nonempty
                return false;
            }
        }
    }

    /*!
    @brief returns the number of elements

    Returns the number of elements in a JSON value.

    @return The return value depends on the different types and is
            defined as follows:
            Value type  | return value
            ----------- | -------------
            null        | `0`
            boolean     | `1`
            string      | `1`
            number      | `1`
            object      | result of function object_t::size()
            array       | result of function array_t::size()

    @complexity Constant, as long as @ref array_t and @ref object_t satisfy the
    Container concept; that is, their size() functions have constant complexity.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - Has the semantics of `std::distance(begin(), end())`.

    @liveexample{The following code calls `size()` on the different value
    types.,size}

    @sa @ref empty() -- checks whether the container is empty
    @sa @ref max_size() -- returns the maximal number of elements

    @since version 1.0.0
    */
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
                assert(m_value.array != nullptr);
                return m_value.array->size();
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                return m_value.object->size();
            }

            default:
            {
                // all other types have size 1
                return 1;
            }
        }
    }

    /*!
    @brief returns the maximum possible number of elements

    Returns the maximum number of elements a JSON value is able to hold due to
    system or library implementation limitations, i.e. `std::distance(begin(),
    end())` for the JSON value.

    @return The return value depends on the different types and is
            defined as follows:
            Value type  | return value
            ----------- | -------------
            null        | `0` (same as `size()`)
            boolean     | `1` (same as `size()`)
            string      | `1` (same as `size()`)
            number      | `1` (same as `size()`)
            object      | result of function `object_t::max_size()`
            array       | result of function `array_t::max_size()`

    @complexity Constant, as long as @ref array_t and @ref object_t satisfy the
    Container concept; that is, their `max_size()` functions have constant
    complexity.

    @requirement This function helps `basic_json` satisfying the
    [Container](http://en.cppreference.com/w/cpp/concept/Container)
    requirements:
    - The complexity is constant.
    - Has the semantics of returning `b.size()` where `b` is the largest
      possible JSON value.

    @liveexample{The following code calls `max_size()` on the different value
    types. Note the output is implementation specific.,max_size}

    @sa @ref size() -- returns the number of elements

    @since version 1.0.0
    */
    size_type max_size() const noexcept
    {
        switch (m_type)
        {
            case value_t::array:
            {
                assert(m_value.array != nullptr);
                return m_value.array->max_size();
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                return m_value.object->max_size();
            }

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

    /*!
    @brief clears the contents

    Clears the content of a JSON value and resets it to the default value as
    if @ref basic_json(value_t) would have been called:

    Value type  | initial value
    ----------- | -------------
    null        | `null`
    boolean     | `false`
    string      | `""`
    number      | `0`
    object      | `{}`
    array       | `[]`

    @note Floating-point numbers are set to `0.0` which will be serialized to
    `0`. The vale type remains @ref number_float_t.

    @complexity Linear in the size of the JSON value.

    @liveexample{The example below shows the effect of `clear()` to different
    JSON types.,clear}

    @since version 1.0.0
    */
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
                assert(m_value.string != nullptr);
                m_value.string->clear();
                break;
            }

            case value_t::array:
            {
                assert(m_value.array != nullptr);
                m_value.array->clear();
                break;
            }

            case value_t::object:
            {
                assert(m_value.object != nullptr);
                m_value.object->clear();
                break;
            }

            default:
            {
                break;
            }
        }
    }

    /*!
    @brief add an object to an array

    Appends the given element @a val to the end of the JSON value. If the
    function is called on a JSON null value, an empty array is created before
    appending @a val.

    @param[in] val the value to add to the JSON array

    @throw std::domain_error when called on a type other than JSON array or
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
        if (not(is_null() or is_array()))
        {
            throw std::domain_error("cannot use push_back() with " + type_name());
        }

        // transform null object into an array
        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
        }

        // add element to array (move semantics)
        assert(m_value.array != nullptr);
        m_value.array->push_back(std::move(val));
        // invalidate object
        val.m_type = value_t::null;
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
        if (not(is_null() or is_array()))
        {
            throw std::domain_error("cannot use push_back() with " + type_name());
        }

        // transform null object into an array
        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
        }

        // add element to array
        assert(m_value.array != nullptr);
        m_value.array->push_back(val);
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
    called on a JSON null value, an empty object is created before inserting @a
    val.

    @param[in] val the value to add to the JSON object

    @throw std::domain_error when called on a type other than JSON object or
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
        if (not(is_null() or is_object()))
        {
            throw std::domain_error("cannot use push_back() with " + type_name());
        }

        // transform null object into an object
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
        }

        // add element to array
        assert(m_value.object != nullptr);
        m_value.object->insert(val);
    }

    /*!
    @brief add an object to an object
    @copydoc push_back(const typename object_t::value_type&)
    */
    reference operator+=(const typename object_t::value_type& val)
    {
        push_back(val);
        return operator[](val.first);
    }

    /*!
    @brief inserts element

    Inserts element @a val before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] val element to insert
    @return iterator pointing to the inserted @a val.

    @throw std::domain_error if called on JSON values other than arrays;
    example: `"cannot use insert() with string"`
    @throw std::domain_error if @a pos is not an iterator of *this; example:
    `"iterator does not fit current value"`

    @complexity Constant plus linear in the distance between pos and end of the
    container.

    @liveexample{The example shows how `insert()` is used.,insert}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, const basic_json& val)
    {
        // insert only works for arrays
        if (is_array())
        {
            // check if iterator pos fits to this JSON value
            if (pos.m_object != this)
            {
                throw std::domain_error("iterator does not fit current value");
            }

            // insert to array and return iterator
            iterator result(this);
            assert(m_value.array != nullptr);
            result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, val);
            return result;
        }
        else
        {
            throw std::domain_error("cannot use insert() with " + type_name());
        }
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

    @throw std::domain_error if called on JSON values other than arrays;
    example: `"cannot use insert() with string"`
    @throw std::domain_error if @a pos is not an iterator of *this; example:
    `"iterator does not fit current value"`

    @complexity Linear in @a cnt plus linear in the distance between @a pos
    and end of the container.

    @liveexample{The example shows how `insert()` is used.,insert__count}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, size_type cnt, const basic_json& val)
    {
        // insert only works for arrays
        if (is_array())
        {
            // check if iterator pos fits to this JSON value
            if (pos.m_object != this)
            {
                throw std::domain_error("iterator does not fit current value");
            }

            // insert to array and return iterator
            iterator result(this);
            assert(m_value.array != nullptr);
            result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, cnt, val);
            return result;
        }
        else
        {
            throw std::domain_error("cannot use insert() with " + type_name());
        }
    }

    /*!
    @brief inserts elements

    Inserts elements from range `[first, last)` before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] first begin of the range of elements to insert
    @param[in] last end of the range of elements to insert

    @throw std::domain_error if called on JSON values other than arrays;
    example: `"cannot use insert() with string"`
    @throw std::domain_error if @a pos is not an iterator of *this; example:
    `"iterator does not fit current value"`
    @throw std::domain_error if @a first and @a last do not belong to the same
    JSON value; example: `"iterators do not fit"`
    @throw std::domain_error if @a first or @a last are iterators into
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
        if (not is_array())
        {
            throw std::domain_error("cannot use insert() with " + type_name());
        }

        // check if iterator pos fits to this JSON value
        if (pos.m_object != this)
        {
            throw std::domain_error("iterator does not fit current value");
        }

        if (first.m_object != last.m_object)
        {
            throw std::domain_error("iterators do not fit");
        }

        if (first.m_object == this or last.m_object == this)
        {
            throw std::domain_error("passed iterators may not belong to container");
        }

        // insert to array and return iterator
        iterator result(this);
        assert(m_value.array != nullptr);
        result.m_it.array_iterator = m_value.array->insert(
                                         pos.m_it.array_iterator,
                                         first.m_it.array_iterator,
                                         last.m_it.array_iterator);
        return result;
    }

    /*!
    @brief inserts elements

    Inserts elements from initializer list @a ilist before iterator @a pos.

    @param[in] pos iterator before which the content will be inserted; may be
    the end() iterator
    @param[in] ilist initializer list to insert the values from

    @throw std::domain_error if called on JSON values other than arrays;
    example: `"cannot use insert() with string"`
    @throw std::domain_error if @a pos is not an iterator of *this; example:
    `"iterator does not fit current value"`

    @return iterator pointing to the first element inserted, or @a pos if
    `ilist` is empty

    @complexity Linear in `ilist.size()` plus linear in the distance between @a
    pos and end of the container.

    @liveexample{The example shows how `insert()` is used.,insert__ilist}

    @since version 1.0.0
    */
    iterator insert(const_iterator pos, std::initializer_list<basic_json> ilist)
    {
        // insert only works for arrays
        if (not is_array())
        {
            throw std::domain_error("cannot use insert() with " + type_name());
        }

        // check if iterator pos fits to this JSON value
        if (pos.m_object != this)
        {
            throw std::domain_error("iterator does not fit current value");
        }

        // insert to array and return iterator
        iterator result(this);
        assert(m_value.array != nullptr);
        result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, ilist);
        return result;
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
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        std::swap(m_type, other.m_type);
        std::swap(m_value, other.m_value);
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON array with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other array to exchange the contents with

    @throw std::domain_error when JSON value is not an array; example: `"cannot
    use swap() with string"`

    @complexity Constant.

    @liveexample{The example below shows how arrays can be swapped with
    `swap()`.,swap__array_t}

    @since version 1.0.0
    */
    void swap(array_t& other)
    {
        // swap only works for arrays
        if (is_array())
        {
            assert(m_value.array != nullptr);
            std::swap(*(m_value.array), other);
        }
        else
        {
            throw std::domain_error("cannot use swap() with " + type_name());
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON object with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other object to exchange the contents with

    @throw std::domain_error when JSON value is not an object; example:
    `"cannot use swap() with string"`

    @complexity Constant.

    @liveexample{The example below shows how objects can be swapped with
    `swap()`.,swap__object_t}

    @since version 1.0.0
    */
    void swap(object_t& other)
    {
        // swap only works for objects
        if (is_object())
        {
            assert(m_value.object != nullptr);
            std::swap(*(m_value.object), other);
        }
        else
        {
            throw std::domain_error("cannot use swap() with " + type_name());
        }
    }

    /*!
    @brief exchanges the values

    Exchanges the contents of a JSON string with those of @a other. Does not
    invoke any move, copy, or swap operations on individual elements. All
    iterators and references remain valid. The past-the-end iterator is
    invalidated.

    @param[in,out] other string to exchange the contents with

    @throw std::domain_error when JSON value is not a string; example: `"cannot
    use swap() with boolean"`

    @complexity Constant.

    @liveexample{The example below shows how strings can be swapped with
    `swap()`.,swap__string_t}

    @since version 1.0.0
    */
    void swap(string_t& other)
    {
        // swap only works for strings
        if (is_string())
        {
            assert(m_value.string != nullptr);
            std::swap(*(m_value.string), other);
        }
        else
        {
            throw std::domain_error("cannot use swap() with " + type_name());
        }
    }

    /// @}


    //////////////////////////////////////////
    // lexicographical comparison operators //
    //////////////////////////////////////////

    /// @name lexicographical comparison operators
    /// @{

  private:
    /*!
    @brief comparison operator for JSON types

    Returns an ordering that is similar to Python:
    - order: null < boolean < number < object < array < string
    - furthermore, each type is not smaller than itself

    @since version 1.0.0
    */
    friend bool operator<(const value_t lhs, const value_t rhs) noexcept
    {
        static constexpr std::array<uint8_t, 8> order = {{
                0, // null
                3, // object
                4, // array
                5, // string
                1, // boolean
                2, // integer
                2, // unsigned
                2, // float
            }
        };

        // discarded values are not comparable
        if (lhs == value_t::discarded or rhs == value_t::discarded)
        {
            return false;
        }

        return order[static_cast<std::size_t>(lhs)] < order[static_cast<std::size_t>(rhs)];
    }

  public:
    /*!
    @brief comparison: equal

    Compares two JSON values for equality according to the following rules:
    - Two JSON values are equal if (1) they are from the same type and (2)
      their stored values are the same.
    - Integer and floating-point numbers are automatically converted before
      comparison. Floating-point numbers are compared indirectly: two
      floating-point numbers `f1` and `f2` are considered equal if neither
      `f1 > f2` nor `f2 > f1` holds.
    - Two JSON null values are equal.

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether the values @a lhs and @a rhs are equal

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__equal}

    @since version 1.0.0
    */
    friend bool operator==(const_reference lhs, const_reference rhs) noexcept
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                {
                    assert(lhs.m_value.array != nullptr);
                    assert(rhs.m_value.array != nullptr);
                    return *lhs.m_value.array == *rhs.m_value.array;
                }
                case value_t::object:
                {
                    assert(lhs.m_value.object != nullptr);
                    assert(rhs.m_value.object != nullptr);
                    return *lhs.m_value.object == *rhs.m_value.object;
                }
                case value_t::null:
                {
                    return true;
                }
                case value_t::string:
                {
                    assert(lhs.m_value.string != nullptr);
                    assert(rhs.m_value.string != nullptr);
                    return *lhs.m_value.string == *rhs.m_value.string;
                }
                case value_t::boolean:
                {
                    return lhs.m_value.boolean == rhs.m_value.boolean;
                }
                case value_t::number_integer:
                {
                    return lhs.m_value.number_integer == rhs.m_value.number_integer;
                }
                case value_t::number_unsigned:
                {
                    return lhs.m_value.number_unsigned == rhs.m_value.number_unsigned;
                }
                case value_t::number_float:
                {
                    return lhs.m_value.number_float == rhs.m_value.number_float;
                }
                default:
                {
                    return false;
                }
            }
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_integer) == rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_integer)
        {
            return lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_integer)
        {
            return static_cast<number_integer_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_integer;
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_integer == static_cast<number_integer_t>(rhs.m_value.number_unsigned);
        }

        return false;
    }

    /*!
    @brief comparison: equal

    The functions compares the given JSON value against a null pointer. As the
    null pointer can be used to initialize a JSON value to null, a comparison
    of JSON value @a v with a null pointer should be equivalent to call
    `v.is_null()`.

    @param[in] v  JSON value to consider
    @return whether @a v is null

    @complexity Constant.

    @liveexample{The example compares several JSON types to the null pointer.
    ,operator__equal__nullptr_t}

    @since version 1.0.0
    */
    friend bool operator==(const_reference v, std::nullptr_t) noexcept
    {
        return v.is_null();
    }

    /*!
    @brief comparison: equal
    @copydoc operator==(const_reference, std::nullptr_t)
    */
    friend bool operator==(std::nullptr_t, const_reference v) noexcept
    {
        return v.is_null();
    }

    /*!
    @brief comparison: not equal

    Compares two JSON values for inequality by calculating `not (lhs == rhs)`.

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether the values @a lhs and @a rhs are not equal

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__notequal}

    @since version 1.0.0
    */
    friend bool operator!=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs == rhs);
    }

    /*!
    @brief comparison: not equal

    The functions compares the given JSON value against a null pointer. As the
    null pointer can be used to initialize a JSON value to null, a comparison
    of JSON value @a v with a null pointer should be equivalent to call
    `not v.is_null()`.

    @param[in] v  JSON value to consider
    @return whether @a v is not null

    @complexity Constant.

    @liveexample{The example compares several JSON types to the null pointer.
    ,operator__notequal__nullptr_t}

    @since version 1.0.0
    */
    friend bool operator!=(const_reference v, std::nullptr_t) noexcept
    {
        return not v.is_null();
    }

    /*!
    @brief comparison: not equal
    @copydoc operator!=(const_reference, std::nullptr_t)
    */
    friend bool operator!=(std::nullptr_t, const_reference v) noexcept
    {
        return not v.is_null();
    }

    /*!
    @brief comparison: less than

    Compares whether one JSON value @a lhs is less than another JSON value @a
    rhs according to the following rules:
    - If @a lhs and @a rhs have the same type, the values are compared using
      the default `<` operator.
    - Integer and floating-point numbers are automatically converted before
      comparison
    - In case @a lhs and @a rhs have different types, the values are ignored
      and the order of the types is considered, see
      @ref operator<(const value_t, const value_t).

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether @a lhs is less than @a rhs

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__less}

    @since version 1.0.0
    */
    friend bool operator<(const_reference lhs, const_reference rhs) noexcept
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                {
                    assert(lhs.m_value.array != nullptr);
                    assert(rhs.m_value.array != nullptr);
                    return *lhs.m_value.array < *rhs.m_value.array;
                }
                case value_t::object:
                {
                    assert(lhs.m_value.object != nullptr);
                    assert(rhs.m_value.object != nullptr);
                    return *lhs.m_value.object < *rhs.m_value.object;
                }
                case value_t::null:
                {
                    return false;
                }
                case value_t::string:
                {
                    assert(lhs.m_value.string != nullptr);
                    assert(rhs.m_value.string != nullptr);
                    return *lhs.m_value.string < *rhs.m_value.string;
                }
                case value_t::boolean:
                {
                    return lhs.m_value.boolean < rhs.m_value.boolean;
                }
                case value_t::number_integer:
                {
                    return lhs.m_value.number_integer < rhs.m_value.number_integer;
                }
                case value_t::number_unsigned:
                {
                    return lhs.m_value.number_unsigned < rhs.m_value.number_unsigned;
                }
                case value_t::number_float:
                {
                    return lhs.m_value.number_float < rhs.m_value.number_float;
                }
                default:
                {
                    return false;
                }
            }
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_integer)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_integer < static_cast<number_integer_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_integer)
        {
            return static_cast<number_integer_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_integer;
        }

        // We only reach this line if we cannot compare values. In that case,
        // we compare types. Note we have to call the operator explicitly,
        // because MSVC has problems otherwise.
        return operator<(lhs_type, rhs_type);
    }

    /*!
    @brief comparison: less than or equal

    Compares whether one JSON value @a lhs is less than or equal to another
    JSON value by calculating `not (rhs < lhs)`.

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether @a lhs is less than or equal to @a rhs

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__greater}

    @since version 1.0.0
    */
    friend bool operator<=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (rhs < lhs);
    }

    /*!
    @brief comparison: greater than

    Compares whether one JSON value @a lhs is greater than another
    JSON value by calculating `not (lhs <= rhs)`.

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether @a lhs is greater than to @a rhs

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__lessequal}

    @since version 1.0.0
    */
    friend bool operator>(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs <= rhs);
    }

    /*!
    @brief comparison: greater than or equal

    Compares whether one JSON value @a lhs is greater than or equal to another
    JSON value by calculating `not (lhs < rhs)`.

    @param[in] lhs  first JSON value to consider
    @param[in] rhs  second JSON value to consider
    @return whether @a lhs is greater than or equal to @a rhs

    @complexity Linear.

    @liveexample{The example demonstrates comparing several JSON
    types.,operator__greaterequal}

    @since version 1.0.0
    */
    friend bool operator>=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs < rhs);
    }

    /// @}


    ///////////////////
    // serialization //
    ///////////////////

    /// @name serialization
    /// @{

    /*!
    @brief serialize to stream

    Serialize the given JSON value @a j to the output stream @a o. The JSON
    value will be serialized using the @ref dump member function. The
    indentation of the output can be controlled with the member variable
    `width` of the output stream @a o. For instance, using the manipulator
    `std::setw(4)` on @a o sets the indentation level to `4` and the
    serialization result is the same as calling `dump(4)`.

    @param[in,out] o  stream to serialize to
    @param[in] j  JSON value to serialize

    @return the stream @a o

    @complexity Linear.

    @liveexample{The example below shows the serialization with different
    parameters to `width` to adjust the indentation level.,operator_serialize}

    @since version 1.0.0
    */
    friend std::ostream& operator<<(std::ostream& o, const basic_json& j)
    {
        // read width member and use it as indentation parameter if nonzero
        const bool pretty_print = (o.width() > 0);
        const auto indentation = (pretty_print ? o.width() : 0);

        // reset width to 0 for subsequent calls to this stream
        o.width(0);

        // do the actual serialization
        j.dump(o, pretty_print, static_cast<unsigned int>(indentation));
        return o;
    }

    /*!
    @brief serialize to stream
    @copydoc operator<<(std::ostream&, const basic_json&)
    */
    friend std::ostream& operator>>(const basic_json& j, std::ostream& o)
    {
        return o << j;
    }

    /// @}


    /////////////////////
    // deserialization //
    /////////////////////

    /// @name deserialization
    /// @{

    /*!
    @brief deserialize from string

    @param[in] s  string to read a serialized JSON value from
    @param[in] cb a parser callback function of type @ref parser_callback_t
    which is used to control the deserialization by filtering unwanted values
    (optional)

    @return result of the deserialization

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser. The complexity can be higher if the parser callback function
    @a cb has a super-linear complexity.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates the `parse()` function with and
    without callback function.,parse__string__parser_callback_t}

    @sa @ref parse(std::istream&, parser_callback_t) for a version that reads
    from an input stream

    @since version 1.0.0
    */
    static basic_json parse(const string_t& s, parser_callback_t cb = nullptr)
    {
        return parser(s, cb).parse();
    }

    /*!
    @brief deserialize from stream

    @param[in,out] i  stream to read a serialized JSON value from
    @param[in] cb a parser callback function of type @ref parser_callback_t
    which is used to control the deserialization by filtering unwanted values
    (optional)

    @return result of the deserialization

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser. The complexity can be higher if the parser callback function
    @a cb has a super-linear complexity.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below demonstrates the `parse()` function with and
    without callback function.,parse__istream__parser_callback_t}

    @sa @ref parse(const string_t&, parser_callback_t) for a version that reads
    from a string

    @since version 1.0.0
    */
    static basic_json parse(std::istream& i, parser_callback_t cb = nullptr)
    {
        return parser(i, cb).parse();
    }

    /*!
    @copydoc parse(std::istream&, parser_callback_t)
    */
    static basic_json parse(std::istream&& i, parser_callback_t cb = nullptr)
    {
        return parser(i, cb).parse();
    }

    /*!
    @brief deserialize from stream

    Deserializes an input stream to a JSON value.

    @param[in,out] i  input stream to read a serialized JSON value from
    @param[in,out] j  JSON value to write the deserialized input to

    @throw std::invalid_argument in case of parse errors

    @complexity Linear in the length of the input. The parser is a predictive
    LL(1) parser.

    @note A UTF-8 byte order mark is silently ignored.

    @liveexample{The example below shows how a JSON value is constructed by
    reading a serialization from a stream.,operator_deserialize}

    @sa parse(std::istream&, parser_callback_t) for a variant with a parser
    callback function to filter values while parsing

    @since version 1.0.0
    */
    friend std::istream& operator<<(basic_json& j, std::istream& i)
    {
        j = parser(i).parse();
        return i;
    }

    /*!
    @brief deserialize from stream
    @copydoc operator<<(basic_json&, std::istream&)
    */
    friend std::istream& operator>>(std::istream& i, basic_json& j)
    {
        j = parser(i).parse();
        return i;
    }

    /// @}


  private:
    ///////////////////////////
    // convenience functions //
    ///////////////////////////

    /// return the type as string
    string_t type_name() const noexcept
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
            case value_t::discarded:
                return "discarded";
            default:
                return "number";
        }
    }

    /*!
    @brief calculates the extra space to escape a JSON string

    @param[in] s  the string to escape
    @return the number of characters required to escape string @a s

    @complexity Linear in the length of string @a s.
    */
    static std::size_t extra_space(const string_t& s) noexcept
    {
        std::size_t result = 0;

        for (const auto& c : s)
        {
            switch (c)
            {
                case '"':
                case '\\':
                case '\b':
                case '\f':
                case '\n':
                case '\r':
                case '\t':
                {
                    // from c (1 byte) to \x (2 bytes)
                    result += 1;
                    break;
                }

                default:
                {
                    if (c >= 0x00 and c <= 0x1f)
                    {
                        // from c (1 byte) to \uxxxx (6 bytes)
                        result += 5;
                    }
                    break;
                }
            }
        }

        return result;
    }

    /*!
    @brief escape a string

    Escape a string by replacing certain special characters by a sequence of an
    escape character (backslash) and another character and other control
    characters by a sequence of "\u" followed by a four-digit hex
    representation.

    @param[in] s  the string to escape
    @return  the escaped string

    @complexity Linear in the length of string @a s.
    */
    static string_t escape_string(const string_t& s)
    {
        const auto space = extra_space(s);
        if (space == 0)
        {
            return s;
        }

        // create a result string of necessary size
        string_t result(s.size() + space, '\\');
        std::size_t pos = 0;

        for (const auto& c : s)
        {
            switch (c)
            {
                // quotation mark (0x22)
                case '"':
                {
                    result[pos + 1] = '"';
                    pos += 2;
                    break;
                }

                // reverse solidus (0x5c)
                case '\\':
                {
                    // nothing to change
                    pos += 2;
                    break;
                }

                // backspace (0x08)
                case '\b':
                {
                    result[pos + 1] = 'b';
                    pos += 2;
                    break;
                }

                // formfeed (0x0c)
                case '\f':
                {
                    result[pos + 1] = 'f';
                    pos += 2;
                    break;
                }

                // newline (0x0a)
                case '\n':
                {
                    result[pos + 1] = 'n';
                    pos += 2;
                    break;
                }

                // carriage return (0x0d)
                case '\r':
                {
                    result[pos + 1] = 'r';
                    pos += 2;
                    break;
                }

                // horizontal tab (0x09)
                case '\t':
                {
                    result[pos + 1] = 't';
                    pos += 2;
                    break;
                }

                default:
                {
                    if (c >= 0x00 and c <= 0x1f)
                    {
                        // convert a number 0..15 to its hex representation
                        // (0..f)
                        auto hexify = [](const char v) -> char
                        {
                            return (v < 10) ? ('0' + v) : ('a' + v - 10);
                        };

                        // print character c as \uxxxx
                        for (const char m :
                    { 'u', '0', '0', hexify(c >> 4), hexify(c & 0x0f)
                        })
                        {
                            result[++pos] = m;
                        }

                        ++pos;
                    }
                    else
                    {
                        // all other characters are added as-is
                        result[pos++] = c;
                    }
                    break;
                }
            }
        }

        return result;
    }

    /*!
    @brief internal implementation of the serialization function

    This function is called by the public member function dump and organizes
    the serialization internally. The indentation level is propagated as
    additional parameter. In case of arrays and objects, the function is called
    recursively. Note that

    - strings and object keys are escaped using `escape_string()`
    - integer numbers are converted implicitly via `operator<<`
    - floating-point numbers are converted to a string using `"%g"` format

    @param[out] o              stream to write to
    @param[in] pretty_print    whether the output shall be pretty-printed
    @param[in] indent_step     the indent level
    @param[in] current_indent  the current indent level (only used internally)
    */
    void dump(std::ostream& o,
              const bool pretty_print,
              const unsigned int indent_step,
              const unsigned int current_indent = 0) const
    {
        // variable to hold indentation for recursive calls
        unsigned int new_indent = current_indent;

        switch (m_type)
        {
            case value_t::object:
            {
                assert(m_value.object != nullptr);

                if (m_value.object->empty())
                {
                    o << "{}";
                    return;
                }

                o << "{";

                // increase indentation
                if (pretty_print)
                {
                    new_indent += indent_step;
                    o << "\n";
                }

                for (auto i = m_value.object->cbegin(); i != m_value.object->cend(); ++i)
                {
                    if (i != m_value.object->cbegin())
                    {
                        o << (pretty_print ? ",\n" : ",");
                    }
                    o << string_t(new_indent, ' ') << "\""
                      << escape_string(i->first) << "\":"
                      << (pretty_print ? " " : "");
                    i->second.dump(o, pretty_print, indent_step, new_indent);
                }

                // decrease indentation
                if (pretty_print)
                {
                    new_indent -= indent_step;
                    o << "\n";
                }

                o << string_t(new_indent, ' ') + "}";
                return;
            }

            case value_t::array:
            {
                assert(m_value.array != nullptr);

                if (m_value.array->empty())
                {
                    o << "[]";
                    return;
                }

                o << "[";

                // increase indentation
                if (pretty_print)
                {
                    new_indent += indent_step;
                    o << "\n";
                }

                for (auto i = m_value.array->cbegin(); i != m_value.array->cend(); ++i)
                {
                    if (i != m_value.array->cbegin())
                    {
                        o << (pretty_print ? ",\n" : ",");
                    }
                    o << string_t(new_indent, ' ');
                    i->dump(o, pretty_print, indent_step, new_indent);
                }

                // decrease indentation
                if (pretty_print)
                {
                    new_indent -= indent_step;
                    o << "\n";
                }

                o << string_t(new_indent, ' ') << "]";
                return;
            }

            case value_t::string:
            {
                assert(m_value.string != nullptr);
                o << string_t("\"") << escape_string(*m_value.string) << "\"";
                return;
            }

            case value_t::boolean:
            {
                o << (m_value.boolean ? "true" : "false");
                return;
            }

            case value_t::number_integer:
            {
                o << m_value.number_integer;
                return;
            }

            case value_t::number_unsigned:
            {
                o << m_value.number_unsigned;
                return;
            }

            case value_t::number_float:
            {
                // check if number was parsed from a string
                if (m_type.bits.parsed)
                {
                    // check if parsed number had an exponent given
                    if (m_type.bits.has_exp)
                    {
                        // buffer size: precision (2^8-1 = 255) + other ('-.e-xxx' = 7) + null (1)
                        char buf[263];
                        int len;

                        // handle capitalization of the exponent
                        if (m_type.bits.exp_cap)
                        {
                            len = snprintf(buf, sizeof(buf), "%.*E",
                                           m_type.bits.precision, m_value.number_float) + 1;
                        }
                        else
                        {
                            len = snprintf(buf, sizeof(buf), "%.*e",
                                           m_type.bits.precision, m_value.number_float) + 1;
                        }

                        // remove '+' sign from the exponent if necessary
                        if (not m_type.bits.exp_plus)
                        {
                            if (len > static_cast<int>(sizeof(buf)))
                            {
                                len = sizeof(buf);
                            }
                            for (int i = 0; i < len; i++)
                            {
                                if (buf[i] == '+')
                                {
                                    for (; i + 1 < len; i++)
                                    {
                                        buf[i] = buf[i + 1];
                                    }
                                }
                            }
                        }

                        o << buf;
                    }
                    else
                    {
                        // no exponent - output as a decimal
                        std::stringstream ss;
                        ss.imbue(std::locale(std::locale(), new DecimalSeparator));  // fix locale problems
                        ss << std::setprecision(m_type.bits.precision)
                           << std::fixed << m_value.number_float;
                        o << ss.str();
                    }
                }
                else
                {
                    if (m_value.number_float == 0)
                    {
                        // special case for zero to get "0.0"/"-0.0"
                        o << (std::signbit(m_value.number_float) ? "-0.0" : "0.0");
                    }
                    else
                    {
                        // Otherwise 6, 15 or 16 digits of precision allows
                        // round-trip IEEE 754 string->float->string,
                        // string->double->string or string->long double->string;
                        // to be safe, we read this value from
                        // std::numeric_limits<number_float_t>::digits10
                        std::stringstream ss;
                        ss.imbue(std::locale(std::locale(), new DecimalSeparator));  // fix locale problems
                        ss << std::setprecision(std::numeric_limits<double>::digits10)
                           << m_value.number_float;
                        o << ss.str();
                    }
                }
                return;
            }

            case value_t::discarded:
            {
                o << "<discarded>";
                return;
            }

            case value_t::null:
            {
                o << "null";
                return;
            }
        }
    }

  private:
    //////////////////////
    // member variables //
    //////////////////////

    /// the type of the current element
    type_data_t m_type = value_t::null;

    /// the value of the current element
    json_value m_value = {};


  private:
    ///////////////
    // iterators //
    ///////////////

    /*!
    @brief an iterator for primitive JSON types

    This class models an iterator for primitive JSON types (boolean, number,
    string). It's only purpose is to allow the iterator/const_iterator classes
    to "iterate" over primitive values. Internally, the iterator is modeled by
    a `difference_type` variable. Value begin_value (`0`) models the begin,
    end_value (`1`) models past the end.
    */
    class primitive_iterator_t
    {
      public:
        /// set iterator to a defined beginning
        void set_begin() noexcept
        {
            m_it = begin_value;
        }

        /// set iterator to a defined past the end
        void set_end() noexcept
        {
            m_it = end_value;
        }

        /// return whether the iterator can be dereferenced
        constexpr bool is_begin() const noexcept
        {
            return (m_it == begin_value);
        }

        /// return whether the iterator is at end
        constexpr bool is_end() const noexcept
        {
            return (m_it == end_value);
        }

        /// return reference to the value to change and compare
        operator difference_type& () noexcept
        {
            return m_it;
        }

        /// return value to compare
        constexpr operator difference_type () const noexcept
        {
            return m_it;
        }

      private:
        static constexpr difference_type begin_value = 0;
        static constexpr difference_type end_value = begin_value + 1;

        /// iterator as signed integer type
        difference_type m_it = std::numeric_limits<std::ptrdiff_t>::denorm_min();
    };

    /*!
    @brief an iterator value

    @note This structure could easily be a union, but MSVC currently does not
    allow unions members with complex constructors, see
    https://github.com/nlohmann/json/pull/105.
    */
    struct internal_iterator
    {
        /// iterator for JSON objects
        typename object_t::iterator object_iterator;
        /// iterator for JSON arrays
        typename array_t::iterator array_iterator;
        /// generic iterator for all other types
        primitive_iterator_t primitive_iterator;

        /// create an uninitialized internal_iterator
        internal_iterator() noexcept
            : object_iterator(), array_iterator(), primitive_iterator()
        {}
    };

    /// proxy class for the iterator_wrapper functions
    template<typename IteratorType>
    class iteration_proxy
    {
      private:
        /// helper class for iteration
        class iteration_proxy_internal
        {
          private:
            /// the iterator
            IteratorType anchor;
            /// an index for arrays (used to create key names)
            size_t array_index = 0;

          public:
            explicit iteration_proxy_internal(IteratorType it) noexcept
                : anchor(it)
            {}

            /// dereference operator (needed for range-based for)
            iteration_proxy_internal& operator*()
            {
                return *this;
            }

            /// increment operator (needed for range-based for)
            iteration_proxy_internal& operator++()
            {
                ++anchor;
                ++array_index;

                return *this;
            }

            /// inequality operator (needed for range-based for)
            bool operator!= (const iteration_proxy_internal& o) const
            {
                return anchor != o.anchor;
            }

            /// return key of the iterator
            typename basic_json::string_t key() const
            {
                assert(anchor.m_object != nullptr);

                switch (anchor.m_object->type())
                {
                    // use integer array index as key
                    case value_t::array:
                    {
                        return std::to_string(array_index);
                    }

                    // use key from the object
                    case value_t::object:
                    {
                        return anchor.key();
                    }

                    // use an empty key for all primitive types
                    default:
                    {
                        return "";
                    }
                }
            }

            /// return value of the iterator
            typename IteratorType::reference value() const
            {
                return anchor.value();
            }
        };

        /// the container to iterate
        typename IteratorType::reference container;

      public:
        /// construct iteration proxy from a container
        explicit iteration_proxy(typename IteratorType::reference cont)
            : container(cont)
        {}

        /// return iterator begin (needed for range-based for)
        iteration_proxy_internal begin() noexcept
        {
            return iteration_proxy_internal(container.begin());
        }

        /// return iterator end (needed for range-based for)
        iteration_proxy_internal end() noexcept
        {
            return iteration_proxy_internal(container.end());
        }
    };

  public:
    /*!
    @brief a const random access iterator for the @ref basic_json class

    This class implements a const iterator for the @ref basic_json class. From
    this class, the @ref iterator class is derived.

    @requirement The class satisfies the following concept requirements:
    - [RandomAccessIterator](http://en.cppreference.com/w/cpp/concept/RandomAccessIterator):
      The iterator that can be moved to point (forward and backward) to any
      element in constant time.

    @since version 1.0.0
    */
    class const_iterator : public std::iterator<std::random_access_iterator_tag, const basic_json>
    {
        /// allow basic_json to access private members
        friend class basic_json;

      public:
        /// the type of the values when the iterator is dereferenced
        using value_type = typename basic_json::value_type;
        /// a type to represent differences between iterators
        using difference_type = typename basic_json::difference_type;
        /// defines a pointer to the type iterated over (value_type)
        using pointer = typename basic_json::const_pointer;
        /// defines a reference to the type iterated over (value_type)
        using reference = typename basic_json::const_reference;
        /// the category of the iterator
        using iterator_category = std::bidirectional_iterator_tag;

        /// default constructor
        const_iterator() = default;

        /// constructor for a given JSON instance
        explicit const_iterator(pointer object) noexcept
            : m_object(object)
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    m_it.object_iterator = typename object_t::iterator();
                    break;
                }

                case basic_json::value_t::array:
                {
                    m_it.array_iterator = typename array_t::iterator();
                    break;
                }

                default:
                {
                    m_it.primitive_iterator = primitive_iterator_t();
                    break;
                }
            }
        }

        /// copy constructor given a nonconst iterator
        explicit const_iterator(const iterator& other) noexcept
            : m_object(other.m_object)
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    m_it.object_iterator = other.m_it.object_iterator;
                    break;
                }

                case basic_json::value_t::array:
                {
                    m_it.array_iterator = other.m_it.array_iterator;
                    break;
                }

                default:
                {
                    m_it.primitive_iterator = other.m_it.primitive_iterator;
                    break;
                }
            }
        }

        /// copy constructor
        const_iterator(const const_iterator& other) noexcept
            : m_object(other.m_object), m_it(other.m_it)
        {}

        /// copy assignment
        const_iterator& operator=(const_iterator other) noexcept(
            std::is_nothrow_move_constructible<pointer>::value and
            std::is_nothrow_move_assignable<pointer>::value and
            std::is_nothrow_move_constructible<internal_iterator>::value and
            std::is_nothrow_move_assignable<internal_iterator>::value
        )
        {
            std::swap(m_object, other.m_object);
            std::swap(m_it, other.m_it);
            return *this;
        }

      private:
        /// set the iterator to the first value
        void set_begin() noexcept
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    assert(m_object->m_value.object != nullptr);
                    m_it.object_iterator = m_object->m_value.object->begin();
                    break;
                }

                case basic_json::value_t::array:
                {
                    assert(m_object->m_value.array != nullptr);
                    m_it.array_iterator = m_object->m_value.array->begin();
                    break;
                }

                case basic_json::value_t::null:
                {
                    // set to end so begin()==end() is true: null is empty
                    m_it.primitive_iterator.set_end();
                    break;
                }

                default:
                {
                    m_it.primitive_iterator.set_begin();
                    break;
                }
            }
        }

        /// set the iterator past the last value
        void set_end() noexcept
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    assert(m_object->m_value.object != nullptr);
                    m_it.object_iterator = m_object->m_value.object->end();
                    break;
                }

                case basic_json::value_t::array:
                {
                    assert(m_object->m_value.array != nullptr);
                    m_it.array_iterator = m_object->m_value.array->end();
                    break;
                }

                default:
                {
                    m_it.primitive_iterator.set_end();
                    break;
                }
            }
        }

      public:
        /// return a reference to the value pointed to by the iterator
        reference operator*() const
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    assert(m_object->m_value.object);
                    assert(m_it.object_iterator != m_object->m_value.object->end());
                    return m_it.object_iterator->second;
                }

                case basic_json::value_t::array:
                {
                    assert(m_object->m_value.array);
                    assert(m_it.array_iterator != m_object->m_value.array->end());
                    return *m_it.array_iterator;
                }

                case basic_json::value_t::null:
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.primitive_iterator.is_begin())
                    {
                        return *m_object;
                    }
                    else
                    {
                        throw std::out_of_range("cannot get value");
                    }
                }
            }
        }

        /// dereference the iterator
        pointer operator->() const
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    assert(m_object->m_value.object);
                    assert(m_it.object_iterator != m_object->m_value.object->end());
                    return &(m_it.object_iterator->second);
                }

                case basic_json::value_t::array:
                {
                    assert(m_object->m_value.array);
                    assert(m_it.array_iterator != m_object->m_value.array->end());
                    return &*m_it.array_iterator;
                }

                default:
                {
                    if (m_it.primitive_iterator.is_begin())
                    {
                        return m_object;
                    }
                    else
                    {
                        throw std::out_of_range("cannot get value");
                    }
                }
            }
        }

        /// post-increment (it++)
        const_iterator operator++(int)
        {
            auto result = *this;
            ++(*this);
            return result;
        }

        /// pre-increment (++it)
        const_iterator& operator++()
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    ++m_it.object_iterator;
                    break;
                }

                case basic_json::value_t::array:
                {
                    ++m_it.array_iterator;
                    break;
                }

                default:
                {
                    ++m_it.primitive_iterator;
                    break;
                }
            }

            return *this;
        }

        /// post-decrement (it--)
        const_iterator operator--(int)
        {
            auto result = *this;
            --(*this);
            return result;
        }

        /// pre-decrement (--it)
        const_iterator& operator--()
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    --m_it.object_iterator;
                    break;
                }

                case basic_json::value_t::array:
                {
                    --m_it.array_iterator;
                    break;
                }

                default:
                {
                    --m_it.primitive_iterator;
                    break;
                }
            }

            return *this;
        }

        /// comparison: equal
        bool operator==(const const_iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    return (m_it.object_iterator == other.m_it.object_iterator);
                }

                case basic_json::value_t::array:
                {
                    return (m_it.array_iterator == other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.primitive_iterator == other.m_it.primitive_iterator);
                }
            }
        }

        /// comparison: not equal
        bool operator!=(const const_iterator& other) const
        {
            return not operator==(other);
        }

        /// comparison: smaller
        bool operator<(const const_iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    throw std::domain_error("cannot compare order of object iterators");
                }

                case basic_json::value_t::array:
                {
                    return (m_it.array_iterator < other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.primitive_iterator < other.m_it.primitive_iterator);
                }
            }
        }

        /// comparison: less than or equal
        bool operator<=(const const_iterator& other) const
        {
            return not other.operator < (*this);
        }

        /// comparison: greater than
        bool operator>(const const_iterator& other) const
        {
            return not operator<=(other);
        }

        /// comparison: greater than or equal
        bool operator>=(const const_iterator& other) const
        {
            return not operator<(other);
        }

        /// add to iterator
        const_iterator& operator+=(difference_type i)
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    throw std::domain_error("cannot use offsets with object iterators");
                }

                case basic_json::value_t::array:
                {
                    m_it.array_iterator += i;
                    break;
                }

                default:
                {
                    m_it.primitive_iterator += i;
                    break;
                }
            }

            return *this;
        }

        /// subtract from iterator
        const_iterator& operator-=(difference_type i)
        {
            return operator+=(-i);
        }

        /// add to iterator
        const_iterator operator+(difference_type i)
        {
            auto result = *this;
            result += i;
            return result;
        }

        /// subtract from iterator
        const_iterator operator-(difference_type i)
        {
            auto result = *this;
            result -= i;
            return result;
        }

        /// return difference
        difference_type operator-(const const_iterator& other) const
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    throw std::domain_error("cannot use offsets with object iterators");
                }

                case basic_json::value_t::array:
                {
                    return m_it.array_iterator - other.m_it.array_iterator;
                }

                default:
                {
                    return m_it.primitive_iterator - other.m_it.primitive_iterator;
                }
            }
        }

        /// access to successor
        reference operator[](difference_type n) const
        {
            assert(m_object != nullptr);

            switch (m_object->m_type)
            {
                case basic_json::value_t::object:
                {
                    throw std::domain_error("cannot use operator[] for object iterators");
                }

                case basic_json::value_t::array:
                {
                    return *(m_it.array_iterator + n);
                }

                case basic_json::value_t::null:
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.primitive_iterator == -n)
                    {
                        return *m_object;
                    }
                    else
                    {
                        throw std::out_of_range("cannot get value");
                    }
                }
            }
        }

        /// return the key of an object iterator
        typename object_t::key_type key() const
        {
            assert(m_object != nullptr);

            if (m_object->is_object())
            {
                return m_it.object_iterator->first;
            }
            else
            {
                throw std::domain_error("cannot use key() for non-object iterators");
            }
        }

        /// return the value of an iterator
        reference value() const
        {
            return operator*();
        }

      private:
        /// associated JSON instance
        pointer m_object = nullptr;
        /// the actual iterator of the associated instance
        internal_iterator m_it = internal_iterator();
    };

    /*!
    @brief a mutable random access iterator for the @ref basic_json class

    @requirement The class satisfies the following concept requirements:
    - [RandomAccessIterator](http://en.cppreference.com/w/cpp/concept/RandomAccessIterator):
      The iterator that can be moved to point (forward and backward) to any
      element in constant time.
    - [OutputIterator](http://en.cppreference.com/w/cpp/concept/OutputIterator):
      It is possible to write to the pointed-to element.

    @since version 1.0.0
    */
    class iterator : public const_iterator
    {
      public:
        using base_iterator = const_iterator;
        using pointer = typename basic_json::pointer;
        using reference = typename basic_json::reference;

        /// default constructor
        iterator() = default;

        /// constructor for a given JSON instance
        explicit iterator(pointer object) noexcept
            : base_iterator(object)
        {}

        /// copy constructor
        iterator(const iterator& other) noexcept
            : base_iterator(other)
        {}

        /// copy assignment
        iterator& operator=(iterator other) noexcept(
            std::is_nothrow_move_constructible<pointer>::value and
            std::is_nothrow_move_assignable<pointer>::value and
            std::is_nothrow_move_constructible<internal_iterator>::value and
            std::is_nothrow_move_assignable<internal_iterator>::value
        )
        {
            base_iterator::operator=(other);
            return *this;
        }

        /// return a reference to the value pointed to by the iterator
        reference operator*()
        {
            return const_cast<reference>(base_iterator::operator*());
        }

        /// dereference the iterator
        pointer operator->()
        {
            return const_cast<pointer>(base_iterator::operator->());
        }

        /// post-increment (it++)
        iterator operator++(int)
        {
            iterator result = *this;
            base_iterator::operator++();
            return result;
        }

        /// pre-increment (++it)
        iterator& operator++()
        {
            base_iterator::operator++();
            return *this;
        }

        /// post-decrement (it--)
        iterator operator--(int)
        {
            iterator result = *this;
            base_iterator::operator--();
            return result;
        }

        /// pre-decrement (--it)
        iterator& operator--()
        {
            base_iterator::operator--();
            return *this;
        }

        /// add to iterator
        iterator& operator+=(difference_type i)
        {
            base_iterator::operator+=(i);
            return *this;
        }

        /// subtract from iterator
        iterator& operator-=(difference_type i)
        {
            base_iterator::operator-=(i);
            return *this;
        }

        /// add to iterator
        iterator operator+(difference_type i)
        {
            auto result = *this;
            result += i;
            return result;
        }

        /// subtract from iterator
        iterator operator-(difference_type i)
        {
            auto result = *this;
            result -= i;
            return result;
        }

        /// return difference
        difference_type operator-(const iterator& other) const
        {
            return base_iterator::operator-(other);
        }

        /// access to successor
        reference operator[](difference_type n) const
        {
            return const_cast<reference>(base_iterator::operator[](n));
        }

        /// return the value of an iterator
        reference value() const
        {
            return const_cast<reference>(base_iterator::value());
        }
    };

    /*!
    @brief a template for a reverse iterator class

    @tparam Base the base iterator type to reverse. Valid types are @ref
    iterator (to create @ref reverse_iterator) and @ref const_iterator (to
    create @ref const_reverse_iterator).

    @requirement The class satisfies the following concept requirements:
    - [RandomAccessIterator](http://en.cppreference.com/w/cpp/concept/RandomAccessIterator):
      The iterator that can be moved to point (forward and backward) to any
      element in constant time.
    - [OutputIterator](http://en.cppreference.com/w/cpp/concept/OutputIterator):
      It is possible to write to the pointed-to element (only if @a Base is
      @ref iterator).

    @since version 1.0.0
    */
    template<typename Base>
    class json_reverse_iterator : public std::reverse_iterator<Base>
    {
      public:
        /// shortcut to the reverse iterator adaptor
        using base_iterator = std::reverse_iterator<Base>;
        /// the reference type for the pointed-to element
        using reference = typename Base::reference;

        /// create reverse iterator from iterator
        json_reverse_iterator(const typename base_iterator::iterator_type& it) noexcept
            : base_iterator(it)
        {}

        /// create reverse iterator from base class
        json_reverse_iterator(const base_iterator& it) noexcept
            : base_iterator(it)
        {}

        /// post-increment (it++)
        json_reverse_iterator operator++(int)
        {
            return base_iterator::operator++(1);
        }

        /// pre-increment (++it)
        json_reverse_iterator& operator++()
        {
            base_iterator::operator++();
            return *this;
        }

        /// post-decrement (it--)
        json_reverse_iterator operator--(int)
        {
            return base_iterator::operator--(1);
        }

        /// pre-decrement (--it)
        json_reverse_iterator& operator--()
        {
            base_iterator::operator--();
            return *this;
        }

        /// add to iterator
        json_reverse_iterator& operator+=(difference_type i)
        {
            base_iterator::operator+=(i);
            return *this;
        }

        /// add to iterator
        json_reverse_iterator operator+(difference_type i) const
        {
            auto result = *this;
            result += i;
            return result;
        }

        /// subtract from iterator
        json_reverse_iterator operator-(difference_type i) const
        {
            auto result = *this;
            result -= i;
            return result;
        }

        /// return difference
        difference_type operator-(const json_reverse_iterator& other) const
        {
            return this->base() - other.base();
        }

        /// access to successor
        reference operator[](difference_type n) const
        {
            return *(this->operator+(n));
        }

        /// return the key of an object iterator
        typename object_t::key_type key() const
        {
            auto it = --this->base();
            return it.key();
        }

        /// return the value of an iterator
        reference value() const
        {
            auto it = --this->base();
            return it.operator * ();
        }
    };


  private:
    //////////////////////
    // lexer and parser //
    //////////////////////

    /*!
    @brief lexical analysis

    This class organizes the lexical analysis during JSON deserialization. The
    core of it is a scanner generated by [re2c](http://re2c.org) that processes
    a buffer and recognizes tokens according to RFC 7159.
    */
    class lexer
    {
      public:
        /// token types for the parser
        enum class token_type
        {
            uninitialized,   ///< indicating the scanner is uninitialized
            literal_true,    ///< the "true" literal
            literal_false,   ///< the "false" literal
            literal_null,    ///< the "null" literal
            value_string,    ///< a string -- use get_string() for actual value
            value_number,    ///< a number -- use get_number() for actual value
            begin_array,     ///< the character for array begin "["
            begin_object,    ///< the character for object begin "{"
            end_array,       ///< the character for array end "]"
            end_object,      ///< the character for object end "}"
            name_separator,  ///< the name separator ":"
            value_separator, ///< the value separator ","
            parse_error,     ///< indicating a parse error
            end_of_input     ///< indicating the end of the input buffer
        };

        /// the char type to use in the lexer
        using lexer_char_t = unsigned char;

        /// constructor with a given buffer
        explicit lexer(const string_t& s) noexcept
            : m_stream(nullptr), m_buffer(s)
        {
            m_content = reinterpret_cast<const lexer_char_t*>(s.c_str());
            assert(m_content != nullptr);
            m_start = m_cursor = m_content;
            m_limit = m_content + s.size();
        }

        /// constructor with a given stream
        explicit lexer(std::istream* s) noexcept
            : m_stream(s), m_buffer()
        {
            assert(m_stream != nullptr);
            getline(*m_stream, m_buffer);
            m_content = reinterpret_cast<const lexer_char_t*>(m_buffer.c_str());
            assert(m_content != nullptr);
            m_start = m_cursor = m_content;
            m_limit = m_content + m_buffer.size();
        }

        /// default constructor
        lexer() = default;

        // switch off unwanted functions
        lexer(const lexer&) = delete;
        lexer operator=(const lexer&) = delete;

        /*!
        @brief create a string from a Unicode code point

        @param[in] codepoint1  the code point (can be high surrogate)
        @param[in] codepoint2  the code point (can be low surrogate or 0)

        @return string representation of the code point

        @throw std::out_of_range if code point is >0x10ffff; example: `"code
        points above 0x10FFFF are invalid"`
        @throw std::invalid_argument if the low surrogate is invalid; example:
        `""missing or wrong low surrogate""`

        @see <http://en.wikipedia.org/wiki/UTF-8#Sample_code>
        */
        static string_t to_unicode(const std::size_t codepoint1,
                                   const std::size_t codepoint2 = 0)
        {
            // calculate the codepoint from the given code points
            std::size_t codepoint = codepoint1;

            // check if codepoint1 is a high surrogate
            if (codepoint1 >= 0xD800 and codepoint1 <= 0xDBFF)
            {
                // check if codepoint2 is a low surrogate
                if (codepoint2 >= 0xDC00 and codepoint2 <= 0xDFFF)
                {
                    codepoint =
                        // high surrogate occupies the most significant 22 bits
                        (codepoint1 << 10)
                        // low surrogate occupies the least significant 15 bits
                        + codepoint2
                        // there is still the 0xD800, 0xDC00 and 0x10000 noise
                        // in the result so we have to subtract with:
                        // (0xD800 << 10) + DC00 - 0x10000 = 0x35FDC00
                        - 0x35FDC00;
                }
                else
                {
                    throw std::invalid_argument("missing or wrong low surrogate");
                }
            }

            string_t result;

            if (codepoint < 0x80)
            {
                // 1-byte characters: 0xxxxxxx (ASCII)
                result.append(1, static_cast<typename string_t::value_type>(codepoint));
            }
            else if (codepoint <= 0x7ff)
            {
                // 2-byte characters: 110xxxxx 10xxxxxx
                result.append(1, static_cast<typename string_t::value_type>(0xC0 | ((codepoint >> 6) & 0x1F)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | (codepoint & 0x3F)));
            }
            else if (codepoint <= 0xffff)
            {
                // 3-byte characters: 1110xxxx 10xxxxxx 10xxxxxx
                result.append(1, static_cast<typename string_t::value_type>(0xE0 | ((codepoint >> 12) & 0x0F)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | ((codepoint >> 6) & 0x3F)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | (codepoint & 0x3F)));
            }
            else if (codepoint <= 0x10ffff)
            {
                // 4-byte characters: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
                result.append(1, static_cast<typename string_t::value_type>(0xF0 | ((codepoint >> 18) & 0x07)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | ((codepoint >> 12) & 0x3F)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | ((codepoint >> 6) & 0x3F)));
                result.append(1, static_cast<typename string_t::value_type>(0x80 | (codepoint & 0x3F)));
            }
            else
            {
                throw std::out_of_range("code points above 0x10FFFF are invalid");
            }

            return result;
        }

        /// return name of values of type token_type (only used for errors)
        static std::string token_type_name(token_type t)
        {
            switch (t)
            {
                case token_type::uninitialized:
                    return "<uninitialized>";
                case token_type::literal_true:
                    return "true literal";
                case token_type::literal_false:
                    return "false literal";
                case token_type::literal_null:
                    return "null literal";
                case token_type::value_string:
                    return "string literal";
                case token_type::value_number:
                    return "number literal";
                case token_type::begin_array:
                    return "'['";
                case token_type::begin_object:
                    return "'{'";
                case token_type::end_array:
                    return "']'";
                case token_type::end_object:
                    return "'}'";
                case token_type::name_separator:
                    return "':'";
                case token_type::value_separator:
                    return "','";
                case token_type::parse_error:
                    return "<parse error>";
                case token_type::end_of_input:
                    return "end of input";
                default:
                {
                    // catch non-enum values
                    return "unknown token"; // LCOV_EXCL_LINE
                }
            }
        }

        /*!
        This function implements a scanner for JSON. It is specified using
        regular expressions that try to follow RFC 7159 as close as possible.
        These regular expressions are then translated into a minimized
        deterministic finite automaton (DFA) by the tool
        [re2c](http://re2c.org). As a result, the translated code for this
        function consists of a large block of code with `goto` jumps.

        @return the class of the next token read from the buffer
        */
        token_type scan() noexcept
        {
            // pointer for backtracking information
            m_marker = nullptr;

            // remember the begin of the token
            m_start = m_cursor;
            assert(m_start != nullptr);


            {
                lexer_char_t yych;
                unsigned int yyaccept = 0;
                static const unsigned char yybm[] =
                {
                    0,   0,   0,   0,   0,   0,   0,   0,
                    0,  32,  32,   0,   0,  32,   0,   0,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    96,  64,   0,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    192, 192, 192, 192, 192, 192, 192, 192,
                    192, 192,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,   0,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                    64,  64,  64,  64,  64,  64,  64,  64,
                };
                if ((m_limit - m_cursor) < 5)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= ':')
                {
                    if (yych <= ' ')
                    {
                        if (yych <= '\n')
                        {
                            if (yych <= 0x00)
                            {
                                goto basic_json_parser_28;
                            }
                            if (yych <= 0x08)
                            {
                                goto basic_json_parser_30;
                            }
                            if (yych >= '\n')
                            {
                                goto basic_json_parser_4;
                            }
                        }
                        else
                        {
                            if (yych == '\r')
                            {
                                goto basic_json_parser_2;
                            }
                            if (yych <= 0x1F)
                            {
                                goto basic_json_parser_30;
                            }
                        }
                    }
                    else
                    {
                        if (yych <= ',')
                        {
                            if (yych == '"')
                            {
                                goto basic_json_parser_27;
                            }
                            if (yych <= '+')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_16;
                        }
                        else
                        {
                            if (yych <= '/')
                            {
                                if (yych <= '-')
                                {
                                    goto basic_json_parser_23;
                                }
                                goto basic_json_parser_30;
                            }
                            else
                            {
                                if (yych <= '0')
                                {
                                    goto basic_json_parser_24;
                                }
                                if (yych <= '9')
                                {
                                    goto basic_json_parser_26;
                                }
                                goto basic_json_parser_18;
                            }
                        }
                    }
                }
                else
                {
                    if (yych <= 'n')
                    {
                        if (yych <= ']')
                        {
                            if (yych == '[')
                            {
                                goto basic_json_parser_8;
                            }
                            if (yych <= '\\')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_10;
                        }
                        else
                        {
                            if (yych == 'f')
                            {
                                goto basic_json_parser_22;
                            }
                            if (yych <= 'm')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_20;
                        }
                    }
                    else
                    {
                        if (yych <= '{')
                        {
                            if (yych == 't')
                            {
                                goto basic_json_parser_21;
                            }
                            if (yych <= 'z')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_12;
                        }
                        else
                        {
                            if (yych <= '}')
                            {
                                if (yych <= '|')
                                {
                                    goto basic_json_parser_30;
                                }
                                goto basic_json_parser_14;
                            }
                            else
                            {
                                if (yych == 0xEF)
                                {
                                    goto basic_json_parser_6;
                                }
                                goto basic_json_parser_30;
                            }
                        }
                    }
                }
basic_json_parser_2:
                ++m_cursor;
                yych = *m_cursor;
                goto basic_json_parser_5;
basic_json_parser_3:
                {
                    return scan();
                }
basic_json_parser_4:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
basic_json_parser_5:
                if (yybm[0 + yych] & 32)
                {
                    goto basic_json_parser_4;
                }
                goto basic_json_parser_3;
basic_json_parser_6:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 0xBB)
                {
                    goto basic_json_parser_64;
                }
basic_json_parser_7:
                {
                    return token_type::parse_error;
                }
basic_json_parser_8:
                ++m_cursor;
                {
                    return token_type::begin_array;
                }
basic_json_parser_10:
                ++m_cursor;
                {
                    return token_type::end_array;
                }
basic_json_parser_12:
                ++m_cursor;
                {
                    return token_type::begin_object;
                }
basic_json_parser_14:
                ++m_cursor;
                {
                    return token_type::end_object;
                }
basic_json_parser_16:
                ++m_cursor;
                {
                    return token_type::value_separator;
                }
basic_json_parser_18:
                ++m_cursor;
                {
                    return token_type::name_separator;
                }
basic_json_parser_20:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'u')
                {
                    goto basic_json_parser_60;
                }
                goto basic_json_parser_7;
basic_json_parser_21:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'r')
                {
                    goto basic_json_parser_56;
                }
                goto basic_json_parser_7;
basic_json_parser_22:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'a')
                {
                    goto basic_json_parser_51;
                }
                goto basic_json_parser_7;
basic_json_parser_23:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_7;
                }
                if (yych <= '0')
                {
                    goto basic_json_parser_50;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_41;
                }
                goto basic_json_parser_7;
basic_json_parser_24:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 'D')
                {
                    if (yych == '.')
                    {
                        goto basic_json_parser_43;
                    }
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_44;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_44;
                    }
                }
basic_json_parser_25:
                {
                    return token_type::value_number;
                }
basic_json_parser_26:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                goto basic_json_parser_42;
basic_json_parser_27:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 0x0F)
                {
                    goto basic_json_parser_7;
                }
                goto basic_json_parser_32;
basic_json_parser_28:
                ++m_cursor;
                {
                    return token_type::end_of_input;
                }
basic_json_parser_30:
                yych = *++m_cursor;
                goto basic_json_parser_7;
basic_json_parser_31:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
basic_json_parser_32:
                if (yybm[0 + yych] & 64)
                {
                    goto basic_json_parser_31;
                }
                if (yych <= 0x0F)
                {
                    goto basic_json_parser_33;
                }
                if (yych <= '"')
                {
                    goto basic_json_parser_35;
                }
                goto basic_json_parser_34;
basic_json_parser_33:
                m_cursor = m_marker;
                if (yyaccept == 0)
                {
                    goto basic_json_parser_7;
                }
                else
                {
                    goto basic_json_parser_25;
                }
basic_json_parser_34:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= 'e')
                {
                    if (yych <= '/')
                    {
                        if (yych == '"')
                        {
                            goto basic_json_parser_31;
                        }
                        if (yych <= '.')
                        {
                            goto basic_json_parser_33;
                        }
                        goto basic_json_parser_31;
                    }
                    else
                    {
                        if (yych <= '\\')
                        {
                            if (yych <= '[')
                            {
                                goto basic_json_parser_33;
                            }
                            goto basic_json_parser_31;
                        }
                        else
                        {
                            if (yych == 'b')
                            {
                                goto basic_json_parser_31;
                            }
                            goto basic_json_parser_33;
                        }
                    }
                }
                else
                {
                    if (yych <= 'q')
                    {
                        if (yych <= 'f')
                        {
                            goto basic_json_parser_31;
                        }
                        if (yych == 'n')
                        {
                            goto basic_json_parser_31;
                        }
                        goto basic_json_parser_33;
                    }
                    else
                    {
                        if (yych <= 's')
                        {
                            if (yych <= 'r')
                            {
                                goto basic_json_parser_31;
                            }
                            goto basic_json_parser_33;
                        }
                        else
                        {
                            if (yych <= 't')
                            {
                                goto basic_json_parser_31;
                            }
                            if (yych <= 'u')
                            {
                                goto basic_json_parser_37;
                            }
                            goto basic_json_parser_33;
                        }
                    }
                }
basic_json_parser_35:
                ++m_cursor;
                {
                    return token_type::value_string;
                }
basic_json_parser_37:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_33;
                    }
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_38;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_33;
                    }
                }
basic_json_parser_38:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_33;
                    }
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_39;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_33;
                    }
                }
basic_json_parser_39:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_33;
                    }
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_40;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_33;
                    }
                }
basic_json_parser_40:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_31;
                    }
                    goto basic_json_parser_33;
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_31;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych <= 'f')
                    {
                        goto basic_json_parser_31;
                    }
                    goto basic_json_parser_33;
                }
basic_json_parser_41:
                yyaccept = 1;
                m_marker = ++m_cursor;
                if ((m_limit - m_cursor) < 3)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
basic_json_parser_42:
                if (yybm[0 + yych] & 128)
                {
                    goto basic_json_parser_41;
                }
                if (yych <= 'D')
                {
                    if (yych != '.')
                    {
                        goto basic_json_parser_25;
                    }
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_44;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_44;
                    }
                    goto basic_json_parser_25;
                }
basic_json_parser_43:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_33;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_48;
                }
                goto basic_json_parser_33;
basic_json_parser_44:
                yych = *++m_cursor;
                if (yych <= ',')
                {
                    if (yych != '+')
                    {
                        goto basic_json_parser_33;
                    }
                }
                else
                {
                    if (yych <= '-')
                    {
                        goto basic_json_parser_45;
                    }
                    if (yych <= '/')
                    {
                        goto basic_json_parser_33;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_46;
                    }
                    goto basic_json_parser_33;
                }
basic_json_parser_45:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_33;
                }
                if (yych >= ':')
                {
                    goto basic_json_parser_33;
                }
basic_json_parser_46:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_25;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_46;
                }
                goto basic_json_parser_25;
basic_json_parser_48:
                yyaccept = 1;
                m_marker = ++m_cursor;
                if ((m_limit - m_cursor) < 3)
                {
                    yyfill();    // LCOV_EXCL_LINE;
                }
                yych = *m_cursor;
                if (yych <= 'D')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_25;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_48;
                    }
                    goto basic_json_parser_25;
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_44;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_44;
                    }
                    goto basic_json_parser_25;
                }
basic_json_parser_50:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 'D')
                {
                    if (yych == '.')
                    {
                        goto basic_json_parser_43;
                    }
                    goto basic_json_parser_25;
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_44;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_44;
                    }
                    goto basic_json_parser_25;
                }
basic_json_parser_51:
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_33;
                }
                yych = *++m_cursor;
                if (yych != 's')
                {
                    goto basic_json_parser_33;
                }
                yych = *++m_cursor;
                if (yych != 'e')
                {
                    goto basic_json_parser_33;
                }
                ++m_cursor;
                {
                    return token_type::literal_false;
                }
basic_json_parser_56:
                yych = *++m_cursor;
                if (yych != 'u')
                {
                    goto basic_json_parser_33;
                }
                yych = *++m_cursor;
                if (yych != 'e')
                {
                    goto basic_json_parser_33;
                }
                ++m_cursor;
                {
                    return token_type::literal_true;
                }
basic_json_parser_60:
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_33;
                }
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_33;
                }
                ++m_cursor;
                {
                    return token_type::literal_null;
                }
basic_json_parser_64:
                yych = *++m_cursor;
                if (yych != 0xBF)
                {
                    goto basic_json_parser_33;
                }
                ++m_cursor;
                {
                    return scan();
                }
            }

        }

        /// append data from the stream to the internal buffer
        void yyfill() noexcept
        {
            if (m_stream == nullptr or not * m_stream)
            {
                return;
            }

            const auto offset_start = m_start - m_content;
            const auto offset_marker = m_marker - m_start;
            const auto offset_cursor = m_cursor - m_start;

            m_buffer.erase(0, static_cast<size_t>(offset_start));
            std::string line;
            assert(m_stream != nullptr);
            std::getline(*m_stream, line);
            m_buffer += "\n" + line; // add line with newline symbol

            m_content = reinterpret_cast<const lexer_char_t*>(m_buffer.c_str());
            assert(m_content != nullptr);
            m_start  = m_content;
            m_marker = m_start + offset_marker;
            m_cursor = m_start + offset_cursor;
            m_limit  = m_start + m_buffer.size() - 1;
        }

        /// return string representation of last read token
        string_t get_token() const
        {
            assert(m_start != nullptr);
            return string_t(reinterpret_cast<typename string_t::const_pointer>(m_start),
                            static_cast<size_t>(m_cursor - m_start));
        }

        /*!
        @brief return string value for string tokens

        The function iterates the characters between the opening and closing
        quotes of the string value. The complete string is the range
        [m_start,m_cursor). Consequently, we iterate from m_start+1 to
        m_cursor-1.

        We differentiate two cases:

        1. Escaped characters. In this case, a new character is constructed
           according to the nature of the escape. Some escapes create new
           characters (e.g., `"\\n"` is replaced by `"\n"`), some are copied as
           is (e.g., `"\\\\"`). Furthermore, Unicode escapes of the shape
           `"\\uxxxx"` need special care. In this case, to_unicode takes care
           of the construction of the values.
        2. Unescaped characters are copied as is.

        @return string value of current token without opening and closing quotes
        @throw std::out_of_range if to_unicode fails
        */
        string_t get_string() const
        {
            string_t result;
            result.reserve(static_cast<size_t>(m_cursor - m_start - 2));

            // iterate the result between the quotes
            for (const lexer_char_t* i = m_start + 1; i < m_cursor - 1; ++i)
            {
                // process escaped characters
                if (*i == '\\')
                {
                    // read next character
                    ++i;

                    switch (*i)
                    {
                        // the default escapes
                        case 't':
                        {
                            result += "\t";
                            break;
                        }
                        case 'b':
                        {
                            result += "\b";
                            break;
                        }
                        case 'f':
                        {
                            result += "\f";
                            break;
                        }
                        case 'n':
                        {
                            result += "\n";
                            break;
                        }
                        case 'r':
                        {
                            result += "\r";
                            break;
                        }
                        case '\\':
                        {
                            result += "\\";
                            break;
                        }
                        case '/':
                        {
                            result += "/";
                            break;
                        }
                        case '"':
                        {
                            result += "\"";
                            break;
                        }

                        // unicode
                        case 'u':
                        {
                            // get code xxxx from uxxxx
                            auto codepoint = std::strtoul(std::string(reinterpret_cast<typename string_t::const_pointer>(i + 1),
                                                          4).c_str(), nullptr, 16);

                            // check if codepoint is a high surrogate
                            if (codepoint >= 0xD800 and codepoint <= 0xDBFF)
                            {
                                // make sure there is a subsequent unicode
                                if ((i + 6 >= m_limit) or * (i + 5) != '\\' or * (i + 6) != 'u')
                                {
                                    throw std::invalid_argument("missing low surrogate");
                                }

                                // get code yyyy from uxxxx\uyyyy
                                auto codepoint2 = std::strtoul(std::string(reinterpret_cast<typename string_t::const_pointer>
                                                               (i + 7), 4).c_str(), nullptr, 16);
                                result += to_unicode(codepoint, codepoint2);
                                // skip the next 10 characters (xxxx\uyyyy)
                                i += 10;
                            }
                            else
                            {
                                // add unicode character(s)
                                result += to_unicode(codepoint);
                                // skip the next four characters (xxxx)
                                i += 4;
                            }
                            break;
                        }
                    }
                }
                else
                {
                    // all other characters are just copied to the end of the
                    // string
                    result.append(1, static_cast<typename string_t::value_type>(*i));
                }
            }

            return result;
        }

        /*!
        @brief parse floating point number

        This function (and its overloads) serves to select the most approprate
        standard floating point number parsing function based on the type
        supplied via the first parameter.  Set this to
        @a static_cast<number_float_t*>(nullptr).

        @param[in] type  the @ref number_float_t in use

        @param[in,out] endptr recieves a pointer to the first character after
        the number

        @return the floating point number

        @bug This function uses `std::strtof`, `std::strtod`, or `std::strtold`
        which use the current C locale to determine which character is used as
        decimal point character. This may yield to parse errors if the locale
        does not used `.`.
        */
        long double str_to_float_t(long double* /* type */, char** endptr) const
        {
            return std::strtold(reinterpret_cast<typename string_t::const_pointer>(m_start), endptr);
        }

        /*!
        @brief parse floating point number

        This function (and its overloads) serves to select the most approprate
        standard floating point number parsing function based on the type
        supplied via the first parameter.  Set this to
        @a static_cast<number_float_t*>(nullptr).

        @param[in] type  the @ref number_float_t in use

        @param[in,out] endptr  recieves a pointer to the first character after
        the number

        @return the floating point number
        */
        double str_to_float_t(double* /* type */, char** endptr) const
        {
            return std::strtod(reinterpret_cast<typename string_t::const_pointer>(m_start), endptr);
        }

        /*!
        @brief parse floating point number

        This function (and its overloads) serves to select the most approprate
        standard floating point number parsing function based on the type
        supplied via the first parameter.  Set this to
        @a static_cast<number_float_t*>(nullptr).

        @param[in] type  the @ref number_float_t in use

        @param[in,out] endptr  recieves a pointer to the first character after
        the number

        @return the floating point number
        */
        float str_to_float_t(float* /* type */, char** endptr) const
        {
            return std::strtof(reinterpret_cast<typename string_t::const_pointer>(m_start), endptr);
        }

        /*!
        @brief return number value for number tokens

        This function translates the last token into the most appropriate
        number type (either integer, unsigned integer or floating point),
        which is passed back to the caller via the result parameter.

        This function parses the integer component up to the radix point or
        exponent while collecting information about the 'floating point
        representation', which it stores in the result parameter. If there is
        no radix point or exponent, and the number can fit into a
        @ref number_integer_t or @ref number_unsigned_t then it sets the
        result parameter accordingly.

        The 'floating point representation' includes the number of significant
        figures after the radix point, whether the number is in exponential
        or decimal form, the capitalization of the exponent marker, and if the
        optional '+' is present in the exponent. This information is necessary
        to perform accurate round trips of floating point numbers.

        If the number is a floating point number the number is then parsed
        using @a std:strtod (or @a std:strtof or @a std::strtold).

        @param[out] result  @ref basic_json object to receive the number, or
          NAN if the conversion read past the current token. The latter case
          needs to be treated by the caller function.
        */
        void get_number(basic_json& result) const
        {
            assert(m_start != nullptr);

            const lexer::lexer_char_t* curptr = m_start;

            // remember this number was parsed (for later serialization)
            result.m_type.bits.parsed = true;

            // 'found_radix_point' will be set to 0xFF upon finding a radix
            // point and later used to mask in/out the precision depending
            // whether a radix is found i.e. 'precision &= found_radix_point'
            uint8_t found_radix_point = 0;
            uint8_t precision = 0;

            // accumulate the integer conversion result (unsigned for now)
            number_unsigned_t value = 0;

            // maximum absolute value of the relevant integer type
            number_unsigned_t max;

            // temporarily store the type to avoid unecessary bitfield access
            value_t type;

            // look for sign
            if (*curptr == '-')
            {
                type = value_t::number_integer;
                max = static_cast<uint64_t>(std::numeric_limits<number_integer_t>::max()) + 1;
                curptr++;
            }
            else
            {
                type = value_t::number_unsigned;
                max = static_cast<uint64_t>(std::numeric_limits<number_unsigned_t>::max());
                if (*curptr == '+')
                {
                    curptr++;
                }
            }

            // count the significant figures
            for (; curptr < m_cursor; curptr++)
            {
                // quickly skip tests if a digit
                if (*curptr < '0' || *curptr > '9')
                {
                    if (*curptr == '.')
                    {
                        // don't count '.' but change to float
                        type = value_t::number_float;

                        // reset precision count
                        precision = 0;
                        found_radix_point = 0xFF;
                        continue;
                    }
                    // assume exponent (if not then will fail parse): change to
                    // float, stop counting and record exponent details
                    type = value_t::number_float;
                    result.m_type.bits.has_exp = true;

                    // exponent capitalization
                    result.m_type.bits.exp_cap = (*curptr == 'E');

                    // exponent '+' sign
                    result.m_type.bits.exp_plus = (*(++curptr) == '+');
                    break;
                }

                // skip if definitely not an integer
                if (type != value_t::number_float)
                {
                    // multiply last value by ten and add the new digit
                    auto temp = value * 10 + *curptr - 0x30;

                    // test for overflow
                    if (temp < value || temp > max)
                    {
                        // overflow
                        type = value_t::number_float;
                    }
                    else
                    {
                        // no overflow - save it
                        value = temp;
                    }
                }
                ++precision;
            }

            // If no radix point was found then precision would now be set to
            // the number of digits, which is wrong - clear it.
            result.m_type.bits.precision = precision & found_radix_point;

            // save the value (if not a float)
            if (type == value_t::number_unsigned)
            {
                result.m_value.number_unsigned = value;
            }
            else if (type == value_t::number_integer)
            {
                result.m_value.number_integer = -static_cast<number_integer_t>(value);
            }
            else
            {
                // parse with strtod
                result.m_value.number_float = str_to_float_t(static_cast<number_float_t*>(nullptr), NULL);
            }

            // save the type
            result.m_type = type;
        }

      private:
        /// optional input stream
        std::istream* m_stream = nullptr;
        /// the buffer
        string_t m_buffer;
        /// the buffer pointer
        const lexer_char_t* m_content = nullptr;
        /// pointer to the beginning of the current symbol
        const lexer_char_t* m_start = nullptr;
        /// pointer for backtracking information
        const lexer_char_t* m_marker = nullptr;
        /// pointer to the current symbol
        const lexer_char_t* m_cursor = nullptr;
        /// pointer to the end of the buffer
        const lexer_char_t* m_limit = nullptr;
    };

    /*!
    @brief syntax analysis

    This class implements a recursive decent parser.
    */
    class parser
    {
      public:
        /// constructor for strings
        parser(const string_t& s, parser_callback_t cb = nullptr) noexcept
            : callback(cb), m_lexer(s)
        {
            // read first token
            get_token();
        }

        /// a parser reading from an input stream
        parser(std::istream& _is, parser_callback_t cb = nullptr) noexcept
            : callback(cb), m_lexer(&_is)
        {
            // read first token
            get_token();
        }

        /// public parser interface
        basic_json parse()
        {
            basic_json result = parse_internal(true);

            expect(lexer::token_type::end_of_input);

            // return parser result and replace it with null in case the
            // top-level value was discarded by the callback function
            return result.is_discarded() ? basic_json() : result;
        }

      private:
        /// the actual parser
        basic_json parse_internal(bool keep)
        {
            auto result = basic_json(value_t::discarded);

            switch (last_token)
            {
                case lexer::token_type::begin_object:
                {
                    if (keep and (not callback or (keep = callback(depth++, parse_event_t::object_start, result))))
                    {
                        // explicitly set result to object to cope with {}
                        result.m_type = value_t::object;
                        result.m_value = json_value(value_t::object);
                    }

                    // read next token
                    get_token();

                    // closing } -> we are done
                    if (last_token == lexer::token_type::end_object)
                    {
                        get_token();
                        if (keep and callback and not callback(--depth, parse_event_t::object_end, result))
                        {
                            result = basic_json(value_t::discarded);
                        }
                        return result;
                    }

                    // no comma is expected here
                    unexpect(lexer::token_type::value_separator);

                    // otherwise: parse key-value pairs
                    do
                    {
                        // ugly, but could be fixed with loop reorganization
                        if (last_token == lexer::token_type::value_separator)
                        {
                            get_token();
                        }

                        // store key
                        expect(lexer::token_type::value_string);
                        const auto key = m_lexer.get_string();

                        bool keep_tag = false;
                        if (keep)
                        {
                            if (callback)
                            {
                                basic_json k(key);
                                keep_tag = callback(depth, parse_event_t::key, k);
                            }
                            else
                            {
                                keep_tag = true;
                            }
                        }

                        // parse separator (:)
                        get_token();
                        expect(lexer::token_type::name_separator);

                        // parse and add value
                        get_token();
                        auto value = parse_internal(keep);
                        if (keep and keep_tag and not value.is_discarded())
                        {
                            result[key] = std::move(value);
                        }
                    }
                    while (last_token == lexer::token_type::value_separator);

                    // closing }
                    expect(lexer::token_type::end_object);
                    get_token();
                    if (keep and callback and not callback(--depth, parse_event_t::object_end, result))
                    {
                        result = basic_json(value_t::discarded);
                    }

                    return result;
                }

                case lexer::token_type::begin_array:
                {
                    if (keep and (not callback or (keep = callback(depth++, parse_event_t::array_start, result))))
                    {
                        // explicitly set result to object to cope with []
                        result.m_type = value_t::array;
                        result.m_value = json_value(value_t::array);
                    }

                    // read next token
                    get_token();

                    // closing ] -> we are done
                    if (last_token == lexer::token_type::end_array)
                    {
                        get_token();
                        if (callback and not callback(--depth, parse_event_t::array_end, result))
                        {
                            result = basic_json(value_t::discarded);
                        }
                        return result;
                    }

                    // no comma is expected here
                    unexpect(lexer::token_type::value_separator);

                    // otherwise: parse values
                    do
                    {
                        // ugly, but could be fixed with loop reorganization
                        if (last_token == lexer::token_type::value_separator)
                        {
                            get_token();
                        }

                        // parse value
                        auto value = parse_internal(keep);
                        if (keep and not value.is_discarded())
                        {
                            result.push_back(std::move(value));
                        }
                    }
                    while (last_token == lexer::token_type::value_separator);

                    // closing ]
                    expect(lexer::token_type::end_array);
                    get_token();
                    if (keep and callback and not callback(--depth, parse_event_t::array_end, result))
                    {
                        result = basic_json(value_t::discarded);
                    }

                    return result;
                }

                case lexer::token_type::literal_null:
                {
                    get_token();
                    result.m_type = value_t::null;
                    break;
                }

                case lexer::token_type::value_string:
                {
                    const auto s = m_lexer.get_string();
                    get_token();
                    result = basic_json(s);
                    break;
                }

                case lexer::token_type::literal_true:
                {
                    get_token();
                    result.m_type = value_t::boolean;
                    result.m_value = true;
                    break;
                }

                case lexer::token_type::literal_false:
                {
                    get_token();
                    result.m_type = value_t::boolean;
                    result.m_value = false;
                    break;
                }

                case lexer::token_type::value_number:
                {
                    m_lexer.get_number(result);
                    get_token();
                    break;
                }

                default:
                {
                    // the last token was unexpected
                    unexpect(last_token);
                }
            }

            if (keep and callback and not callback(depth, parse_event_t::value, result))
            {
                result = basic_json(value_t::discarded);
            }
            return result;
        }

        /// get next token from lexer
        typename lexer::token_type get_token() noexcept
        {
            last_token = m_lexer.scan();
            return last_token;
        }

        void expect(typename lexer::token_type t) const
        {
            if (t != last_token)
            {
                std::string error_msg = "parse error - unexpected ";
                error_msg += (last_token == lexer::token_type::parse_error ? ("'" +  m_lexer.get_token() + "'") :
                              lexer::token_type_name(last_token));
                error_msg += "; expected " + lexer::token_type_name(t);
                throw std::invalid_argument(error_msg);
            }
        }

        void unexpect(typename lexer::token_type t) const
        {
            if (t == last_token)
            {
                std::string error_msg = "parse error - unexpected ";
                error_msg += (last_token == lexer::token_type::parse_error ? ("'" +  m_lexer.get_token() + "'") :
                              lexer::token_type_name(last_token));
                throw std::invalid_argument(error_msg);
            }
        }

      private:
        /// current level of recursion
        int depth = 0;
        /// callback function
        parser_callback_t callback;
        /// the type of the last read token
        typename lexer::token_type last_token = lexer::token_type::uninitialized;
        /// the lexer
        lexer m_lexer;
    };
};


/////////////
// presets //
/////////////

/*!
@brief default JSON class

This type is the default specialization of the @ref basic_json class which uses
the standard template types.

@since version 1.0.0
*/
using json = basic_json<>;
}


/////////////////////////
// nonmember functions //
/////////////////////////

// specialization of std::swap, and std::hash
namespace std
{
/*!
@brief exchanges the values of two JSON objects

@since version 1.0.0
*/
template <>
inline void swap(nlohmann::json& j1,
                 nlohmann::json& j2) noexcept(
                     is_nothrow_move_constructible<nlohmann::json>::value and
                     is_nothrow_move_assignable<nlohmann::json>::value
                 )
{
    j1.swap(j2);
}

/// hash value for JSON objects
template <>
struct hash<nlohmann::json>
{
    /*!
    @brief return a hash value for a JSON object

    @since version 1.0.0
    */
    std::size_t operator()(const nlohmann::json& j) const
    {
        // a naive hashing via the string representation
        const auto& h = hash<nlohmann::json::string_t>();
        return h(j.dump());
    }
};
}

/*!
@brief user-defined string literal for JSON values

This operator implements a user-defined string literal for JSON objects. It can
be used by adding \p "_json" to a string literal and returns a JSON object if
no parse error occurred.

@param[in] s  a string representation of a JSON object
@return a JSON object

@since version 1.0.0
*/
inline nlohmann::json operator "" _json(const char* s, std::size_t)
{
    return nlohmann::json::parse(reinterpret_cast<const nlohmann::json::string_t::value_type*>(s));
}

// restore GCC/clang diagnostic settings
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    #pragma GCC diagnostic pop
#endif

#endif
