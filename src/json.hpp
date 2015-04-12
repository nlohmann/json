/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2015 Niels Lohmann.
@author Niels Lohmann <http://nlohmann.me>
@see https://github.com/nlohmann/json
*/

#ifndef _NLOHMANN_JSON
#define _NLOHMANN_JSON

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

/*!
@brief namespace for Niels Lohmann
@see https://github.com/nlohmann
*/
namespace nlohmann
{


// Helper to determine whether there's a key_type for T.
// http://stackoverflow.com/a/7728728/266378
template<typename T>
struct has_mapped_type
{
  private:
    template<typename C> static char test(typename C::mapped_type*);
    template<typename C> static int  test(...);
  public:
    enum { value = sizeof(test<T>(0)) == sizeof(char) };
};

/*!
@brief JSON

@tparam ObjectType         type for JSON objects
                           (@c std::map by default)
@tparam ArrayType          type for JSON arrays
                           (@c std::vector by default)
@tparam StringType         type for JSON strings and object keys
                           (@c std::string by default)
@tparam BooleanType        type for JSON booleans
                           (@c bool by default)
@tparam NumberIntegerType  type for JSON integer numbers
                           (@c int64_t by default)
@tparam NumberFloatType    type for JSON floating-point numbers
                           (@c double by default)
@tparam AllocatorType      type of the allocator to use
                           (@c std::allocator by default)

@note ObjectType trick from http://stackoverflow.com/a/9860911

@see RFC 7159 <http://rfc7159.net/rfc7159>
@see ECMA 404 <http://www.ecma-international.org/publications/standards/Ecma-404.htm>
*/
template <
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = int64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator
    >
class basic_json
{
  public:
    /////////////////////
    // container types //
    /////////////////////

    // forward declarations
    class iterator;
    class const_iterator;
    class reverse_iterator;
    class const_reverse_iterator;

    /*!
    @brief the type of elements in a basic_json container
    @ingroup container
    */
    using value_type = basic_json;

    /*!
    @brief the type of an element reference
    @ingroup container
    */
    using reference = value_type&;

    /*!
    @brief the type of an element const reference
    @ingroup container
    */
    using const_reference = const value_type&;

    /*!
    @brief a type to represent differences between iterators
    @ingroup container
    */
    using difference_type = std::ptrdiff_t;

    /*!
    @brief a type to represent container sizes
    @ingroup container
    */
    using size_type = std::size_t;

    /// the allocator type
    using allocator_type = AllocatorType<basic_json>;

    /// the type of an element pointer
    using pointer = typename std::allocator_traits<allocator_type>::pointer;
    /// the type of an element const pointer
    using const_pointer = typename std::allocator_traits<allocator_type>::const_pointer;

    /*!
    @brief an iterator for a basic_json container
    @ingroup container
    */
    using iterator = basic_json::iterator;

    /*!
    @brief a const iterator for a basic_json container
    @ingroup container
    */
    using const_iterator = basic_json::const_iterator;

    /*!
    @brief a reverse iterator for a basic_json container
    @ingroup reversiblecontainer
    */
    using reverse_iterator = basic_json::reverse_iterator;

    /*!
    @brief a const reverse iterator for a basic_json container
    @ingroup reversiblecontainer
    */
    using const_reverse_iterator = basic_json::const_reverse_iterator;


    /// returns the allocator associated with the container
    inline static allocator_type get_allocator()
    {
        return allocator_type();
    }


    ///////////////////////////
    // JSON value data types //
    ///////////////////////////

    /// a type for an object
    using object_t = ObjectType<StringType, basic_json>;
    /// a type for an array
    using array_t = ArrayType<basic_json>;
    /// a type for a string
    using string_t = StringType;
    /// a type for a boolean
    using boolean_t = BooleanType;
    /// a type for a number (integer)
    using number_integer_t = NumberIntegerType;
    /// a type for a number (floating-point)
    using number_float_t = NumberFloatType;
    /// a type for list initialization
    using list_init_t = std::initializer_list<basic_json>;


    ////////////////////////
    // JSON value storage //
    ////////////////////////

    /// a JSON value
    union json_value
    {
        /// object (stored with pointer to save storage)
        object_t* object;
        /// array (stored with pointer to save storage)
        array_t* array;
        /// string (stored with pointer to save storage)
        string_t* string;
        /// bolean
        boolean_t boolean;
        /// number (integer)
        number_integer_t number_integer;
        /// number (floating-point)
        number_float_t number_float;

        /// default constructor (for null values)
        json_value() = default;
        /// constructor for booleans
        json_value(boolean_t v) : boolean(v) {}
        /// constructor for numbers (integer)
        json_value(number_integer_t v) : number_integer(v) {}
        /// constructor for numbers (floating-point)
        json_value(number_float_t v) : number_float(v) {}
    };


    /////////////////////////////////
    // JSON value type enumeration //
    /////////////////////////////////

    /// JSON value type enumeration
    enum class value_t : uint8_t
    {
        null,           ///< null value
        object,         ///< object (unordered set of name/value pairs)
        array,          ///< array (ordered collection of values)
        string,         ///< string value
        boolean,        ///< boolean value
        number_integer, ///< number value (integer)
        number_float    ///< number value (floating-point)
    };

    /*!
    @brief comparison operator for JSON value types

    Returns an ordering that is similar to Python:
    - order: null < boolean < number < object < array < string
    - furthermore, each type is not smaller than itself
    */
    friend bool operator<(const value_t lhs, const value_t rhs)
    {
        // no type is smaller than itself
        if (lhs == rhs)
        {
            return false;
        }

        switch (lhs)
        {
            case (value_t::null):
            {
                // nulls are smaller than all other types
                return true;
            }

            case (value_t::boolean):
            {
                // only nulls are smaller than booleans
                return (rhs != value_t::null);
            }

            case (value_t::number_float):
            case (value_t::number_integer):
            {
                switch (rhs)
                {
                    // numbers are smaller than objects, arrays, and string
                    case (value_t::object):
                    case (value_t::array):
                    case (value_t::string):
                    {
                        return true;
                    }

                    default:
                    {
                        return false;
                    }
                }
            }

            case (value_t::object):
            {
                switch (rhs)
                {
                    // objects are smaller than arrays and string
                    case (value_t::array):
                    case (value_t::string):
                    {
                        return true;
                    }

                    default:
                    {
                        return false;
                    }
                }
            }

            case (value_t::array):
            {
                // arrays are smaller than strings
                return (rhs == value_t::string);
            }

            default:
            {
                // a string is not smaller than any other types
                return false;
            }
        }
    }


    //////////////////
    // constructors //
    //////////////////

    /*!
    @brief create an empty value with a given type
    @param value  the type to create an value of

    @exception std::bad_alloc  if allocation for object, array, or string fails.
    */
    inline basic_json(const value_t value)
        : m_type(value)
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                break;
            }

            case (value_t::object):
            {
                AllocatorType<object_t> alloc;
                m_value.object = alloc.allocate(1);
                alloc.construct(m_value.object);
                break;
            }

            case (value_t::array):
            {
                AllocatorType<array_t> alloc;
                m_value.array = alloc.allocate(1);
                alloc.construct(m_value.array);
                break;
            }

            case (value_t::string):
            {
                AllocatorType<string_t> alloc;
                m_value.string = alloc.allocate(1);
                alloc.construct(m_value.string, "");
                break;
            }

            case (value_t::boolean):
            {
                m_value.boolean = boolean_t(false);
                break;
            }

            case (value_t::number_integer):
            {
                m_value.number_integer = number_integer_t(0);
                break;
            }

            case (value_t::number_float):
            {
                m_value.number_float = number_float_t(0.0);
                break;
            }
        }
    }

    /*!
    @brief create a null object (implicitly)
    @ingroup container
    */
    inline basic_json() noexcept = default;

    /// create a null object (explicitly)
    inline basic_json(std::nullptr_t) noexcept
        : m_type(value_t::null)
    {}

    /// create an object (explicit)
    inline basic_json(const object_t& value)
        : m_type(value_t::object)
    {
        AllocatorType<object_t> alloc;
        m_value.object = alloc.allocate(1);
        alloc.construct(m_value.object, value);
    }

    /// create an object (implicit)
    template <class V, typename
              std::enable_if<
                  std::is_constructible<typename object_t::key_type, typename V::key_type>::value and
                  std::is_constructible<basic_json, typename V::mapped_type>::value, int>::type
              = 0>
    inline basic_json(const V& value)
        : m_type(value_t::object)
    {
        AllocatorType<object_t> alloc;
        m_value.object = alloc.allocate(1);
        using std::begin;
        using std::end;
        alloc.construct(m_value.object, begin(value), end(value));
    }

    /// create an array (explicit)
    inline basic_json(const array_t& value)
        : m_type(value_t::array)
    {
        AllocatorType<array_t> alloc;
        m_value.array = alloc.allocate(1);
        alloc.construct(m_value.array, value);
    }

    /// create an array (implicit)
    template <class V, typename
              std::enable_if<
                  not std::is_same<V, basic_json::iterator>::value and
                  not std::is_same<V, basic_json::const_iterator>::value and
                  not std::is_same<V, basic_json::reverse_iterator>::value and
                  not std::is_same<V, basic_json::const_reverse_iterator>::value and
                  not std::is_same<V, typename array_t::iterator>::value and
                  not std::is_same<V, typename array_t::const_iterator>::value and
                  std::is_constructible<basic_json, typename V::value_type>::value, int>::type
              = 0>
    inline basic_json(const V& value)
        : m_type(value_t::array)
    {
        AllocatorType<array_t> alloc;
        m_value.array = alloc.allocate(1);
        using std::begin;
        using std::end;
        alloc.construct(m_value.array, begin(value), end(value));
    }

    /// create a string (explicit)
    inline basic_json(const string_t& value)
        : m_type(value_t::string)
    {
        AllocatorType<string_t> alloc;
        m_value.string = alloc.allocate(1);
        alloc.construct(m_value.string, value);
    }

    /// create a string (explicit)
    inline basic_json(const typename string_t::value_type* value)
        : m_type(value_t::string)
    {
        AllocatorType<string_t> alloc;
        m_value.string = alloc.allocate(1);
        alloc.construct(m_value.string, value);
    }

    /// create a string (implicit)
    template <class V, typename
              std::enable_if<
                  std::is_constructible<string_t, V>::value, int>::type
              = 0>
    inline basic_json(const V& value)
        : basic_json(string_t(value))
    {}

    /// create a boolean (explicit)
    inline basic_json(boolean_t value)
        : m_type(value_t::boolean), m_value(value)
    {}

    /// create an integer number (explicit)
    inline basic_json(const number_integer_t& value)
        : m_type(value_t::number_integer), m_value(value)
    {}

    /// create an integer number (implicit)
    template<typename T, typename
             std::enable_if<
                 std::is_constructible<number_integer_t, T>::value and
                 std::numeric_limits<T>::is_integer, T>::type
             = 0>
    inline basic_json(const T value) noexcept
        : m_type(value_t::number_integer), m_value(number_integer_t(value))
    {}

    /// create a floating-point number (explicit)
    inline basic_json(const number_float_t& value)
        : m_type(value_t::number_float), m_value(value)
    {}

    /// create a floating-point number (implicit)
    template<typename T, typename = typename
             std::enable_if<
                 std::is_constructible<number_float_t, T>::value and
                 std::is_floating_point<T>::value>::type
             >
    inline basic_json(const T value) noexcept
        : m_type(value_t::number_float), m_value(number_float_t(value))
    {}

    /// create a container (array or object) from an initializer list
    inline basic_json(list_init_t l, bool type_deduction = true, value_t manual_type = value_t::array)
    {
        // the initializer list could describe an object
        bool is_object = true;

        // check if each element is an array with two elements whose first element
        // is a string
        for (const auto& element : l)
        {
            if ((element.m_final and element.m_type == value_t::array)
                    or (element.m_type != value_t::array or element.size() != 2
                        or element[0].m_type != value_t::string))
            {
                // we found an element that makes it impossible to use the
                // initializer list as object
                is_object = false;
                break;
            }
        }

        // adjust type if type deduction is not wanted
        if (not type_deduction)
        {
            // mark this object's type as final
            m_final = true;

            // if array is wanted, do not create an object though possible
            if (manual_type == value_t::array)
            {
                is_object = false;
            }

            // if object is wanted but impossible, throw an exception
            if (manual_type == value_t::object and not is_object)
            {
                throw std::logic_error("cannot create JSON object from initializer list");
            }
        }

        if (is_object)
        {
            // the initializer list is a list of pairs -> create object
            m_type = value_t::object;
            AllocatorType<object_t> alloc;
            m_value.object = alloc.allocate(1);
            alloc.construct(m_value.object);

            for (auto& element : l)
            {
                m_value.object->emplace(std::move(*(element[0].m_value.string)), std::move(element[1]));
            }
        }
        else
        {
            // the initializer list describes an array -> create array
            m_type = value_t::array;
            AllocatorType<array_t> alloc;
            m_value.array = alloc.allocate(1);
            alloc.construct(m_value.array, std::move(l));
        }
    }

    /// explicitly create an array from an initializer list
    inline static basic_json array(list_init_t l = list_init_t())
    {
        return basic_json(l, false, value_t::array);
    }

    /// explicitly create an object from an initializer list
    inline static basic_json object(list_init_t l = list_init_t())
    {
        return basic_json(l, false, value_t::object);
    }

    /// construct an array with count copies of given value
    inline basic_json(size_type count, const basic_json& other)
        : m_type(value_t::array)
    {
        AllocatorType<array_t> alloc;
        m_value.array = alloc.allocate(1);
        alloc.construct(m_value.array, count, other);
    }

    /// construct a JSON container given an iterator range
    template <class T, typename
              std::enable_if<
                  std::is_same<T, basic_json::iterator>::value or
                  std::is_same<T, basic_json::const_iterator>::value
                  , int>::type
              = 0>
    inline basic_json(T first, T last)
    {
        // make sure iterator fits the current value
        if (first.m_object != last.m_object or
                first.m_object->m_type != last.m_object->m_type)
        {
            throw std::runtime_error("iterators are not compatible");
        }

        // set the type
        m_type = first.m_object->m_type;

        // check if iterator range is complete for non-compound values
        switch (m_type)
        {
            case value_t::number_integer:
            case value_t::number_float:
            case value_t::boolean:
            case value_t::string:
            {
                if (first.m_it.generic_iterator != 0 or last.m_it.generic_iterator != 1)
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
                m_value.number_integer = first.m_object->m_value.number_integer;
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
                AllocatorType<string_t> alloc;
                m_value.string = alloc.allocate(1);
                alloc.construct(m_value.string, *first.m_object->m_value.string);
                break;
            }

            case value_t::object:
            {
                AllocatorType<object_t> alloc;
                m_value.object = alloc.allocate(1);
                alloc.construct(m_value.object, first.m_it.object_iterator, last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                AllocatorType<array_t> alloc;
                m_value.array = alloc.allocate(1);
                alloc.construct(m_value.array, first.m_it.array_iterator, last.m_it.array_iterator);
                break;
            }

            default:
            {
                throw std::runtime_error("cannot use construct with iterators from " + first.m_object->type_name());
            }
        }
    }

    ///////////////////////////////////////
    // other constructors and destructor //
    ///////////////////////////////////////

    /*!
    @brief copy constructor

    @exception std::bad_alloc  if allocation for object, array, or string fails.

    @ingroup container
    */
    inline basic_json(const basic_json& other)
        : m_type(other.m_type)
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                break;
            }

            case (value_t::object):
            {
                AllocatorType<object_t> alloc;
                m_value.object = alloc.allocate(1);
                alloc.construct(m_value.object, *other.m_value.object);
                break;
            }

            case (value_t::array):
            {
                AllocatorType<array_t> alloc;
                m_value.array = alloc.allocate(1);
                alloc.construct(m_value.array, *other.m_value.array);
                break;
            }

            case (value_t::string):
            {
                AllocatorType<string_t> alloc;
                m_value.string = alloc.allocate(1);
                alloc.construct(m_value.string, *other.m_value.string);
                break;
            }

            case (value_t::boolean):
            {
                m_value.boolean = other.m_value.boolean;
                break;
            }

            case (value_t::number_integer):
            {
                m_value.number_integer = other.m_value.number_integer;
                break;
            }

            case (value_t::number_float):
            {
                m_value.number_float = other.m_value.number_float;
                break;
            }
        }
    }

    /// move constructor
    inline basic_json(basic_json&& other) noexcept
        : m_type(std::move(other.m_type)),
          m_value(std::move(other.m_value))
    {
        // invalidate payload
        other.m_type = value_t::null;
        other.m_value = {};
    }

    /*!
    @brief copy assignment
    @ingroup container
    */
    inline reference& operator=(basic_json other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        std::swap(m_type, other.m_type);
        std::swap(m_value, other.m_value);
        return *this;
    }

    /*!
    @brief destructor
    @ingroup container
    */
    inline ~basic_json() noexcept
    {
        switch (m_type)
        {
            case (value_t::object):
            {
                AllocatorType<object_t> alloc;
                alloc.destroy(m_value.object);
                alloc.deallocate(m_value.object, 1);
                m_value.object = nullptr;
                break;
            }

            case (value_t::array):
            {
                AllocatorType<array_t> alloc;
                alloc.destroy(m_value.array);
                alloc.deallocate(m_value.array, 1);
                m_value.array = nullptr;
                break;
            }

            case (value_t::string):
            {
                AllocatorType<string_t> alloc;
                alloc.destroy(m_value.string);
                alloc.deallocate(m_value.string, 1);
                m_value.string = nullptr;
                break;
            }

            default:
            {
                // all other types need no specific destructor
                break;
            }
        }
    }


  public:
    ///////////////////////
    // object inspection //
    ///////////////////////

    /*!
    @brief serialization

    Serialization function for JSON objects. The function tries to mimick
    Python's @p json.dumps() function, and currently supports its @p indent
    parameter.

    @param indent  sif indent is nonnegative, then array elements and object
    members will be pretty-printed with that indent level. An indent level of 0
    will only insert newlines. -1 (the default) selects the most compact
    representation

    @see https://docs.python.org/2/library/json.html#json.dump
    */
    inline string_t dump(const int indent = -1) const noexcept
    {
        if (indent >= 0)
        {
            return dump(true, static_cast<unsigned int>(indent));
        }
        else
        {
            return dump(false, 0);
        }
    }

    /// return the type of the object (explicit)
    inline value_t type() const noexcept
    {
        return m_type;
    }

    // return whether value is null
    inline bool is_null() const noexcept
    {
        return m_type == value_t::null;
    }

    // return whether value is boolean
    inline bool is_boolean() const noexcept
    {
        return m_type == value_t::boolean;
    }

    // return whether value is number
    inline bool is_number() const noexcept
    {
        return (m_type == value_t::number_integer) or (m_type == value_t::number_float);
    }

    // return whether value is object
    inline bool is_object() const noexcept
    {
        return m_type == value_t::object;
    }

    // return whether value is array
    inline bool is_array() const noexcept
    {
        return m_type == value_t::array;
    }

    // return whether value is string
    inline bool is_string() const noexcept
    {
        return m_type == value_t::string;
    }

    /// return the type of the object (implicit)
    inline operator value_t() const noexcept
    {
        return m_type;
    }

  private:
    //////////////////////
    // value conversion //
    //////////////////////

    /// get an object (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<typename object_t::key_type, typename T::key_type>::value and
                  std::is_convertible<basic_json, typename T::mapped_type>::value
                  , int>::type = 0>
    inline T get_impl(T*) const
    {
        switch (m_type)
        {
            case (value_t::object):
            {
                return T(m_value.object->begin(), m_value.object->end());
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    /// get an object (explicit)
    inline object_t get_impl(object_t*) const
    {
        switch (m_type)
        {
            case (value_t::object):
            {
                return *(m_value.object);
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to object");
            }
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<basic_json, typename T::value_type>::value and
                  not std::is_same<basic_json, typename T::value_type>::value and
                  not std::is_arithmetic<T>::value and
                  not std::is_convertible<std::string, T>::value and
                  not has_mapped_type<T>::value
                  , int>::type = 0>
    inline T get_impl(T*) const
    {
        switch (m_type)
        {
            case (value_t::array):
            {
                T to_vector;
                std::transform(m_value.array->begin(), m_value.array->end(),
                               std::inserter(to_vector, to_vector.end()), [](basic_json i)
                {
                    return i.get<typename T::value_type>();
                });
                return to_vector;
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_convertible<basic_json, T>::value and
                  not std::is_same<basic_json, T>::value
                  , int>::type = 0>
    inline std::vector<T> get_impl(std::vector<T>*) const
    {
        switch (m_type)
        {
            case (value_t::array):
            {
                std::vector<T> to_vector;
                to_vector.reserve(m_value.array->size());
                std::transform(m_value.array->begin(), m_value.array->end(),
                               std::inserter(to_vector, to_vector.end()), [](basic_json i)
                {
                    return i.get<T>();
                });
                return to_vector;
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    /// get an array (explicit)
    template <class T, typename
              std::enable_if<
                  std::is_same<basic_json, typename T::value_type>::value and
                  not has_mapped_type<T>::value
                  , int>::type = 0>
    inline T get_impl(T*) const
    {
        switch (m_type)
        {
            case (value_t::array):
            {
                return T(m_value.array->begin(), m_value.array->end());
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    inline array_t get_impl(array_t*) const
    {
        switch (m_type)
        {
            case (value_t::array):
            {
                return *(m_value.array);
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to array");
            }
        }
    }

    /// get a string (explicit)
    template <typename T, typename
              std::enable_if<
                  std::is_convertible<string_t, T>::value
                  , int>::type = 0>
    inline T get_impl(T*) const
    {
        switch (m_type)
        {
            case (value_t::string):
            {
                return *m_value.string;
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    /// get a number (explicit)
    template<typename T, typename
             std::enable_if<
                 std::is_arithmetic<T>::value
                 , int>::type = 0>
    inline T get_impl(T*) const
    {
        switch (m_type)
        {
            case (value_t::number_integer):
            {
                return static_cast<T>(m_value.number_integer);
            }
            case (value_t::number_float):
            {
                return static_cast<T>(m_value.number_float);
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(T).name());
            }
        }
    }

    /// get a boolean (explicit)
    inline boolean_t get_impl(boolean_t*) const
    {
        switch (m_type)
        {
            case (value_t::boolean):
            {
                return m_value.boolean;
            }
            default:
            {
                throw std::logic_error("cannot cast " + type_name() + " to " + typeid(boolean_t).name());
            }
        }
    }

  public:
    /// get a value (explicit)
    // <http://stackoverflow.com/a/8315197/266378>
    template<typename T>
    inline T get() const
    {
        return get_impl(static_cast<T*>(nullptr));
    }

    /// get a value (implicit)
    template<typename T>
    inline operator T() const
    {
        return get<T>();
    }


    ////////////////////
    // element access //
    ////////////////////

    /// access specified element with bounds checking
    inline reference at(size_type idx)
    {
        // at only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use at with " + type_name());
        }

        return m_value.array->at(idx);
    }

    /// access specified element with bounds checking
    inline const_reference at(size_type idx) const
    {
        // at only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use at with " + type_name());
        }

        return m_value.array->at(idx);
    }

    /// access specified element with bounds checking
    inline reference at(const typename object_t::key_type& key)
    {
        // at only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use at with " + type_name());
        }

        return m_value.object->at(key);
    }

    /// access specified element with bounds checking
    inline const_reference at(const typename object_t::key_type& key) const
    {
        // at only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use at with " + type_name());
        }

        return m_value.object->at(key);
    }

    /// access specified element
    inline reference operator[](size_type idx)
    {
        // implicitly convert null to object
        if (m_type == value_t::null)
        {
            m_type = value_t::array;
            AllocatorType<array_t> alloc;
            m_value.array = alloc.allocate(1);
            alloc.construct(m_value.array);
        }

        // [] only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        for (size_t i = m_value.array->size(); i <= idx; ++i)
        {
            m_value.array->push_back(basic_json());
        }

        return m_value.array->operator[](idx);
    }

    /// access specified element
    inline const_reference operator[](size_type idx) const
    {
        // at only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        return m_value.array->operator[](idx);
    }

    /// access specified element
    inline reference operator[](const typename object_t::key_type& key)
    {
        // implicitly convert null to object
        if (m_type == value_t::null)
        {
            m_type = value_t::object;
            AllocatorType<object_t> alloc;
            m_value.object = alloc.allocate(1);
            alloc.construct(m_value.object);
        }

        // [] only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        return m_value.object->operator[](key);
    }

    /// access specified element
    inline const_reference operator[](const typename object_t::key_type& key) const
    {
        // at only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        return m_value.object->operator[](key);
    }

    /// access specified element (needed for clang)
    template<typename T, std::size_t n>
    inline reference operator[](const T (&key)[n])
    {
        // implicitly convert null to object
        if (m_type == value_t::null)
        {
            m_type = value_t::object;
            AllocatorType<object_t> alloc;
            m_value.object = alloc.allocate(1);
            alloc.construct(m_value.object);
        }

        // at only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        return m_value.object->operator[](key);
    }

    /// access specified element (needed for clang)
    template<typename T, std::size_t n>
    inline const_reference operator[](const T (&key)[n]) const
    {
        // at only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use [] with " + type_name());
        }

        return m_value.object->operator[](key);
    }

    /// access the first element
    inline reference front()
    {
        return *begin();
    }

    /// access the first element
    inline const_reference front() const
    {
        return *cbegin();
    }

    /// access the last element
    inline reference back()
    {
        auto tmp = end();
        --tmp;
        return *tmp;
    }

    /// access the last element
    inline const_reference back() const
    {
        auto tmp = cend();
        --tmp;
        return *tmp;
    }

    /// remove element given an iterator
    template <class T, typename
              std::enable_if<
                  std::is_same<T, basic_json::iterator>::value or
                  std::is_same<T, basic_json::const_iterator>::value
                  , int>::type
              = 0>
    inline T erase(T pos)
    {
        // make sure iterator fits the current value
        if (this != pos.m_object or m_type != pos.m_object->m_type)
        {
            throw std::runtime_error("iterator does not fit current value");
        }

        T result = end();

        switch (m_type)
        {
            case value_t::number_integer:
            case value_t::number_float:
            case value_t::boolean:
            case value_t::string:
            {
                if (pos.m_it.generic_iterator != 0)
                {
                    throw std::out_of_range("iterator out of range");
                }

                if (m_type == value_t::string)
                {
                    delete m_value.string;
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
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

            default:
            {
                throw std::runtime_error("cannot use erase with " + type_name());
            }
        }

        return result;
    }

    /// remove elements given an iterator range
    template <class T, typename
              std::enable_if<
                  std::is_same<T, basic_json::iterator>::value or
                  std::is_same<T, basic_json::const_iterator>::value
                  , int>::type
              = 0>
    inline T erase(T first, T last)
    {
        // make sure iterator fits the current value
        if (this != first.m_object or this != last.m_object or
                m_type != first.m_object->m_type or m_type != last.m_object->m_type)
        {
            throw std::runtime_error("iterators do not fit current value");
        }

        T result = end();

        switch (m_type)
        {
            case value_t::number_integer:
            case value_t::number_float:
            case value_t::boolean:
            case value_t::string:
            {
                if (first.m_it.generic_iterator != 0 or last.m_it.generic_iterator != 1)
                {
                    throw std::out_of_range("iterators out of range");
                }

                if (m_type == value_t::string)
                {
                    delete m_value.string;
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
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

            default:
            {
                throw std::runtime_error("cannot use erase with " + type_name());
            }
        }

        return result;
    }

    /// remove element from an object given a key
    inline size_type erase(const typename object_t::key_type& key)
    {
        // this erase only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use erase with " + type_name());
        }

        return m_value.object->erase(key);
    }

    /// remove element from an array given an index
    inline void erase(const size_type idx)
    {
        // this erase only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use erase with " + type_name());
        }

        if (idx >= size())
        {
            throw std::out_of_range("index out of range");
        }

        m_value.array->erase(m_value.array->begin() + static_cast<difference_type>(idx));
    }

    /// find an element in an object
    inline iterator find(typename object_t::key_type key)
    {
        auto result = end();

        if (m_type == value_t::object)
        {
            result.m_it.object_iterator = m_value.object->find(key);
        }

        return result;
    }

    /// find an element in an object
    inline const_iterator find(typename object_t::key_type key) const
    {
        auto result = cend();

        if (m_type == value_t::object)
        {
            result.m_it.object_iterator = m_value.object->find(key);
        }

        return result;
    }

    /// returns the number of occurrences of a key in an object
    inline size_type count(typename object_t::key_type key) const
    {
        // return 0 for all nonobject types
        return (m_type == value_t::object) ? m_value.object->count(key) : 0;
    }


    ///////////////
    // iterators //
    ///////////////

    /*!
    @brief returns an iterator to the first element
    @ingroup container
    */
    inline iterator begin() noexcept
    {
        iterator result(this);
        result.set_begin();
        return result;
    }

    /*!
    @brief returns a const iterator to the first element
    @ingroup container
    */
    inline const_iterator begin() const noexcept
    {
        return cbegin();
    }

    /*!
    @brief returns a const iterator to the first element
    @ingroup container
    */
    inline const_iterator cbegin() const noexcept
    {
        const_iterator result(this);
        result.set_begin();
        return result;
    }

    /*!
    @brief returns an iterator to one past the last element
    @ingroup container
    */
    inline iterator end() noexcept
    {
        iterator result(this);
        result.set_end();
        return result;
    }

    /*!
    @brief returns a const iterator to one past the last element
    @ingroup container
    */
    inline const_iterator end() const noexcept
    {
        return cend();
    }

    /*!
    @brief returns a const iterator to one past the last element
    @ingroup container
    */
    inline const_iterator cend() const noexcept
    {
        const_iterator result(this);
        result.set_end();
        return result;
    }

    /*!
    @brief returns a reverse iterator to the first element
    @ingroup reversiblecontainer
    */
    inline reverse_iterator rbegin() noexcept
    {
        return reverse_iterator(end());
    }

    /*!
    @brief returns a const reverse iterator to the first element
    @ingroup reversiblecontainer
    */
    inline const_reverse_iterator rbegin() const noexcept
    {
        return crbegin();
    }

    /*!
    @brief returns a reverse iterator to one past the last element
    @ingroup reversiblecontainer
    */
    inline reverse_iterator rend() noexcept
    {
        return reverse_iterator(begin());
    }

    /*!
    @brief returns a const reverse iterator to one past the last element
    @ingroup reversiblecontainer
    */
    inline const_reverse_iterator rend() const noexcept
    {
        return crend();
    }

    /*!
    @brief returns a const reverse iterator to the first element
    @ingroup reversiblecontainer
    */
    inline const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(cend());
    }

    /*!
    @brief returns a const reverse iterator to one past the last element
    @ingroup reversiblecontainer
    */
    inline const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(cbegin());
    }


    //////////////
    // capacity //
    //////////////

    /*!
    @brief checks whether the container is empty
    @ingroup container
    */
    inline bool empty() const noexcept
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                return true;
            }

            case (value_t::array):
            {
                return m_value.array->empty();
            }

            case (value_t::object):
            {
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
    @ingroup container
    */
    inline size_type size() const noexcept
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                return 0;
            }

            case (value_t::array):
            {
                return m_value.array->size();
            }

            case (value_t::object):
            {
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
    @ingroup container
    */
    inline size_type max_size() const noexcept
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                return 0;
            }

            case (value_t::array):
            {
                return m_value.array->max_size();
            }

            case (value_t::object):
            {
                return m_value.object->max_size();
            }

            default:
            {
                // all other types have max_size 1
                return 1;
            }
        }
    }


    ///////////////
    // modifiers //
    ///////////////

    /// clears the contents
    inline void clear() noexcept
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                break;
            }

            case (value_t::number_integer):
            {
                m_value.number_integer = 0;
                break;
            }

            case (value_t::number_float):
            {
                m_value.number_float = 0.0;
                break;
            }

            case (value_t::boolean):
            {
                m_value.boolean = false;
                break;
            }

            case (value_t::string):
            {
                m_value.string->clear();
                break;
            }

            case (value_t::array):
            {
                m_value.array->clear();
                break;
            }

            case (value_t::object):
            {
                m_value.object->clear();
                break;
            }
        }
    }

    /// add an object to an array
    inline void push_back(basic_json&& value)
    {
        // push_back only works for null objects or arrays
        if (not(m_type == value_t::null or m_type == value_t::array))
        {
            throw std::runtime_error("cannot add element to " + type_name());
        }

        // transform null object into an array
        if (m_type == value_t::null)
        {
            m_type = value_t::array;
            AllocatorType<array_t> alloc;
            m_value.array = alloc.allocate(1);
            alloc.construct(m_value.array);
        }

        // add element to array (move semantics)
        m_value.array->push_back(std::move(value));
        // invalidate object
        value.m_type = value_t::null;
    }

    /// add an object to an array
    inline reference operator+=(basic_json&& value)
    {
        push_back(std::move(value));
        return *this;
    }

    /// add an object to an array
    inline void push_back(const basic_json& value)
    {
        // push_back only works for null objects or arrays
        if (not(m_type == value_t::null or m_type == value_t::array))
        {
            throw std::runtime_error("cannot add element to " + type_name());
        }

        // transform null object into an array
        if (m_type == value_t::null)
        {
            m_type = value_t::array;
            AllocatorType<array_t> alloc;
            m_value.array = alloc.allocate(1);
            alloc.construct(m_value.array);
        }

        // add element to array
        m_value.array->push_back(value);
    }

    /// add an object to an array
    inline reference operator+=(const basic_json& value)
    {
        push_back(value);
        return *this;
    }

    /// add an object to an object
    inline void push_back(const typename object_t::value_type& value)
    {
        // push_back only works for null objects or objects
        if (not(m_type == value_t::null or m_type == value_t::object))
        {
            throw std::runtime_error("cannot add element to " + type_name());
        }

        // transform null object into an object
        if (m_type == value_t::null)
        {
            m_type = value_t::object;
            AllocatorType<object_t> alloc;
            m_value.object = alloc.allocate(1);
            alloc.construct(m_value.object);
        }

        // add element to array
        m_value.object->insert(value);
    }

    /// add an object to an object
    inline reference operator+=(const typename object_t::value_type& value)
    {
        push_back(value);
        return operator[](value.first);
    }

    /*!
    @brief exchanges the values
    @ingroup container
    */
    inline void swap(reference other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        std::swap(m_type, other.m_type);
        std::swap(m_value, other.m_value);
    }

    /// swaps the contents
    inline void swap(array_t& other)
    {
        // swap only works for arrays
        if (m_type != value_t::array)
        {
            throw std::runtime_error("cannot use swap with " + type_name());
        }

        // swap arrays
        std::swap(*(m_value.array), other);
    }

    /// swaps the contents
    inline void swap(object_t& other)
    {
        // swap only works for objects
        if (m_type != value_t::object)
        {
            throw std::runtime_error("cannot use swap with " + type_name());
        }

        // swap arrays
        std::swap(*(m_value.object), other);
    }

    /// swaps the contents
    inline void swap(string_t& other)
    {
        // swap only works for strings
        if (m_type != value_t::string)
        {
            throw std::runtime_error("cannot use swap with " + type_name());
        }

        // swap arrays
        std::swap(*(m_value.string), other);
    }


    //////////////////////////////////////////
    // lexicographical comparison operators //
    //////////////////////////////////////////

    /*!
    @brief comparison: equal
    @ingroup container
    */
    friend bool operator==(const_reference lhs, const_reference rhs) noexcept
    {
        switch (lhs.type())
        {
            case (value_t::array):
            {
                if (rhs.type() == value_t::array)
                {
                    return *lhs.m_value.array == *rhs.m_value.array;
                }
                break;
            }
            case (value_t::object):
            {
                if (rhs.type() == value_t::object)
                {
                    return *lhs.m_value.object == *rhs.m_value.object;
                }
                break;
            }
            case (value_t::null):
            {
                if (rhs.type() == value_t::null)
                {
                    return true;
                }
                break;
            }
            case (value_t::string):
            {
                if (rhs.type() == value_t::string)
                {
                    return *lhs.m_value.string == *rhs.m_value.string;
                }
                break;
            }
            case (value_t::boolean):
            {
                if (rhs.type() == value_t::boolean)
                {
                    return lhs.m_value.boolean == rhs.m_value.boolean;
                }
                break;
            }
            case (value_t::number_integer):
            {
                if (rhs.type() == value_t::number_integer)
                {
                    return lhs.m_value.number_integer == rhs.m_value.number_integer;
                }
                if (rhs.type() == value_t::number_float)
                {
                    return lhs.m_value.number_integer == static_cast<number_integer_t>(rhs.m_value.number_float);
                }
                break;
            }
            case (value_t::number_float):
            {
                if (rhs.type() == value_t::number_integer)
                {
                    return approx(lhs.m_value.number_float, static_cast<number_float_t>(rhs.m_value.number_integer));
                }
                if (rhs.type() == value_t::number_float)
                {
                    return approx(lhs.m_value.number_float, rhs.m_value.number_float);
                }
                break;
            }
        }

        return false;
    }

    /*!
    @brief comparison: not equal
    @ingroup container
    */
    friend bool operator!=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs == rhs);
    }

    /// comparison: less than
    friend bool operator<(const_reference lhs, const_reference rhs) noexcept
    {
        switch (lhs.type())
        {
            case (value_t::array):
            {
                if (rhs.type() == value_t::array)
                {
                    return *lhs.m_value.array < *rhs.m_value.array;
                }
                break;
            }
            case (value_t::object):
            {
                if (rhs.type() == value_t::object)
                {
                    return *lhs.m_value.object < *rhs.m_value.object;
                }
                break;
            }
            case (value_t::null):
            {
                if (rhs.type() == value_t::null)
                {
                    return false;
                }
                break;
            }
            case (value_t::string):
            {
                if (rhs.type() == value_t::string)
                {
                    return *lhs.m_value.string < *rhs.m_value.string;
                }
                break;
            }
            case (value_t::boolean):
            {
                if (rhs.type() == value_t::boolean)
                {
                    return lhs.m_value.boolean < rhs.m_value.boolean;
                }
                break;
            }
            case (value_t::number_integer):
            {
                if (rhs.type() == value_t::number_integer)
                {
                    return lhs.m_value.number_integer < rhs.m_value.number_integer;
                }
                if (rhs.type() == value_t::number_float)
                {
                    return lhs.m_value.number_integer < static_cast<number_integer_t>(rhs.m_value.number_float);
                }
                break;
            }
            case (value_t::number_float):
            {
                if (rhs.type() == value_t::number_integer)
                {
                    return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_integer);
                }
                if (rhs.type() == value_t::number_float)
                {
                    return lhs.m_value.number_float < rhs.m_value.number_float;
                }
                break;
            }
        }

        // We only reach this line if we cannot compare values. In that case,
        // we compare types.
        return lhs.type() < rhs.type();
    }

    /// comparison: less than or equal
    friend bool operator<=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (rhs < lhs);
    }

    /// comparison: greater than
    friend bool operator>(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs <= rhs);
    }

    /// comparison: greater than or equal
    friend bool operator>=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs < rhs);
    }


    ///////////////////
    // serialization //
    ///////////////////

    /// serialize to stream
    friend std::ostream& operator<<(std::ostream& o, const basic_json& j)
    {
        // read width member and use it as indentation parameter if nonzero
        const int indentation = (o.width() == 0) ? -1 : o.width();

        o << j.dump(indentation);
        return o;
    }

    /// serialize to stream
    friend std::ostream& operator>>(const basic_json& j, std::ostream& o)
    {
        // read width member and use it as indentation parameter if nonzero
        const int indentation = (o.width() == 0) ? -1 : o.width();

        o << j.dump(indentation);
        return o;
    }


    /////////////////////
    // deserialization //
    /////////////////////

    /// deserialize from string
    static basic_json parse(const string_t& s)
    {
        return parser(s).parse();
    }

    /// deserialize from stream
    static basic_json parse(std::istream& i)
    {
        return parser(i).parse();
    }

    /// deserialize from stream
    friend std::istream& operator>>(std::istream& i, basic_json& j)
    {
        j = parser(i).parse();
        return i;
    }

    /// deserialize from stream
    friend std::istream& operator<<(basic_json& j, std::istream& i)
    {
        j = parser(i).parse();
        return i;
    }


  private:
    ///////////////////////////
    // convenience functions //
    ///////////////////////////

    /// return the type as string
    inline string_t type_name() const noexcept
    {
        switch (m_type)
        {
            case (value_t::null):
            {
                return "null";
            }

            case (value_t::object):
            {
                return "object";
            }

            case (value_t::array):
            {
                return "array";
            }

            case (value_t::string):
            {
                return "string";
            }

            case (value_t::boolean):
            {
                return "boolean";
            }

            default:
            {
                return "number";
            }
        }
    }

    /*!
    @brief escape a string

    Escape a string by replacing certain special characters by a sequence of an
    escape character (backslash) and another character and other control
    characters by a sequence of "\u" followed by a four-digit hex
    representation.

    @param s  the string to escape
    @return escaped string
    */
    static string_t escape_string(const string_t& s) noexcept
    {
        // create a result string of at least the size than s
        string_t result;
        result.reserve(s.size());

        for (const auto c : s)
        {
            switch (c)
            {
                // quotation mark (0x22)
                case '"':
                {
                    result += "\\\"";
                    break;
                }

                // reverse solidus (0x5c)
                case '\\':
                {
                    result += "\\\\";
                    break;
                }

                // backspace (0x08)
                case '\b':
                {
                    result += "\\b";
                    break;
                }

                // formfeed (0x0c)
                case '\f':
                {
                    result += "\\f";
                    break;
                }

                // newline (0x0a)
                case '\n':
                {
                    result += "\\n";
                    break;
                }

                // carriage return (0x0d)
                case '\r':
                {
                    result += "\\r";
                    break;
                }

                // horizontal tab (0x09)
                case '\t':
                {
                    result += "\\t";
                    break;
                }

                default:
                {
                    if (c >= 0 and c <= 0x1f)
                    {
                        // control characters (everything between 0x00 and 0x1f)
                        // -> create four-digit hex representation
                        std::stringstream ss;
                        ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c);
                        result += ss.str();
                    }
                    else
                    {
                        // all other characters are added as-is
                        result.append(1, c);
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
    the serializaion internally. The indentation level is propagated as
    additional parameter. In case of arrays and objects, the function is called
    recursively. Note that

    - strings and object keys are escaped using escape_string()
    - integer numbers are converted to a string before output using
      std::to_string()
    - floating-point numbers are converted to a string using "%g" format

    @param prettyPrint    whether the output shall be pretty-printed
    @param indentStep     the indent level
    @param currentIndent  the current indent level (only used internally)
    */
    inline string_t dump(const bool prettyPrint, const unsigned int indentStep,
                         const unsigned int currentIndent = 0) const noexcept
    {
        // variable to hold indentation for recursive calls
        auto new_indent = currentIndent;

        // helper function to return whitespace as indentation
        const auto indent = [prettyPrint, &new_indent]()
        {
            return prettyPrint ? string_t(new_indent, ' ') : string_t();
        };

        switch (m_type)
        {
            case (value_t::object):
            {
                if (m_value.object->empty())
                {
                    return "{}";
                }

                string_t result = "{";

                // increase indentation
                if (prettyPrint)
                {
                    new_indent += indentStep;
                    result += "\n";
                }

                for (auto i = m_value.object->cbegin(); i != m_value.object->cend(); ++i)
                {
                    if (i != m_value.object->cbegin())
                    {
                        result += prettyPrint ? ",\n" : ",";
                    }
                    result += indent() + "\"" + escape_string(i->first) + "\":" + (prettyPrint ? " " : "")
                              + i->second.dump(prettyPrint, indentStep, new_indent);
                }

                // decrease indentation
                if (prettyPrint)
                {
                    new_indent -= indentStep;
                    result += "\n";
                }

                return result + indent() + "}";
            }

            case (value_t::array):
            {
                if (m_value.array->empty())
                {
                    return "[]";
                }

                string_t result = "[";

                // increase indentation
                if (prettyPrint)
                {
                    new_indent += indentStep;
                    result += "\n";
                }

                for (auto i = m_value.array->cbegin(); i != m_value.array->cend(); ++i)
                {
                    if (i != m_value.array->cbegin())
                    {
                        result += prettyPrint ? ",\n" : ",";
                    }
                    result += indent() + i->dump(prettyPrint, indentStep, new_indent);
                }

                // decrease indentation
                if (prettyPrint)
                {
                    new_indent -= indentStep;
                    result += "\n";
                }

                return result + indent() + "]";
            }

            case (value_t::string):
            {
                return string_t("\"") + escape_string(*m_value.string) + "\"";
            }

            case (value_t::boolean):
            {
                return m_value.boolean ? "true" : "false";
            }

            case (value_t::number_integer):
            {
                return std::to_string(m_value.number_integer);
            }

            case (value_t::number_float):
            {
                // 15 digits of precision allows round-trip IEEE 754
                // string->double->string
                const auto sz = static_cast<unsigned int>(std::snprintf(nullptr, 0, "%.15g", m_value.number_float));
                std::vector<char> buf(sz + 1);
                std::snprintf(&buf[0], buf.size(), "%.15g", m_value.number_float);
                return string_t(buf.data());
            }

            default:
            {
                return "null";
            }
        }
    }

    /// "equality" comparison for floating point numbers
    template<typename T>
    inline static bool approx(const T a, const T b)
    {
        return not (a > b or a < b);
    }


  private:
    //////////////////////
    // member variables //
    //////////////////////

    /// the type of the current element
    value_t m_type = value_t::null;

    /// whether the type of JSON object may change later
    bool m_final = false;

    /// the value of the current element
    json_value m_value = {};


  private:
    ///////////////
    // iterators //
    ///////////////

    /// an iterator value
    template<typename array_iterator_t, typename object_iterator_t>
    union internal_iterator
    {
        /// iterator for JSON objects
        object_iterator_t object_iterator;
        /// iterator for JSON arrays
        array_iterator_t array_iterator;
        /// generic iteraotr for all other value types
        difference_type generic_iterator;

        /// default constructor
        internal_iterator() : generic_iterator(-1) {}
    };

  public:
    /// a random access iterator for the basic_json class
    class iterator : public std::iterator<std::random_access_iterator_tag, basic_json>
    {
        // allow basic_json class to access m_it
        friend class basic_json;

      public:
        /// the type of the values when the iterator is dereferenced
        using value_type = basic_json::value_type;
        /// a type to represent differences between iterators
        using difference_type = basic_json::difference_type;
        /// defines a pointer to the type iterated over (value_type)
        using pointer = basic_json::pointer;
        /// defines a reference to the type iterated over (value_type)
        using reference = basic_json::reference;
        /// the category of the iterator
        using iterator_category = std::bidirectional_iterator_tag;

        /// default constructor
        inline iterator() = default;

        /// constructor for a given JSON instance
        inline iterator(pointer object) noexcept : m_object(object)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = typename object_t::iterator();
                    break;
                }
                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = typename array_t::iterator();
                    break;
                }
                default:
                {
                    m_it.generic_iterator = -1;
                    break;
                }
            }
        }

        /// copy constructor
        inline iterator(const iterator& other) noexcept
            : m_object(other.m_object), m_it(other.m_it)
        {}

        /// copy assignment
        inline iterator& operator=(iterator other) noexcept (
            std::is_nothrow_move_constructible<pointer>::value and
            std::is_nothrow_move_assignable<pointer>::value and
            std::is_nothrow_move_constructible<internal_iterator<typename array_t::iterator, typename object_t::iterator>>::value
            and
            std::is_nothrow_move_assignable<internal_iterator<typename array_t::iterator, typename object_t::iterator>>::value
        )
        {
            std::swap(m_object, other.m_object);
            std::swap(m_it, other.m_it);
            return *this;
        }

      private:
        /// set the iterator to the first value
        inline void set_begin() noexcept
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = m_object->m_value.object->begin();
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = m_object->m_value.array->begin();
                    break;
                }

                case (basic_json::value_t::null):
                {
                    // set to end so begin()==end() is true: null is empty
                    m_it.generic_iterator = 1;
                    break;
                }

                default:
                {
                    m_it.generic_iterator = 0;
                    break;
                }
            }
        }

        /// set the iterator past the last value
        inline void set_end() noexcept
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = m_object->m_value.object->end();
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = m_object->m_value.array->end();
                    break;
                }

                default:
                {
                    m_it.generic_iterator = 1;
                    break;
                }
            }
        }

      public:
        /// return a reference to the value pointed to by the iterator
        inline reference operator*()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return m_it.object_iterator->second;
                }

                case (basic_json::value_t::array):
                {
                    return *m_it.array_iterator;
                }

                case (basic_json::value_t::null):
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.generic_iterator == 0)
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
        inline pointer operator->()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return &(m_it.object_iterator->second);
                }

                case (basic_json::value_t::array):
                {
                    return &*m_it.array_iterator;
                }

                case (basic_json::value_t::null):
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.generic_iterator == 0)
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
        inline iterator operator++(int)
        {
            auto result = *this;

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator++;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator++;
                    break;
                }

                default:
                {
                    m_it.generic_iterator++;
                    break;
                }
            }

            return result;
        }

        /// pre-increment (++it)
        inline iterator& operator++()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    ++m_it.object_iterator;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    ++m_it.array_iterator;
                    break;
                }

                default:
                {
                    ++m_it.generic_iterator;
                    break;
                }
            }

            return *this;
        }

        /// post-decrement (it--)
        inline iterator operator--(int)
        {
            auto result = *this;

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator--;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator--;
                    break;
                }

                default:
                {
                    m_it.generic_iterator--;
                    break;
                }
            }

            return result;
        }

        /// pre-decrement (--it)
        inline iterator& operator--()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    --m_it.object_iterator;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    --m_it.array_iterator;
                    break;
                }

                default:
                {
                    --m_it.generic_iterator;
                    break;
                }
            }

            return *this;
        }

        /// comparison: equal
        inline bool operator==(const iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return (m_it.object_iterator == other.m_it.object_iterator);
                }

                case (basic_json::value_t::array):
                {
                    return (m_it.array_iterator == other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.generic_iterator == other.m_it.generic_iterator);
                }
            }
        }

        /// comparison: not equal
        inline bool operator!=(const iterator& other) const
        {
            return not operator==(other);
        }

        /// comparison: smaller
        inline bool operator<(const iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator< for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    return (m_it.array_iterator < other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.generic_iterator < other.m_it.generic_iterator);
                }
            }
        }

        /// comparison: less than or equal
        inline bool operator<=(const iterator& other) const
        {
            return not other.operator < (*this);
        }

        /// comparison: greater than
        inline bool operator>(const iterator& other) const
        {
            return not operator<=(other);
        }

        /// comparison: greater than or equal
        inline bool operator>=(const iterator& other) const
        {
            return not operator<(other);
        }

        /// add to iterator
        inline iterator& operator+=(difference_type i)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator+= for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator += i;
                    break;
                }

                default:
                {
                    m_it.generic_iterator += i;
                    break;
                }
            }

            return *this;
        }

        /// subtract from iterator
        inline iterator& operator-=(difference_type i)
        {
            return operator+=(-i);
        }

        /// add to iterator
        inline iterator operator+(difference_type i)
        {
            auto result = *this;
            result += i;
            return result;
        }

        /// subtract from iterator
        inline iterator operator-(difference_type i)
        {
            auto result = *this;
            result -= i;
            return result;
        }

        /// return difference
        inline difference_type operator-(const iterator& other) const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator- for object iterators");
                    return 0;
                }

                case (basic_json::value_t::array):
                {
                    return m_it.array_iterator - other.m_it.array_iterator;
                }

                default:
                {
                    return m_it.generic_iterator - other.m_it.generic_iterator;
                }
            }
        }

        /// access to successor
        inline reference operator[](difference_type n)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator[] for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    return *(m_it.array_iterator + n);
                }

                case (basic_json::value_t::null):
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.generic_iterator == -n)
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
        inline typename object_t::key_type key() const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return m_it.object_iterator->first;
                }

                default:
                {
                    throw std::domain_error("cannot use key() for non-object iterators");
                }
            }
        }

        /// return the key of an iterator
        inline reference value()
        {
            return operator*();
        }

      private:
        /// associated JSON instance
        pointer m_object = nullptr;
        /// the actual iterator of the associated instance
        internal_iterator<typename array_t::iterator, typename object_t::iterator> m_it;
    };

    /// a const random access iterator for the basic_json class
    class const_iterator : public std::iterator<std::random_access_iterator_tag, const basic_json>
    {
        // allow basic_json class to access m_it
        friend class basic_json;

      public:
        /// the type of the values when the iterator is dereferenced
        using value_type = basic_json::value_type;
        /// a type to represent differences between iterators
        using difference_type = basic_json::difference_type;
        /// defines a pointer to the type iterated over (value_type)
        using pointer = basic_json::const_pointer;
        /// defines a reference to the type iterated over (value_type)
        using reference = basic_json::const_reference;
        /// the category of the iterator
        using iterator_category = std::bidirectional_iterator_tag;

        /// default constructor
        inline const_iterator() = default;

        /// constructor for a given JSON instance
        inline const_iterator(pointer object) noexcept : m_object(object)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = typename object_t::const_iterator();
                    break;
                }
                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = typename array_t::const_iterator();
                    break;
                }
                default:
                {
                    m_it.generic_iterator = -1;
                    break;
                }
            }
        }

        /// copy constructor given a nonconst iterator
        inline const_iterator(const iterator& other) noexcept : m_object(other.m_object)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = other.m_it.object_iterator;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = other.m_it.array_iterator;
                    break;
                }

                default:
                {
                    m_it.generic_iterator = other.m_it.generic_iterator;
                    break;
                }
            }
        }

        /// copy constructor
        inline const_iterator(const const_iterator& other) noexcept
            : m_object(other.m_object), m_it(other.m_it)
        {}

        /// copy assignment
        inline const_iterator& operator=(const_iterator other) noexcept(
            std::is_nothrow_move_constructible<pointer>::value and
            std::is_nothrow_move_assignable<pointer>::value and
            std::is_nothrow_move_constructible<internal_iterator<typename array_t::const_iterator, typename object_t::const_iterator>>::value
            and
            std::is_nothrow_move_assignable<internal_iterator<typename array_t::const_iterator, typename object_t::const_iterator>>::value
        )
        {
            std::swap(m_object, other.m_object);
            std::swap(m_it, other.m_it);
            return *this;
        }

      private:
        /// set the iterator to the first value
        inline void set_begin() noexcept
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = m_object->m_value.object->cbegin();
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = m_object->m_value.array->cbegin();
                    break;
                }

                case (basic_json::value_t::null):
                {
                    // set to end so begin()==end() is true: null is empty
                    m_it.generic_iterator = 1;
                    break;
                }

                default:
                {
                    m_it.generic_iterator = 0;
                    break;
                }
            }
        }

        /// set the iterator past the last value
        inline void set_end() noexcept
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator = m_object->m_value.object->cend();
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator = m_object->m_value.array->cend();
                    break;
                }

                default:
                {
                    m_it.generic_iterator = 1;
                    break;
                }
            }
        }

      public:
        /// return a reference to the value pointed to by the iterator
        inline reference operator*() const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return m_it.object_iterator->second;
                }

                case (basic_json::value_t::array):
                {
                    return *m_it.array_iterator;
                }

                case (basic_json::value_t::null):
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.generic_iterator == 0)
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
        inline pointer operator->() const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return &(m_it.object_iterator->second);
                }

                case (basic_json::value_t::array):
                {
                    return &*m_it.array_iterator;
                }

                default:
                {
                    if (m_it.generic_iterator == 0)
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
        inline const_iterator operator++(int)
        {
            auto result = *this;

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator++;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator++;
                    break;
                }

                default:
                {
                    m_it.generic_iterator++;
                    break;
                }
            }

            return result;
        }

        /// pre-increment (++it)
        inline const_iterator& operator++()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    ++m_it.object_iterator;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    ++m_it.array_iterator;
                    break;
                }

                default:
                {
                    ++m_it.generic_iterator;
                    break;
                }
            }

            return *this;
        }

        /// post-decrement (it--)
        inline const_iterator operator--(int)
        {
            auto result = *this;

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    m_it.object_iterator--;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator--;
                    break;
                }

                default:
                {
                    m_it.generic_iterator--;
                    break;
                }
            }

            return result;
        }

        /// pre-decrement (--it)
        inline const_iterator& operator--()
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    --m_it.object_iterator;
                    break;
                }

                case (basic_json::value_t::array):
                {
                    --m_it.array_iterator;
                    break;
                }

                default:
                {
                    --m_it.generic_iterator;
                    break;
                }
            }

            return *this;
        }

        /// comparison: equal
        inline bool operator==(const const_iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return (m_it.object_iterator == other.m_it.object_iterator);
                }

                case (basic_json::value_t::array):
                {
                    return (m_it.array_iterator == other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.generic_iterator == other.m_it.generic_iterator);
                }
            }
        }

        /// comparison: not equal
        inline bool operator!=(const const_iterator& other) const
        {
            return not operator==(other);
        }

        /// comparison: smaller
        inline bool operator<(const const_iterator& other) const
        {
            // if objects are not the same, the comparison is undefined
            if (m_object != other.m_object)
            {
                throw std::domain_error("cannot compare iterators of different containers");
            }

            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator< for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    return (m_it.array_iterator < other.m_it.array_iterator);
                }

                default:
                {
                    return (m_it.generic_iterator < other.m_it.generic_iterator);
                }
            }
        }

        /// comparison: less than or equal
        inline bool operator<=(const const_iterator& other) const
        {
            return not other.operator < (*this);
        }

        /// comparison: greater than
        inline bool operator>(const const_iterator& other) const
        {
            return not operator<=(other);
        }

        /// comparison: greater than or equal
        inline bool operator>=(const const_iterator& other) const
        {
            return not operator<(other);
        }

        /// add to iterator
        inline const_iterator& operator+=(difference_type i)
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator+= for object iterators");
                    break;
                }

                case (basic_json::value_t::array):
                {
                    m_it.array_iterator += i;
                    break;
                }

                default:
                {
                    m_it.generic_iterator += i;
                    break;
                }
            }

            return *this;
        }

        /// subtract from iterator
        inline const_iterator& operator-=(difference_type i)
        {
            return operator+=(-i);
        }

        /// add to iterator
        inline const_iterator operator+(difference_type i)
        {
            auto result = *this;
            result += i;
            return result;
        }

        /// subtract from iterator
        inline const_iterator operator-(difference_type i)
        {
            auto result = *this;
            result -= i;
            return result;
        }

        /// return difference
        inline difference_type operator-(const const_iterator& other) const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator- for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    return m_it.array_iterator - other.m_it.array_iterator;
                }

                default:
                {
                    return m_it.generic_iterator - other.m_it.generic_iterator;
                }
            }
        }

        /// access to successor
        inline reference operator[](difference_type n) const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    throw std::domain_error("cannot use operator[] for object iterators");
                }

                case (basic_json::value_t::array):
                {
                    return *(m_it.array_iterator + n);
                }

                case (basic_json::value_t::null):
                {
                    throw std::out_of_range("cannot get value");
                }

                default:
                {
                    if (m_it.generic_iterator == -n)
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
        inline typename object_t::key_type key() const
        {
            switch (m_object->m_type)
            {
                case (basic_json::value_t::object):
                {
                    return m_it.object_iterator->first;
                }

                default:
                {
                    throw std::domain_error("cannot use key() for non-object iterators");
                }
            }
        }

        /// return the value of an iterator
        inline reference value() const
        {
            return operator*();
        }

      private:
        /// associated JSON instance
        pointer m_object = nullptr;
        /// the actual iterator of the associated instance
        internal_iterator<typename array_t::const_iterator, typename object_t::const_iterator> m_it;
    };

    /// a reverse random access iterator for the basic_json class
    class reverse_iterator : private std::reverse_iterator<basic_json::iterator>
    {
      public:
        inline reverse_iterator(const typename std::reverse_iterator<basic_json::iterator>::iterator_type&
                                it)
            : std::reverse_iterator<basic_json::iterator>(it) {}

        /// return the key of an object iterator
        inline typename object_t::key_type key() const
        {
            return this->base().key();
        }

        /// return the value of an iterator
        inline reference value() const
        {
            return this->base().operator * ();
        }
    };

    /// a const reverse random access iterator for the basic_json class
    class const_reverse_iterator : private std::reverse_iterator<basic_json::const_iterator>
    {
      public:
        inline const_reverse_iterator(const typename
                                      std::reverse_iterator<basic_json::const_iterator>::iterator_type& it)
            : std::reverse_iterator<basic_json::const_iterator>(it) {}

        /// return the key of an object iterator
        inline typename object_t::key_type key() const
        {
            return this->base().key();
        }

        /// return the value of an iterator
        inline const_reference value() const
        {
            return this->base().operator * ();
        }
    };


  private:
    //////////////////////
    // lexer and parser //
    //////////////////////

    /*!
    @brief lexical analysis

    This class organizes the lexical analysis during JSON deserialization. The
    core of it is a scanner generated by re2c <http://re2c.org> that processes
    a buffer and recognizes tokens according to RFC 7159 and ECMA-404.
    */
    class lexer
    {
      public:
        /// token types for the parser
        enum class token_type
        {
            uninitialized,    ///< indicating the scanner is uninitialized
            literal_true,     ///< the "true" literal
            literal_false,    ///< the "false" literal
            literal_null,     ///< the "null" literal
            value_string,     ///< a string - use get_string() for actual value
            value_number,     ///< a number - use get_number() for actual value
            begin_array,      ///< the character for array begin "["
            begin_object,     ///< the character for object begin "{"
            end_array,        ///< the character for array end "]"
            end_object,       ///< the character for object end "}"
            name_separator,   ///< the name separator ":"
            value_separator,  ///< the value separator ","
            parse_error,      ///< indicating a parse error
            end_of_input      ///< indicating the end of the input buffer
        };

        /// the char type to use in the lexer
        using lexer_char_t = unsigned char;

        /// constructor with a given buffer
        inline lexer(const string_t& s) noexcept
            : m_stream(nullptr), m_buffer(s)
        {
            m_content = reinterpret_cast<const lexer_char_t*>(s.c_str());
            m_start = m_cursor = m_content;
            m_limit = m_content + s.size();
        }
        inline lexer(std::istream* s) noexcept
            : m_stream(s)
        {
            getline(*m_stream, m_buffer);
            m_content = reinterpret_cast<const lexer_char_t*>(m_buffer.c_str());
            m_start = m_cursor = m_content;
            m_limit = m_content + m_buffer.size();
        }

        /// default constructor
        inline lexer() = default;

        /*!
        @brief create a string from a Unicode code point

        @param codepoint1  the code point (can be high surrogate)
        @param codepoint2  the code point (can be low surrogate or 0)
        @return string representation of the code point
        @exception std::out_of_range if code point is >0x10ffff
        @exception std::invalid_argument if the low surrogate is invalid

        @see <http://en.wikipedia.org/wiki/UTF-8#Sample_code>
        */
        inline static string_t to_unicode(const std::size_t codepoint1,
                                          const std::size_t codepoint2 = 0)
        {
            string_t result;

            // calculate the codepoint from the given code points
            std::size_t codepoint = codepoint1;
            if (codepoint1 >= 0xD800 and codepoint1 <= 0xDBFF)
            {
                if (codepoint2 >= 0xDC00 and codepoint2 <= 0xDFFF)
                {
                    codepoint =
                        // high surrogate occupies the most significant 22 bits
                        (codepoint1 << 10)
                        // low surrogate occupies the least significant 15 bits
                        + codepoint2
                        // there is still the 0xD800, 0xDC00 and 0x10000 noise
                        // in the result so we have to substract with:
                        // (0xD800 << 10) + DC00 - 0x10000 = 0x35FDC00
                        - 0x35FDC00;
                }
                else
                {
                    throw std::invalid_argument("missing or wrong low surrogate");
                }
            }

            if (codepoint <= 0x7f)
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

        /// return name of values of type token_type
        inline static std::string token_type_name(token_type t) noexcept
        {
            switch (t)
            {
                case (token_type::uninitialized):
                    return "<uninitialized>";
                case (token_type::literal_true):
                    return "true literal";
                case (token_type::literal_false):
                    return "false literal";
                case (token_type::literal_null):
                    return "null literal";
                case (token_type::value_string):
                    return "string literal";
                case (token_type::value_number):
                    return "number literal";
                case (token_type::begin_array):
                    return "[";
                case (token_type::begin_object):
                    return "{";
                case (token_type::end_array):
                    return "]";
                case (token_type::end_object):
                    return "}";
                case (token_type::name_separator):
                    return ":";
                case (token_type::value_separator):
                    return ",";
                case (token_type::end_of_input):
                    return "<end of input>";
                default:
                    return "<parse error>";
            }
        }

        /*!
        This function implements a scanner for JSON. It is specified using
        regular expressions that try to follow RFC 7159 and ECMA-404 as close
        as possible. These regular expressions are then translated into a
        deterministic finite automaton (DFA) by the tool re2c
        <http://re2c.org>. As a result, the translated code for this function
        consists of a large block of code with goto jumps.

        @return the class of the next token read from the buffer
        */
        inline token_type scan() noexcept
        {
            // pointer for backtracking information
            m_marker = nullptr;

            // remember the begin of the token
            m_start = m_cursor;


            {
                lexer_char_t yych;
                unsigned int yyaccept = 0;
                static const unsigned char yybm[] =
                {
                    0,  64,  64,  64,  64,  64,  64,  64,
                    64,  96,  96,  64,  64,  96,  64,  64,
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
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '9')
                {
                    if (yych <= ' ')
                    {
                        if (yych <= '\n')
                        {
                            if (yych <= 0x00)
                            {
                                goto basic_json_parser_27;
                            }
                            if (yych <= 0x08)
                            {
                                goto basic_json_parser_29;
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
                                goto basic_json_parser_29;
                            }
                        }
                    }
                    else
                    {
                        if (yych <= ',')
                        {
                            if (yych == '"')
                            {
                                goto basic_json_parser_26;
                            }
                            if (yych <= '+')
                            {
                                goto basic_json_parser_29;
                            }
                            goto basic_json_parser_14;
                        }
                        else
                        {
                            if (yych <= '-')
                            {
                                goto basic_json_parser_22;
                            }
                            if (yych <= '/')
                            {
                                goto basic_json_parser_29;
                            }
                            if (yych <= '0')
                            {
                                goto basic_json_parser_23;
                            }
                            goto basic_json_parser_25;
                        }
                    }
                }
                else
                {
                    if (yych <= 'm')
                    {
                        if (yych <= '\\')
                        {
                            if (yych <= ':')
                            {
                                goto basic_json_parser_16;
                            }
                            if (yych == '[')
                            {
                                goto basic_json_parser_6;
                            }
                            goto basic_json_parser_29;
                        }
                        else
                        {
                            if (yych <= ']')
                            {
                                goto basic_json_parser_8;
                            }
                            if (yych == 'f')
                            {
                                goto basic_json_parser_21;
                            }
                            goto basic_json_parser_29;
                        }
                    }
                    else
                    {
                        if (yych <= 'z')
                        {
                            if (yych <= 'n')
                            {
                                goto basic_json_parser_18;
                            }
                            if (yych == 't')
                            {
                                goto basic_json_parser_20;
                            }
                            goto basic_json_parser_29;
                        }
                        else
                        {
                            if (yych <= '{')
                            {
                                goto basic_json_parser_10;
                            }
                            if (yych == '}')
                            {
                                goto basic_json_parser_12;
                            }
                            goto basic_json_parser_29;
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
                    yyfill();
                };
                yych = *m_cursor;
basic_json_parser_5:
                if (yybm[0 + yych] & 32)
                {
                    goto basic_json_parser_4;
                }
                goto basic_json_parser_3;
basic_json_parser_6:
                ++m_cursor;
                {
                    return token_type::begin_array;
                }
basic_json_parser_8:
                ++m_cursor;
                {
                    return token_type::end_array;
                }
basic_json_parser_10:
                ++m_cursor;
                {
                    return token_type::begin_object;
                }
basic_json_parser_12:
                ++m_cursor;
                {
                    return token_type::end_object;
                }
basic_json_parser_14:
                ++m_cursor;
                {
                    return token_type::value_separator;
                }
basic_json_parser_16:
                ++m_cursor;
                {
                    return token_type::name_separator;
                }
basic_json_parser_18:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'u')
                {
                    goto basic_json_parser_59;
                }
basic_json_parser_19:
                {
                    return token_type::parse_error;
                }
basic_json_parser_20:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'r')
                {
                    goto basic_json_parser_55;
                }
                goto basic_json_parser_19;
basic_json_parser_21:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych == 'a')
                {
                    goto basic_json_parser_50;
                }
                goto basic_json_parser_19;
basic_json_parser_22:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_19;
                }
                if (yych <= '0')
                {
                    goto basic_json_parser_49;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_40;
                }
                goto basic_json_parser_19;
basic_json_parser_23:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 'D')
                {
                    if (yych == '.')
                    {
                        goto basic_json_parser_42;
                    }
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_43;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_43;
                    }
                }
basic_json_parser_24:
                {
                    return token_type::value_number;
                }
basic_json_parser_25:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                goto basic_json_parser_41;
basic_json_parser_26:
                yyaccept = 0;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 0x00)
                {
                    goto basic_json_parser_19;
                }
                goto basic_json_parser_31;
basic_json_parser_27:
                ++m_cursor;
                {
                    return token_type::end_of_input;
                }
basic_json_parser_29:
                yych = *++m_cursor;
                goto basic_json_parser_19;
basic_json_parser_30:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
basic_json_parser_31:
                if (yybm[0 + yych] & 64)
                {
                    goto basic_json_parser_30;
                }
                if (yych <= 0x00)
                {
                    goto basic_json_parser_32;
                }
                if (yych <= '"')
                {
                    goto basic_json_parser_34;
                }
                goto basic_json_parser_33;
basic_json_parser_32:
                m_cursor = m_marker;
                if (yyaccept == 0)
                {
                    goto basic_json_parser_19;
                }
                else
                {
                    goto basic_json_parser_24;
                }
basic_json_parser_33:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= 'e')
                {
                    if (yych <= '/')
                    {
                        if (yych == '"')
                        {
                            goto basic_json_parser_30;
                        }
                        if (yych <= '.')
                        {
                            goto basic_json_parser_32;
                        }
                        goto basic_json_parser_30;
                    }
                    else
                    {
                        if (yych <= '\\')
                        {
                            if (yych <= '[')
                            {
                                goto basic_json_parser_32;
                            }
                            goto basic_json_parser_30;
                        }
                        else
                        {
                            if (yych == 'b')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_32;
                        }
                    }
                }
                else
                {
                    if (yych <= 'q')
                    {
                        if (yych <= 'f')
                        {
                            goto basic_json_parser_30;
                        }
                        if (yych == 'n')
                        {
                            goto basic_json_parser_30;
                        }
                        goto basic_json_parser_32;
                    }
                    else
                    {
                        if (yych <= 's')
                        {
                            if (yych <= 'r')
                            {
                                goto basic_json_parser_30;
                            }
                            goto basic_json_parser_32;
                        }
                        else
                        {
                            if (yych <= 't')
                            {
                                goto basic_json_parser_30;
                            }
                            if (yych <= 'u')
                            {
                                goto basic_json_parser_36;
                            }
                            goto basic_json_parser_32;
                        }
                    }
                }
basic_json_parser_34:
                ++m_cursor;
                {
                    return token_type::value_string;
                }
basic_json_parser_36:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_32;
                    }
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_37;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_32;
                    }
                }
basic_json_parser_37:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_32;
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
                        goto basic_json_parser_32;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_32;
                    }
                }
basic_json_parser_38:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych >= ':')
                    {
                        goto basic_json_parser_32;
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
                        goto basic_json_parser_32;
                    }
                    if (yych >= 'g')
                    {
                        goto basic_json_parser_32;
                    }
                }
basic_json_parser_39:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '@')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_30;
                    }
                    goto basic_json_parser_32;
                }
                else
                {
                    if (yych <= 'F')
                    {
                        goto basic_json_parser_30;
                    }
                    if (yych <= '`')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych <= 'f')
                    {
                        goto basic_json_parser_30;
                    }
                    goto basic_json_parser_32;
                }
basic_json_parser_40:
                yyaccept = 1;
                m_marker = ++m_cursor;
                if ((m_limit - m_cursor) < 3)
                {
                    yyfill();
                };
                yych = *m_cursor;
basic_json_parser_41:
                if (yybm[0 + yych] & 128)
                {
                    goto basic_json_parser_40;
                }
                if (yych <= 'D')
                {
                    if (yych != '.')
                    {
                        goto basic_json_parser_24;
                    }
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_43;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_43;
                    }
                    goto basic_json_parser_24;
                }
basic_json_parser_42:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_32;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_47;
                }
                goto basic_json_parser_32;
basic_json_parser_43:
                yych = *++m_cursor;
                if (yych <= ',')
                {
                    if (yych != '+')
                    {
                        goto basic_json_parser_32;
                    }
                }
                else
                {
                    if (yych <= '-')
                    {
                        goto basic_json_parser_44;
                    }
                    if (yych <= '/')
                    {
                        goto basic_json_parser_32;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_45;
                    }
                    goto basic_json_parser_32;
                }
basic_json_parser_44:
                yych = *++m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_32;
                }
                if (yych >= ':')
                {
                    goto basic_json_parser_32;
                }
basic_json_parser_45:
                ++m_cursor;
                if (m_limit <= m_cursor)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= '/')
                {
                    goto basic_json_parser_24;
                }
                if (yych <= '9')
                {
                    goto basic_json_parser_45;
                }
                goto basic_json_parser_24;
basic_json_parser_47:
                yyaccept = 1;
                m_marker = ++m_cursor;
                if ((m_limit - m_cursor) < 3)
                {
                    yyfill();
                };
                yych = *m_cursor;
                if (yych <= 'D')
                {
                    if (yych <= '/')
                    {
                        goto basic_json_parser_24;
                    }
                    if (yych <= '9')
                    {
                        goto basic_json_parser_47;
                    }
                    goto basic_json_parser_24;
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_43;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_43;
                    }
                    goto basic_json_parser_24;
                }
basic_json_parser_49:
                yyaccept = 1;
                yych = *(m_marker = ++m_cursor);
                if (yych <= 'D')
                {
                    if (yych == '.')
                    {
                        goto basic_json_parser_42;
                    }
                    goto basic_json_parser_24;
                }
                else
                {
                    if (yych <= 'E')
                    {
                        goto basic_json_parser_43;
                    }
                    if (yych == 'e')
                    {
                        goto basic_json_parser_43;
                    }
                    goto basic_json_parser_24;
                }
basic_json_parser_50:
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_32;
                }
                yych = *++m_cursor;
                if (yych != 's')
                {
                    goto basic_json_parser_32;
                }
                yych = *++m_cursor;
                if (yych != 'e')
                {
                    goto basic_json_parser_32;
                }
                ++m_cursor;
                {
                    return token_type::literal_false;
                }
basic_json_parser_55:
                yych = *++m_cursor;
                if (yych != 'u')
                {
                    goto basic_json_parser_32;
                }
                yych = *++m_cursor;
                if (yych != 'e')
                {
                    goto basic_json_parser_32;
                }
                ++m_cursor;
                {
                    return token_type::literal_true;
                }
basic_json_parser_59:
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_32;
                }
                yych = *++m_cursor;
                if (yych != 'l')
                {
                    goto basic_json_parser_32;
                }
                ++m_cursor;
                {
                    return token_type::literal_null;
                }
            }


        }

        /// append data from the stream to the internal buffer
        inline void yyfill() noexcept
        {
            if (not m_stream or not * m_stream)
            {
                return;
            }

            const ssize_t offset_start = m_start - m_content;
            const ssize_t offset_marker = m_marker - m_start;
            const ssize_t offset_cursor = m_cursor - m_start;

            m_buffer.erase(0, static_cast<size_t>(offset_start));
            std::string line;
            std::getline(*m_stream, line);
            m_buffer += line;

            m_content = reinterpret_cast<const lexer_char_t*>(m_buffer.c_str());
            m_start  = m_content;
            m_marker = m_start + offset_marker;
            m_cursor = m_start + offset_cursor;
            m_limit  = m_start + m_buffer.size() - 1;
        }

        /// return string representation of last read token
        inline string_t get_token() const noexcept
        {
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
           characters (e.g., @c "\\n" is replaced by @c "\n"), some are copied
           as is (e.g., @c "\\\\"). Furthermore, Unicode escapes of the shape
           @c "\\uxxxx" need special care. In this case, to_unicode takes care
           of the construction of the values.
        2. Unescaped characters are copied as is.

        @return string value of current token without opening and closing quotes
        @exception std::out_of_range if to_unicode fails
        */
        inline string_t get_string() const
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

                        // characters that are not "un"escsaped
                        case '\\':
                        {
                            result += "\\\\";
                            break;
                        }
                        case '/':
                        {
                            result += "\\/";
                            break;
                        }
                        case '"':
                        {
                            result += "\\\"";
                            break;
                        }

                        // unicode
                        case 'u':
                        {
                            // get code xxxx from uxxxx
                            auto codepoint = std::strtoul(std::string(reinterpret_cast<typename string_t::const_pointer>(i + 1),
                                                          4).c_str(), nullptr, 16);

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
                                // skip the next 11 characters (xxxx\uyyyy)
                                i += 11;
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
        @brief return number value for number tokens

        This function translates the last token into a floating point number.
        The pointer m_begin points to the beginning of the parsed number. We
        pass this pointer to std::strtod which sets endptr to the first
        character past the converted number. If this pointer is not the same as
        m_cursor, then either more or less characters have been used during the
        comparison. This can happen for inputs like "01" which will be treated
        like number 0 followed by number 1.

        @return the result of the number conversion or NAN if the conversion
        read past the current token. The latter case needs to be treated by the
        caller function.

        @exception std::range_error if passed value is out of range
        */
        inline number_float_t get_number() const
        {
            // conversion
            typename string_t::value_type* endptr;
            const auto float_val = std::strtod(reinterpret_cast<typename string_t::const_pointer>(m_start),
                                               &endptr);

            // return float_val if the whole number was translated and NAN
            // otherwise
            return (reinterpret_cast<lexer_char_t*>(endptr) == m_cursor) ? float_val : NAN;
        }

      private:
        /// optional input stream
        std::istream* m_stream;
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
    */
    class parser
    {
      public:
        /// constructor for strings
        inline parser(const string_t& s) : m_lexer(s)
        {
            // read first token
            get_token();
        }

        /// a parser reading from an input stream
        inline parser(std::istream& _is) : m_lexer(&_is)
        {
            // read first token
            get_token();
        }

        /// public parser interface
        inline basic_json parse()
        {
            basic_json result = parse_internal();

            expect(lexer::token_type::end_of_input);

            return result;
        }

      private:
        /// the actual parser
        inline basic_json parse_internal()
        {
            switch (last_token)
            {
                case (lexer::token_type::begin_object):
                {
                    // explicitly set result to object to cope with {}
                    basic_json result(value_t::object);

                    // read next token
                    get_token();

                    // closing } -> we are done
                    if (last_token == lexer::token_type::end_object)
                    {
                        get_token();
                        return result;
                    }

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

                        // parse separator (:)
                        get_token();
                        expect(lexer::token_type::name_separator);

                        // parse value
                        get_token();
                        result[key] = parse_internal();
                    }
                    while (last_token == lexer::token_type::value_separator);

                    // closing }
                    expect(lexer::token_type::end_object);
                    get_token();

                    return result;
                }

                case (lexer::token_type::begin_array):
                {
                    // explicitly set result to object to cope with []
                    basic_json result(value_t::array);

                    // read next token
                    get_token();

                    // closing ] -> we are done
                    if (last_token == lexer::token_type::end_array)
                    {
                        get_token();
                        return result;
                    }

                    // otherwise: parse values
                    do
                    {
                        // ugly, but could be fixed with loop reorganization
                        if (last_token == lexer::token_type::value_separator)
                        {
                            get_token();
                        }

                        // parse value
                        result.push_back(parse_internal());
                    }
                    while (last_token == lexer::token_type::value_separator);

                    // closing ]
                    expect(lexer::token_type::end_array);
                    get_token();

                    return result;
                }

                case (lexer::token_type::literal_null):
                {
                    get_token();
                    return basic_json(nullptr);
                }

                case (lexer::token_type::value_string):
                {
                    const auto s = m_lexer.get_string();
                    get_token();
                    return basic_json(s);
                }

                case (lexer::token_type::literal_true):
                {
                    get_token();
                    return basic_json(true);
                }

                case (lexer::token_type::literal_false):
                {
                    get_token();
                    return basic_json(false);
                }

                case (lexer::token_type::value_number):
                {
                    auto float_val = m_lexer.get_number();

                    // NAN is returned if token could not be translated
                    // completely
                    if (std::isnan(float_val))
                    {
                        throw std::invalid_argument(std::string("parse error - ") +
                                                    m_lexer.get_token() + " is not a number");
                    }

                    get_token();

                    // check if conversion loses precision
                    const auto int_val = static_cast<number_integer_t>(float_val);
                    if (approx(float_val, static_cast<number_float_t>(int_val)))
                    {
                        // we basic_json not lose precision -> return int
                        return basic_json(int_val);
                    }
                    else
                    {
                        // we would lose precision -> returnfloat
                        return basic_json(float_val);
                    }
                }

                default:
                {
                    std::string error_msg = "parse error - unexpected \'";
                    error_msg += m_lexer.get_token();
                    error_msg += "\' (";
                    error_msg += lexer::token_type_name(last_token) + ")";
                    throw std::invalid_argument(error_msg);
                }
            }
        }

        /// get next token from lexer
        inline typename lexer::token_type get_token()
        {
            last_token = m_lexer.scan();
            return last_token;
        }

        inline void expect(typename lexer::token_type t) const
        {
            if (t != last_token)
            {
                std::string error_msg = "parse error - unexpected \'";
                error_msg += m_lexer.get_token();
                error_msg += "\' (" + lexer::token_type_name(last_token);
                error_msg += "); expected " + lexer::token_type_name(t);
                throw std::invalid_argument(error_msg);
            }
        }

      private:
        /// the type of the last read token
        typename lexer::token_type last_token = lexer::token_type::uninitialized;
        /// the lexer
        lexer m_lexer;
    };
};


/////////////
// presets //
/////////////

/// default JSON class
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
@ingroup container
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
    /// return a hash value for a JSON object
    inline std::size_t operator()(const nlohmann::json& j) const
    {
        // a naive hashing via the string representation
        const auto& h = hash<nlohmann::json::string_t>();
        return h(j.dump());
    }
};
}

/*!
This operator implements a user-defined string literal for JSON objects. It can
be used by adding \p "_json" to a string literal and returns a JSON object if
no parse error occurred.

@param s  a string representation of a JSON object
@return a JSON object
*/
inline nlohmann::json operator "" _json(const char* s, std::size_t)
{
    return nlohmann::json::parse(reinterpret_cast<nlohmann::json::string_t::value_type*>
                                 (const_cast<char*>(s)));
}

#endif
