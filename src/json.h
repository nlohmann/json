/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2015 Niels Lohmann.

@author Niels Lohmann <http://nlohmann.me>

@see https://github.com/nlohmann/json
*/

#pragma once

#include <initializer_list>  // std::initializer_list
#include <iostream>          // std::istream, std::ostream
#include <map>               // std::map
#include <string>            // std::string
#include <vector>            // std::vector
#include <iterator>          // std::iterator
#include <limits>            // std::numeric_limits
#include <functional>        // std::hash

namespace nlohmann
{

/*!
@brief JSON for Modern C++

The size of a JSON object is 16 bytes: 8 bytes for the value union whose
largest item is a pointer type and another 8 byte for an element of the
type union. The latter only needs 1 byte - the remaining 7 bytes are wasted
due to alignment.

@see http://stackoverflow.com/questions/7758580/writing-your-own-stl-container/7759622#7759622

@bug Numbers are currently handled too generously. There are several formats
     that are forbidden by the standard, but are accepted by the parser.

@todo Implement json::insert(), json::emplace(), json::emplace_back, json::erase
*/
class json
{
  public:
    // forward declaration to friend this class
    class iterator;
    class const_iterator;

  public:
    // container types
    /// the type of elements in a JSON class
    using value_type = json;
    /// the type of element references
    using reference = json&;
    /// the type of const element references
    using const_reference = const json&;
    /// the type of pointers to elements
    using pointer = json*;
    /// the type of const pointers to elements
    using const_pointer = const json*;
    /// a type to represent differences between iterators
    using difference_type = std::ptrdiff_t;
    /// a type to represent container sizes
    using size_type = std::size_t;
    /// an iterator for a JSON container
    using iterator = json::iterator;
    /// a const iterator for a JSON container
    using const_iterator = json::const_iterator;
    /// a reverse iterator for a JSON container
    using reverse_iterator = std::reverse_iterator<iterator>;
    /// a const reverse iterator for a JSON container
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    /// a type for an object
    using object_t = std::map<std::string, json>;
    /// a type for an array
    using array_t = std::vector<json>;
    /// a type for a string
    using string_t = std::string;
    /// a type for a Boolean
    using boolean_t = bool;
    /// a type for an integer number
    using number_t = int64_t;
    /// a type for a floating point number
    using number_float_t = double;
    /// a type for list initialization
    using list_init_t = std::initializer_list<json>;

    /// a JSON value
    union value
    {
        /// array as pointer to array_t
        array_t* array;
        /// object as pointer to object_t
        object_t* object;
        /// string as pointer to string_t
        string_t* string;
        /// Boolean
        boolean_t boolean;
        /// number (integer)
        number_t number;
        /// number (float)
        number_float_t number_float;

        /// default constructor
        value() = default;
        /// constructor for arrays
        value(array_t*);
        /// constructor for objects
        value(object_t*);
        /// constructor for strings
        value(string_t*);
        /// constructor for Booleans
        value(boolean_t);
        /// constructor for numbers (integer)
        value(number_t);
        /// constructor for numbers (float)
        value(number_float_t);
    };

    /// possible types of a JSON object
    enum class value_t : uint8_t
    {
        /// ordered collection of values
        array = 0,
        /// unordered set of name/value pairs
        object,
        /// null value
        null,
        /// string value
        string,
        /// Boolean value
        boolean,
        /// number value (integer)
        number,
        /// number value (float)
        number_float
    };

  public:
    /// create an object according to given type
    json(const value_t);
    /// create a null object
    json() noexcept;
    /// create a null object
    json(std::nullptr_t) noexcept;
    /// create a string object from a C++ string
    json(const std::string&);
    /// create a string object from a C++ string (move)
    json(std::string&&);
    /// create a string object from a C string
    json(const char*);
    /// create a Boolean object
    json(const bool) noexcept;
    /// create an array
    json(const array_t&);
    /// create an array (move)
    json(array_t&&);
    /// create an object
    json(const object_t&);
    /// create an object (move)
    json(object_t&&);
    /// create from an initializer list (to an array or object)
    json(list_init_t, bool = true, value_t = value_t::array);

    /*!
    @brief create a number object (integer)
    @param n  an integer number to wrap in a JSON object
    */
    template<typename T, typename
             std::enable_if<
                 std::numeric_limits<T>::is_integer, T>::type
             = 0>
    json(const T n) noexcept
        : final_type_(0), type_(value_t::number),
          value_(static_cast<number_t>(n))
    {}

    /*!
    @brief create a number object (float)
    @param n  a floating point number to wrap in a JSON object
    */
    template<typename T, typename = typename
             std::enable_if<
                 std::is_floating_point<T>::value>::type
             >
    json(const T n) noexcept
        : final_type_(0), type_(value_t::number_float),
          value_(static_cast<number_float_t>(n))
    {}

    /*!
    @brief create an array object
    @param v  any type of container whose elements can be use to construct
              JSON objects (e.g., std::vector, std::set, std::array)
    @note For some reason, we need to explicitly forbid JSON iterator types.
    */
    template <class V, typename
              std::enable_if<
                  not std::is_same<V, json::iterator>::value and
                  not std::is_same<V, json::const_iterator>::value and
                  not std::is_same<V, json::reverse_iterator>::value and
                  not std::is_same<V, json::const_reverse_iterator>::value and
                  std::is_constructible<json, typename V::value_type>::value, int>::type
              = 0>
    json(const V& v) : json(array_t(v.begin(), v.end()))
    {}

    /*!
    @brief create a JSON object
    @param v  any type of associative container whose elements can be use to
              construct JSON objects (e.g., std::map<std::string, *>)
    */
    template <class V, typename
              std::enable_if<
                  std::is_constructible<std::string, typename V::key_type>::value and
                  std::is_constructible<json, typename V::mapped_type>::value, int>::type
              = 0>
    json(const V& v) : json(object_t(v.begin(), v.end()))
    {}

    /// copy constructor
    json(const json&);
    /// move constructor
    json(json&&) noexcept;

    /// copy assignment
    json& operator=(json) noexcept;

    /// destructor
    ~json() noexcept;

    /// explicit keyword to force array creation
    static json array(list_init_t = list_init_t());
    /// explicit keyword to force object creation
    static json object(list_init_t = list_init_t());

    /// create from string representation
    static json parse(const std::string&);
    /// create from string representation
    static json parse(const char*);

  private:
    /// return the type as string
    std::string type_name() const noexcept;

    /// dump the object (with pretty printer)
    std::string dump(const bool, const unsigned int, unsigned int = 0) const noexcept;
    /// replaced a character in a string with another string
    void replaceChar(std::string& str, char c, const std::string& replacement) const;
    /// escapes special characters to safely dump the string
    std::string escapeString(const std::string&) const;

  public:
    /// explicit value conversion
    template<typename T>
    T get() const;

    /// implicit conversion to string representation
    operator std::string() const;
    /// implicit conversion to integer (only for numbers)
    operator int() const;
    /// implicit conversion to integer (only for numbers)
    operator int64_t() const;
    /// implicit conversion to double (only for numbers)
    operator double() const;
    /// implicit conversion to Boolean (only for Booleans)
    operator bool() const;
    /// implicit conversion to JSON vector (not for objects)
    operator array_t() const;
    /// implicit conversion to JSON map (only for objects)
    operator object_t() const;

    /// serialize to stream
    friend std::ostream& operator<<(std::ostream& o, const json& j)
    {
        o << j.dump();
        return o;
    }
    /// serialize to stream
    friend std::ostream& operator>>(const json& j, std::ostream& o)
    {
        o << j.dump();
        return o;
    }

    /// deserialize from stream
    friend std::istream& operator>>(std::istream& i, json& j)
    {
        j = parser(i).parse();
        return i;
    }
    /// deserialize from stream
    friend std::istream& operator<<(json& j, std::istream& i)
    {
        j = parser(i).parse();
        return i;
    }

    /// explicit serialization
    std::string dump(int = -1) const noexcept;

    /// add constructible objects to an array
    template<class T, typename std::enable_if<std::is_constructible<json, T>::value>::type = 0>
    json & operator+=(const T& o)
    {
        push_back(json(o));
        return *this;
    }

    /// add an object/array to an array
    json& operator+=(const json&);

    /// add a pair to an object
    json& operator+=(const object_t::value_type&);
    /// add a list of elements to array or list of pairs to object
    json& operator+=(list_init_t);

    /// add constructible objects to an array
    template<class T, typename std::enable_if<std::is_constructible<json, T>::value>::type = 0>
    void push_back(const T& o)
    {
        push_back(json(o));
    }

    /// add an object/array to an array
    void push_back(const json&);
    /// add an object/array to an array (move)
    void push_back(json&&);

    /// add a pair to an object
    void push_back(const object_t::value_type&);
    /// add a list of elements to array or list of pairs to object
    void push_back(list_init_t);

    /// operator to set an element in an array
    reference operator[](const int);
    /// operator to get an element in an array
    const_reference operator[](const int) const;
    /// operator to get an element in an array
    reference at(const int);
    /// operator to get an element in an array
    const_reference at(const int) const;

    /// operator to set an element in an object
    reference operator[](const std::string&);
    /// operator to set an element in an object
    reference operator[](const char*);
    /// operator to get an element in an object
    const_reference operator[](const std::string&) const;
    /// operator to get an element in an object
    const_reference operator[](const char*) const;
    /// operator to set an element in an object
    reference at(const std::string&);
    /// operator to set an element in an object
    reference at(const char*);
    /// operator to get an element in an object
    const_reference at(const std::string&) const;
    /// operator to get an element in an object
    const_reference at(const char*) const;

    /// return the number of stored values
    size_type size() const noexcept;
    /// return the maximal number of values that can be stored
    size_type max_size() const noexcept;
    /// checks whether object is empty
    bool empty() const noexcept;
    /// removes all elements from compounds and resets values to default
    void clear() noexcept;

    /// swaps content with other object
    void swap(json&) noexcept;

    /// return the type of the object
    value_t type() const noexcept;

    /// find an element in an object (returns end() iterator otherwise)
    iterator find(const std::string&);
    /// find an element in an object (returns end() iterator otherwise)
    const_iterator find(const std::string&) const;
    /// find an element in an object (returns end() iterator otherwise)
    iterator find(const char*);
    /// find an element in an object (returns end() iterator otherwise)
    const_iterator find(const char*) const;

    /// lexicographically compares the values
    bool operator==(const json&) const noexcept;
    /// lexicographically compares the values
    bool operator!=(const json&) const noexcept;

    /// returns an iterator to the beginning (array/object)
    iterator begin() noexcept;
    /// returns an iterator to the end (array/object)
    iterator end() noexcept;
    /// returns an iterator to the beginning (array/object)
    const_iterator begin() const noexcept;
    /// returns an iterator to the end (array/object)
    const_iterator end() const noexcept;
    /// returns an iterator to the beginning (array/object)
    const_iterator cbegin() const noexcept;
    /// returns an iterator to the end (array/object)
    const_iterator cend() const noexcept;
    /// returns a reverse iterator to the beginning
    reverse_iterator rbegin() noexcept;
    /// returns a reverse iterator to the end
    reverse_iterator rend() noexcept;
    /// returns a reverse iterator to the beginning
    const_reverse_iterator crbegin() const noexcept;
    /// returns a reverse iterator to the end
    const_reverse_iterator crend() const noexcept;

  private:
    /// whether the type is final
    unsigned final_type_ : 1;
    /// the type of this object
    value_t type_ = value_t::null;
    /// the payload
    value value_ {};

  public:
    /// an iterator
    class iterator : public std::iterator<std::bidirectional_iterator_tag, json>
    {
        friend class json;
        friend class json::const_iterator;

      public:
        iterator() = default;
        iterator(json*, bool);
        iterator(const iterator&);
        ~iterator();

        iterator& operator=(iterator);
        bool operator==(const iterator&) const;
        bool operator!=(const iterator&) const;
        iterator& operator++();
        iterator& operator--();
        json& operator*() const;
        json* operator->() const;

        /// getter for the key (in case of objects)
        std::string key() const;
        /// getter for the value
        json& value() const;

      private:
        /// a JSON value
        json* object_ = nullptr;
        /// an iterator for JSON arrays
        array_t::iterator* vi_ = nullptr;
        /// an iterator for JSON objects
        object_t::iterator* oi_ = nullptr;
        /// whether iterator points to a valid object
        bool invalid = true;
    };

    /// a const iterator
    class const_iterator : public std::iterator<std::bidirectional_iterator_tag, const json>
    {
        friend class json;

      public:
        const_iterator() = default;
        const_iterator(const json*, bool);
        const_iterator(const const_iterator&);
        const_iterator(const json::iterator&);
        ~const_iterator();

        const_iterator& operator=(const_iterator);
        bool operator==(const const_iterator&) const;
        bool operator!=(const const_iterator&) const;
        const_iterator& operator++();
        const_iterator& operator--();
        const json& operator*() const;
        const json* operator->() const;

        /// getter for the key (in case of objects)
        std::string key() const;
        /// getter for the value
        const json& value() const;

      private:
        /// a JSON value
        const json* object_ = nullptr;
        /// an iterator for JSON arrays
        array_t::const_iterator* vi_ = nullptr;
        /// an iterator for JSON objects
        object_t::const_iterator* oi_ = nullptr;
        /// whether iterator reached past the end
        bool invalid = true;
    };

  private:
    /// a helper class to parse a JSON object
    class parser
    {
      public:
        /// a parser reading from a C string
        parser(const char*);
        /// a parser reading from a C++ string
        parser(const std::string&);
        /// a parser reading from an input stream
        parser(std::istream&);
        /// destructor of the parser
        ~parser() = default;

        // no copy constructor
        parser(const parser&) = delete;
        // no copy assignment
        parser& operator=(parser) = delete;

        /// parse and return a JSON object
        json parse();

      private:
        /// read the next character, stripping whitespace
        bool next();
        /// raise an exception with an error message
        [[noreturn]] inline void error(const std::string&) const;
        /// parse a quoted string
        inline std::string parseString();
        /// transforms a unicode codepoint to it's UTF-8 presentation
        std::string codePointToUTF8(unsigned int codePoint) const;
        /// parses 4 hex characters that represent a unicode code point
        inline unsigned int parse4HexCodePoint();
        /// parses \uXXXX[\uXXXX] unicode escape characters
        inline std::string parseUnicodeEscape();
        /// parse a Boolean "true"
        inline void parseTrue();
        /// parse a Boolean "false"
        inline void parseFalse();
        /// parse a null object
        inline void parseNull();
        /// a helper function to expect a certain character
        inline void expect(const char);

      private:
        /// a buffer of the input
        std::string buffer_ {};
        /// the current character
        char current_ {};
        /// the position inside the input buffer
        std::size_t pos_ = 0;
    };
};

}

/// user-defined literal operator to create JSON objects from strings
nlohmann::json operator "" _json(const char*, std::size_t);

// specialization of std::swap, and std::hash
namespace std
{
template <>
/// swaps the values of two JSON objects
inline void swap(nlohmann::json& j1,
                 nlohmann::json& j2) noexcept(
                     is_nothrow_move_constructible<nlohmann::json>::value and
                     is_nothrow_move_assignable<nlohmann::json>::value
                 )
{
    j1.swap(j2);
}

template <>
/// hash value for JSON objects
struct hash<nlohmann::json>
{
    size_t operator()(const nlohmann::json& j) const
    {
        // a naive hashing via the string representation
        return hash<std::string>()(j.dump());
    }
};

}
