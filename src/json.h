/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2014 Niels Lohmann.

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
@todo Implement json::reverse_iterator, json::const_reverse_iterator,
      json::rbegin(), json::rend(), json::crbegin(), json::crend()?
*/
class json
{
    // forward declaration to friend this class
  public:
    class iterator;
    class const_iterator;

  public:
    /// possible types of a JSON object
    enum class value_type : uint8_t
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

    /// a type for an object
    using object_t = std::map<std::string, json>;
    /// a type for an array
    using array_t = std::vector<json>;
    /// a type for a string
    using string_t = std::string;
    /// a type for a Boolean
    using boolean_t = bool;
    /// a type for an integer number
    using number_t = int;
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

  public:
    /// create an object according to given type
    json(const value_type);
    /// create a null object
    json() = default;
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
    /// create a number object
    json(const int) noexcept;
    /// create a number object
    json(const double) noexcept;
    /// create an array
    json(const array_t&);
    /// create an array (move)
    json(array_t&&);
    /// create an object
    json(const object_t&);
    /// create an object (move)
    json(object_t&&);
    /// create from an initializer list (to an array or object)
    json(list_init_t);

    /// copy constructor
    json(const json&);
    /// move constructor
    json(json&&) noexcept;

    /// copy assignment
    json& operator=(json) noexcept;

    /// destructor
    ~json() noexcept;

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

    /// add an object/array to an array
    json& operator+=(const json&);
    /// add a string to an array
    json& operator+=(const std::string&);
    /// add a null object to an array
    json& operator+=(const std::nullptr_t);
    /// add a string to an array
    json& operator+=(const char*);
    /// add a Boolean to an array
    json& operator+=(bool);
    /// add a number to an array
    json& operator+=(int);
    /// add a number to an array
    json& operator+=(double);

    /// add a pair to an object
    json& operator+=(const object_t::value_type&);
    /// add a list of elements to array or list of pairs to object
    json& operator+=(list_init_t);

    /// add an object/array to an array
    void push_back(const json&);
    /// add an object/array to an array (move)
    void push_back(json&&);
    /// add a string to an array
    void push_back(const std::string&);
    /// add a null object to an array
    void push_back(const std::nullptr_t);
    /// add a string to an array
    void push_back(const char*);
    /// add a Boolean to an array
    void push_back(bool);
    /// add a number to an array
    void push_back(int);
    /// add a number to an array
    void push_back(double);

    /// add a pair to an object
    void push_back(const object_t::value_type&);
    /// add a list of elements to array or list of pairs to object
    void push_back(list_init_t);

    /// operator to set an element in an array
    json& operator[](const int);
    /// operator to get an element in an array
    const json& operator[](const int) const;
    /// operator to get an element in an array
    json& at(const int);
    /// operator to get an element in an array
    const json& at(const int) const;

    /// operator to set an element in an object
    json& operator[](const std::string&);
    /// operator to set an element in an object
    json& operator[](const char*);
    /// operator to get an element in an object
    const json& operator[](const std::string&) const;
    /// operator to set an element in an object
    json& at(const std::string&);
    /// operator to set an element in an object
    json& at(const char*);
    /// operator to get an element in an object
    const json& at(const std::string&) const;
    /// operator to get an element in an object
    const json& at(const char*) const;

    /// return the number of stored values
    std::size_t size() const noexcept;
    /// checks whether object is empty
    bool empty() const noexcept;
    /// removes all elements from compounds and resets values to default
    void clear() noexcept;

    /// swaps content with other object
    void swap(json&) noexcept;

    /// return the type of the object
    value_type type() const noexcept;

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

  private:
    /// the type of this object
    value_type type_ = value_type::null;

    /// the payload
    value value_ {};

  public:
    /// an iterator
    class iterator : public std::iterator<std::forward_iterator_tag, json>
    {
        friend class json;
        friend class json::const_iterator;
      public:
        iterator() = default;
        iterator(json*);
        iterator(const iterator&);
        ~iterator();

        iterator& operator=(iterator);
        bool operator==(const iterator&) const;
        bool operator!=(const iterator&) const;
        iterator& operator++();
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
    };

    /// a const iterator
    class const_iterator : public std::iterator<std::forward_iterator_tag, const json>
    {
        friend class json;

      public:
        const_iterator() = default;
        const_iterator(const json*);
        const_iterator(const const_iterator&);
        const_iterator(const json::iterator&);
        ~const_iterator();

        const_iterator& operator=(const_iterator);
        bool operator==(const const_iterator&) const;
        bool operator!=(const const_iterator&) const;
        const_iterator& operator++();
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

// specialization of std::swap
namespace std
{
template <>
/// swaps the values of two JSON objects
inline void swap(nlohmann::json& j1,
                 nlohmann::json& j2) noexcept(is_nothrow_move_constructible<nlohmann::json>::value and
                         is_nothrow_move_assignable<nlohmann::json>::value)
{
    j1.swap(j2);
}
}
