#pragma once

#include <initializer_list>  // std::initializer_list
#include <iostream>          // std::istream, std::ostream
#include <map>               // std::map
#include <mutex>             // std::mutex
#include <string>            // std::string
#include <vector>            // std::vector

/*!
The size of a JSON object is 16 bytes: 8 bytes for the value union whose
largest item is a pointer type and another 8 byte for an element of the
type union. The latter only needs 1 byte - the remaining 7 bytes are wasted
due to alignment.

@see http://stackoverflow.com/questions/7758580/writing-your-own-stl-container/7759622#7759622

@bug Numbers are currently handled too generously. There are several formats
     that are forbidden by the standard, but are accepted by the parser.

@todo Implement JSON::swap()
@todo Implement JSON::insert(), JSON::emplace(), JSON::emplace_back, JSON::erase
@todo Implement JSON::reverse_iterator, JSON::const_reverse_iterator,
      JSON::rbegin(), JSON::rend(), JSON::crbegin(), JSON::crend()?
*/
class JSON
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
    using object_t = std::map<std::string, JSON>;
    /// a type for an array
    using array_t = std::vector<JSON>;
    /// a type for a string
    using string_t = std::string;
    /// a type for a Boolean
    using boolean_t = bool;
    /// a type for an integer number
    using number_t = int;
    /// a type for a floating point number
    using number_float_t = double;
    /// a type for list initialization
    using list_init_t = std::initializer_list<JSON>;

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
    JSON(const value_type) noexcept;
    /// create a null object
    JSON() = default;
    /// create a null object
    JSON(std::nullptr_t) noexcept;
    /// create a string object from a C++ string
    JSON(const std::string&) noexcept;
    /// create a string object from a C++ string (move)
    JSON(std::string&&) noexcept;
    /// create a string object from a C string
    JSON(const char*) noexcept;
    /// create a Boolean object
    JSON(const bool) noexcept;
    /// create a number object
    JSON(const int) noexcept;
    /// create a number object
    JSON(const double) noexcept;
    /// create an array
    JSON(const array_t&) noexcept;
    /// create an array (move)
    JSON(array_t&&) noexcept;
    /// create an object
    JSON(const object_t&) noexcept;
    /// create an object (move)
    JSON(object_t&&) noexcept;
    /// create from an initializer list (to an array or object)
    JSON(list_init_t) noexcept;

    /// copy constructor
    JSON(const JSON&) noexcept;
    /// move constructor
    JSON(JSON&&) noexcept;

    /// copy assignment
    JSON& operator=(JSON) noexcept;

    /// destructor
    ~JSON() noexcept;

    /// create from string representation
    static JSON parse(const std::string&);
    /// create from string representation
    static JSON parse(const char*);

  private:
    /// return the type as string
    const std::string _typename() const noexcept;

  public:
    /// explicit value conversion
    template<typename T>
    T get() const;

    /// implicit conversion to string representation
    operator const std::string() const;
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

    /// write to stream
    friend std::ostream& operator<<(std::ostream& o, const JSON& j)
    {
        o << j.toString();
        return o;
    }
    /// write to stream
    friend std::ostream& operator>>(const JSON& j, std::ostream& o)
    {
        o << j.toString();
        return o;
    }

    /// read from stream
    friend std::istream& operator>>(std::istream& i, JSON& j)
    {
        Parser(i).parse(j);
        return i;
    }
    /// read from stream
    friend std::istream& operator<<(JSON& j, std::istream& i)
    {
        Parser(i).parse(j);
        return i;
    }

    /// explicit conversion to string representation (C++ style)
    const std::string toString() const noexcept;

    /// add an object/array to an array
    JSON& operator+=(const JSON&);
    /// add a string to an array
    JSON& operator+=(const std::string&);
    /// add a null object to an array
    JSON& operator+=(const std::nullptr_t);
    /// add a string to an array
    JSON& operator+=(const char*);
    /// add a Boolean to an array
    JSON& operator+=(bool);
    /// add a number to an array
    JSON& operator+=(int);
    /// add a number to an array
    JSON& operator+=(double);

    /// add a pair to an object
    JSON& operator+=(const object_t::value_type&);
    /// add a list of elements to array or list of pairs to object
    JSON& operator+=(list_init_t);

    /// add an object/array to an array
    void push_back(const JSON&);
    /// add an object/array to an array (move)
    void push_back(JSON&&);
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
    JSON& operator[](const int);
    /// operator to get an element in an array
    const JSON& operator[](const int) const;
    /// operator to get an element in an array
    JSON& at(const int);
    /// operator to get an element in an array
    const JSON& at(const int) const;

    /// operator to set an element in an object
    JSON& operator[](const std::string&);
    /// operator to set an element in an object
    JSON& operator[](const char*);
    /// operator to get an element in an object
    const JSON& operator[](const std::string&) const;
    /// operator to set an element in an object
    JSON& at(const std::string&);
    /// operator to set an element in an object
    JSON& at(const char*);
    /// operator to get an element in an object
    const JSON& at(const std::string&) const;
    /// operator to get an element in an object
    const JSON& at(const char*) const;

    /// return the number of stored values
    size_t size() const noexcept;
    /// checks whether object is empty
    bool empty() const noexcept;
    /// removes all elements from compounds and resets values to default
    void clear() noexcept;

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
    bool operator==(const JSON&) const noexcept;
    /// lexicographically compares the values
    bool operator!=(const JSON&) const noexcept;

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
    value_type _type = value_type::null;

    /// the payload
    value _value {};

  private:
    /// mutex to guard payload
    static std::mutex _token;

  public:
    /// an iterator
    class iterator
    {
        friend class JSON;
        friend class JSON::const_iterator;
      public:
        iterator() = default;
        iterator(JSON*);
        iterator(const iterator&);
        ~iterator();

        iterator& operator=(iterator);
        bool operator==(const iterator&) const;
        bool operator!=(const iterator&) const;
        iterator& operator++();
        JSON& operator*() const;
        JSON* operator->() const;

        /// getter for the key (in case of objects)
        std::string key() const;
        /// getter for the value
        JSON& value() const;

      private:
        /// a JSON value
        JSON* _object = nullptr;
        /// an iterator for JSON arrays
        array_t::iterator* _vi = nullptr;
        /// an iterator for JSON objects
        object_t::iterator* _oi = nullptr;
    };

    /// a const iterator
    class const_iterator
    {
        friend class JSON;

      public:
        const_iterator() = default;
        const_iterator(const JSON*);
        const_iterator(const const_iterator&);
        const_iterator(const iterator&);
        ~const_iterator();

        const_iterator& operator=(const_iterator);
        bool operator==(const const_iterator&) const;
        bool operator!=(const const_iterator&) const;
        const_iterator& operator++();
        const JSON& operator*() const;
        const JSON* operator->() const;

        /// getter for the key (in case of objects)
        std::string key() const;
        /// getter for the value
        const JSON& value() const;

      private:
        /// a JSON value
        const JSON* _object = nullptr;
        /// an iterator for JSON arrays
        array_t::const_iterator* _vi = nullptr;
        /// an iterator for JSON objects
        object_t::const_iterator* _oi = nullptr;
    };

  private:
    /// a helper class to parse a JSON object
    class Parser
    {
      public:
        /// a parser reading from a C string
        Parser(const char*);
        /// a parser reading from a C++ string
        Parser(const std::string&);
        /// a parser reading from an input stream
        Parser(std::istream&);
        /// destructor of the parser
        ~Parser();

        // no copy constructor
        Parser(const Parser&) = delete;
        // no copy assignment
        Parser& operator=(Parser) = delete;

        /// parse into a given JSON object
        void parse(JSON&);

      private:
        /// read the next character, stripping whitespace
        bool next();
        /// raise an exception with an error message
        void error(const std::string&) __attribute__((noreturn));
        /// parse a quoted string
        std::string parseString();
        /// parse a Boolean "true"
        void parseTrue();
        /// parse a Boolean "false"
        void parseFalse();
        /// parse a null object
        void parseNull();
        /// a helper function to expect a certain character
        void expect(const char);

      private:
        /// the length of the input buffer
        size_t _length {};
        /// a buffer of the input
        char* _buffer { nullptr };
        /// the current character
        char _current {};
        /// the position inside the input buffer
        size_t _pos = 0;
    };
};

/// user-defined literal operator to create JSON objects from strings
JSON operator "" _json(const char*, size_t);
