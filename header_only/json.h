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

@todo Implement json::swap()
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
        inline void error(const std::string&) const __attribute__((noreturn));
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
/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2014 Niels Lohmann.

@author Niels Lohmann <http://nlohmann.me>

@see https://github.com/nlohmann/json
*/



#include <cctype>     // std::isdigit, std::isspace
#include <cstddef>    // std::size_t
#include <stdexcept>  // std::runtime_error
#include <utility>    // std::swap, std::move

namespace nlohmann
{

///////////////////////////////////
// CONSTRUCTORS OF UNION "value" //
///////////////////////////////////

json::value::value(array_t* _array): array(_array) {}
json::value::value(object_t* object_): object(object_) {}
json::value::value(string_t* _string): string(_string) {}
json::value::value(boolean_t _boolean) : boolean(_boolean) {}
json::value::value(number_t _number) : number(_number) {}
json::value::value(number_float_t _number_float) : number_float(_number_float) {}


/////////////////////////////////
// CONSTRUCTORS AND DESTRUCTOR //
/////////////////////////////////

/*!
Construct an empty JSON given the type.

@param t  the type from the @ref json::type enumeration.

@post Memory for array, object, and string are allocated.
*/
json::json(const value_type t)
    : type_(t)
{
    switch (type_)
    {
        case (value_type::array):
        {
            value_.array = new array_t();
            break;
        }
        case (value_type::object):
        {
            value_.object = new object_t();
            break;
        }
        case (value_type::string):
        {
            value_.string = new string_t();
            break;
        }
        case (value_type::boolean):
        {
            value_.boolean = boolean_t();
            break;
        }
        case (value_type::number):
        {
            value_.number = number_t();
            break;
        }
        case (value_type::number_float):
        {
            value_.number_float = number_float_t();
            break;
        }
        default:
        {
            break;
        }
    }
}

/*!
Construct a null JSON object.
*/
json::json(std::nullptr_t) noexcept : json()
{}

/*!
Construct a string JSON object.

@param s  a string to initialize the JSON object with
*/
json::json(const std::string& s)
    : type_(value_type::string), value_(new string_t(s))
{}

json::json(std::string&& s)
    : type_(value_type::string), value_(new string_t(std::move(s)))
{}

json::json(const char* s)
    : type_(value_type::string), value_(new string_t(s))
{}

json::json(const bool b) noexcept
    : type_(value_type::boolean), value_(b)
{}

json::json(const int i) noexcept
    : type_(value_type::number), value_(i)
{}

json::json(const double f) noexcept
    : type_(value_type::number_float), value_(f)
{}

json::json(const array_t& a)
    : type_(value_type::array), value_(new array_t(a))
{}

json::json(array_t&& a)
    : type_(value_type::array), value_(new array_t(std::move(a)))
{}

json::json(const object_t& o)
    : type_(value_type::object), value_(new object_t(o))
{}

json::json(object_t&& o)
    : type_(value_type::object), value_(new object_t(std::move(o)))
{}

/*!
This function is a bit tricky as it uses an initializer list of JSON objects
for both arrays and objects. This is not supported by C++, so we use the
following trick. Both initializer lists for objects and arrays will transform
to a list of JSON objects. The only difference is that in case of an object,
the list will contain JSON array objects with two elements - one for the key
and one for the value. As a result, it is sufficient to check if each element
of the initializer list is an array (1) with two elements (2) whose first
element is of type string (3). If this is the case, we treat the whole
initializer list as list of pairs to construct an object. If not, we pass it
as is to create an array.

@bug With the described approach, we would fail to recognize an array whose
     first element is again an arrays as array.
*/
json::json(list_init_t a)
{
    // check if each element is an array with two elements whose first element
    // is a string
    for (const auto& element : a)
    {
        if (element.type_ != value_type::array or
                element.size() != 2 or
                element[0].type_ != value_type::string)
        {

            // the initializer list describes an array
            type_ = value_type::array;
            value_ = new array_t(a);
            return;
        }
    }

    // the initializer list is a list of pairs
    type_ = value_type::object;
    value_ = new object_t();
    for (const json& element : a)
    {
        const std::string k = element[0];
        value_.object->emplace(std::make_pair(std::move(k),
                                              std::move(element[1])));
    }
}

/*!
A copy constructor for the JSON class.

@param o  the JSON object to copy
*/
json::json(const json& o)
    : type_(o.type_)
{
    switch (type_)
    {
        case (value_type::array):
        {
            value_.array = new array_t(*o.value_.array);
            break;
        }
        case (value_type::object):
        {
            value_.object = new object_t(*o.value_.object);
            break;
        }
        case (value_type::string):
        {
            value_.string = new string_t(*o.value_.string);
            break;
        }
        case (value_type::boolean):
        {
            value_.boolean = o.value_.boolean;
            break;
        }
        case (value_type::number):
        {
            value_.number = o.value_.number;
            break;
        }
        case (value_type::number_float):
        {
            value_.number_float = o.value_.number_float;
            break;
        }
        default:
        {
            break;
        }
    }
}

/*!
A move constructor for the JSON class.

@param o  the JSON object to move

@post The JSON object \p o is invalidated.
*/
json::json(json&& o) noexcept
    : type_(std::move(o.type_)), value_(std::move(o.value_))
{
    // invalidate payload
    o.type_ = value_type::null;
    o.value_ = {};
}

/*!
A copy assignment operator for the JSON class, following the copy-and-swap
idiom.

@param o  A JSON object to assign to this object.
*/
json& json::operator=(json o) noexcept
{
    std::swap(type_, o.type_);
    std::swap(value_, o.value_);
    return *this;
}

json::~json() noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            delete value_.array;
            break;
        }
        case (value_type::object):
        {
            delete value_.object;
            break;
        }
        case (value_type::string):
        {
            delete value_.string;
            break;
        }
        default:
        {
            // nothing to do for non-pointer types
            break;
        }
    }
}

/*!
@param s  a string representation of a JSON object
@return a JSON object
*/
json json::parse(const std::string& s)
{
    return parser(s).parse();
}

/*!
@param s  a string representation of a JSON object
@return a JSON object
*/
json json::parse(const char* s)
{
    return parser(s).parse();
}


std::string json::type_name() const noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            return "array";
        }
        case (value_type::object):
        {
            return "object";
        }
        case (value_type::null):
        {
            return "null";
        }
        case (value_type::string):
        {
            return "string";
        }
        case (value_type::boolean):
        {
            return "boolean";
        }
        default:
        {
            return "number";
        }
    }
}


///////////////////////////////
// OPERATORS AND CONVERSIONS //
///////////////////////////////

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not string
*/
template<>
std::string json::get() const
{
    switch (type_)
    {
        case (value_type::string):
            return *value_.string;
        default:
            throw std::logic_error("cannot cast " + type_name() + " to JSON string");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not number (int or float)
*/
template<>
int json::get() const
{
    switch (type_)
    {
        case (value_type::number):
            return value_.number;
        case (value_type::number_float):
            return static_cast<number_t>(value_.number_float);
        default:
            throw std::logic_error("cannot cast " + type_name() + " to JSON number");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not number (int or float)
*/
template<>
double json::get() const
{
    switch (type_)
    {
        case (value_type::number):
            return static_cast<number_float_t>(value_.number);
        case (value_type::number_float):
            return value_.number_float;
        default:
            throw std::logic_error("cannot cast " + type_name() + " to JSON number");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not boolean
*/
template<>
bool json::get() const
{
    switch (type_)
    {
        case (value_type::boolean):
            return value_.boolean;
        default:
            throw std::logic_error("cannot cast " + type_name() + " to JSON Boolean");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is an object
*/
template<>
json::array_t json::get() const
{
    if (type_ == value_type::array)
    {
        return *value_.array;
    }
    if (type_ == value_type::object)
    {
        throw std::logic_error("cannot cast " + type_name() + " to JSON array");
    }

    array_t result;
    result.push_back(*this);
    return result;
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not object
*/
template<>
json::object_t json::get() const
{
    if (type_ == value_type::object)
    {
        return *value_.object;
    }
    else
    {
        throw std::logic_error("cannot cast " + type_name() + " to JSON object");
    }
}

json::operator std::string() const
{
    return get<std::string>();
}

json::operator int() const
{
    return get<int>();
}

json::operator double() const
{
    return get<double>();
}

json::operator bool() const
{
    return get<bool>();
}

json::operator array_t() const
{
    return get<array_t>();
}

json::operator object_t() const
{
    return get<object_t>();
}

/*!
Internal implementation of the serialization function.

\param prettyPrint    whether the output shall be pretty-printed
\param indentStep     the indent level
\param currentIndent  the current indent level (only used internally)
*/
std::string json::dump(const bool prettyPrint, const unsigned int indentStep,
                       unsigned int currentIndent) const noexcept
{
    // helper function to return whitespace as indentation
    const auto indent = [prettyPrint, &currentIndent]()
    {
        return prettyPrint ? std::string(currentIndent, ' ') : std::string();
    };

    switch (type_)
    {
        case (value_type::string):
        {
            return std::string("\"") + escapeString(*value_.string) + "\"";
        }

        case (value_type::boolean):
        {
            return value_.boolean ? "true" : "false";
        }

        case (value_type::number):
        {
            return std::to_string(value_.number);
        }

        case (value_type::number_float):
        {
            return std::to_string(value_.number_float);
        }

        case (value_type::array):
        {
            if (value_.array->empty())
            {
                return "[]";
            }

            std::string result = "[";

            // increase indentation
            if (prettyPrint)
            {
                currentIndent += indentStep;
                result += "\n";
            }

            for (array_t::const_iterator i = value_.array->begin(); i != value_.array->end(); ++i)
            {
                if (i != value_.array->begin())
                {
                    result += prettyPrint ? ",\n" : ", ";
                }
                result += indent() + i->dump(prettyPrint, indentStep, currentIndent);
            }

            // decrease indentation
            if (prettyPrint)
            {
                currentIndent -= indentStep;
                result += "\n";
            }

            return result + indent() + "]";
        }

        case (value_type::object):
        {
            if (value_.object->empty())
            {
                return "{}";
            }

            std::string result = "{";

            // increase indentation
            if (prettyPrint)
            {
                currentIndent += indentStep;
                result += "\n";
            }

            for (object_t::const_iterator i = value_.object->begin(); i != value_.object->end(); ++i)
            {
                if (i != value_.object->begin())
                {
                    result += prettyPrint ? ",\n" : ", ";
                }
                result += indent() + "\"" + i->first + "\": " + i->second.dump(prettyPrint, indentStep,
                          currentIndent);
            }

            // decrease indentation
            if (prettyPrint)
            {
                currentIndent -= indentStep;
                result += "\n";
            }

            return result + indent() + "}";
        }

        // actually only value_type::null - but making the compiler happy
        default:
        {
            return "null";
        }
    }
}

/*!
Internal function to replace all occurrences of a character in a given string
with another string.

\param str            the string that contains tokens to replace
\param c     the character that needs to be replaced
\param replacement  the string that is the replacement for the character
*/
void json::replaceChar(std::string& str, char c, const std::string& replacement)
const
{
    size_t start_pos = 0;
    while ((start_pos = str.find(c, start_pos)) != std::string::npos)
    {
        str.replace(start_pos, 1, replacement);
        start_pos += replacement.length();
    }
}

/*!
Escapes all special characters in the given string according to ECMA-404.
Necessary as some characters such as quotes, backslashes and so on
can't be used as is when dumping a string value.

\param str        the string that should be escaped.

\return a copy of the given string with all special characters escaped.
*/
std::string json::escapeString(const std::string& str) const
{
    std::string result(str);
    // we first need to escape the backslashes as all other methods will insert
    // legitimate backslashes into the result.
    replaceChar(result, '\\', "\\\\");
    // replace all other characters
    replaceChar(result, '"', "\\\"");
    replaceChar(result, '\n', "\\n");
    replaceChar(result, '\r', "\\r");
    replaceChar(result, '\f', "\\f");
    replaceChar(result, '\b', "\\b");
    replaceChar(result, '\t', "\\t");
    return result;
}

/*!
Serialization function for JSON objects. The function tries to mimick Python's
\p json.dumps() function, and currently supports its \p indent parameter.

\param indent  if indent is nonnegative, then array elements and object members
               will be pretty-printed with that indent level. An indent level
               of 0 will only insert newlines. -1 (the default) selects the
               most compact representation

\see https://docs.python.org/2/library/json.html#json.dump
*/
std::string json::dump(int indent) const noexcept
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


///////////////////////////////////////////
// ADDING ELEMENTS TO OBJECTS AND ARRAYS //
///////////////////////////////////////////

json& json::operator+=(const json& o)
{
    push_back(o);
    return *this;
}

json& json::operator+=(const std::string& s)
{
    push_back(json(s));
    return *this;
}

json& json::operator+=(const char* s)
{
    push_back(json(s));
    return *this;
}

json& json::operator+=(std::nullptr_t)
{
    push_back(json());
    return *this;
}

json& json::operator+=(bool b)
{
    push_back(json(b));
    return *this;
}

/*!
Adds a number (int) to the current object. This is done by wrapping the number
into a JSON and call push_back for this.

@param i  A number (int) to add to the array.
*/
json& json::operator+=(int i)
{
    push_back(json(i));
    return *this;
}

/*!
Adds a number (float) to the current object. This is done by wrapping the
number into a JSON and call push_back for this.

@param f  A number (float) to add to the array.
*/
json& json::operator+=(double f)
{
    push_back(json(f));
    return *this;
}

/*!
@todo comment me
*/
json& json::operator+=(const object_t::value_type& p)
{
    return operator[](p.first) = p.second;
}

/*!
@todo comment me
*/
json& json::operator+=(list_init_t a)
{
    push_back(a);
    return *this;
}

/*!
This function implements the actual "adding to array" function and is called
by all other push_back or operator+= functions. If the function is called for
an array, the passed element is added to the array.

@param o  The element to add to the array.

@pre  The JSON object is an array or null.
@post The JSON object is an array whose last element is the passed element o.
@exception std::runtime_error  The function was called for a JSON type that
             does not support addition to an array (e.g., int or string).

@note Null objects are silently transformed into an array before the addition.
*/
void json::push_back(const json& o)
{
    // push_back only works for null objects or arrays
    if (not(type_ == value_type::null or type_ == value_type::array))
    {
        throw std::runtime_error("cannot add element to " + type_name());
    }

    // transform null object into an array
    if (type_ == value_type::null)
    {
        type_ = value_type::array;
        value_.array = new array_t;
    }

    // add element to array
    value_.array->push_back(o);
}

/*!
This function implements the actual "adding to array" function and is called
by all other push_back or operator+= functions. If the function is called for
an array, the passed element is added to the array using move semantics.

@param o  The element to add to the array.

@pre  The JSON object is an array or null.
@post The JSON object is an array whose last element is the passed element o.
@post The element o is destroyed.
@exception std::runtime_error  The function was called for a JSON type that
             does not support addition to an array (e.g., int or string).

@note Null objects are silently transformed into an array before the addition.
@note This function applies move semantics for the given element.
*/
void json::push_back(json&& o)
{
    // push_back only works for null objects or arrays
    if (not(type_ == value_type::null or type_ == value_type::array))
    {
        throw std::runtime_error("cannot add element to " + type_name());
    }

    // transform null object into an array
    if (type_ == value_type::null)
    {
        type_ = value_type::array;
        value_.array = new array_t;
    }

    // add element to array (move semantics)
    value_.array->emplace_back(std::move(o));
    // invalidate object
    o.type_ = value_type::null;
}

void json::push_back(const std::string& s)
{
    push_back(json(s));
}

void json::push_back(const char* s)
{
    push_back(json(s));
}

void json::push_back(std::nullptr_t)
{
    push_back(json());
}

void json::push_back(bool b)
{
    push_back(json(b));
}

/*!
Adds a number (int) to the current object. This is done by wrapping the number
into a JSON and call push_back for this.

@param i  A number (int) to add to the array.
*/
void json::push_back(int i)
{
    push_back(json(i));
}

/*!
Adds a number (float) to the current object. This is done by wrapping the
number into a JSON and call push_back for this.

@param f  A number (float) to add to the array.
*/
void json::push_back(double f)
{
    push_back(json(f));
}

/*!
@todo comment me
*/
void json::push_back(const object_t::value_type& p)
{
    operator[](p.first) = p.second;
}

/*!
@todo comment me
*/
void json::push_back(list_init_t a)
{
    bool is_array = false;

    // check if each element is an array with two elements whose first element
    // is a string
    for (const auto& element : a)
    {
        if (element.type_ != value_type::array or
                element.size() != 2 or
                element[0].type_ != value_type::string)
        {
            // the initializer list describes an array
            is_array = true;
            break;
        }
    }

    if (is_array)
    {
        for (const json& element : a)
        {
            push_back(element);
        }
    }
    else
    {
        for (const json& element : a)
        {
            const object_t::value_type tmp {element[0].get<std::string>(), element[1]};
            push_back(tmp);
        }
    }
}

/*!
This operator realizes read/write access to array elements given an integer
index.  Bounds will not be checked.

@note The "index" variable should be of type size_t as it is compared against
      size() and used in the at() function. However, the compiler will have
      problems in case integer literals are used. In this case, an implicit
      conversion to both size_t and JSON is possible. Therefore, we use int as
      type and convert it to size_t where necessary.

@param index  the index of the element to return from the array
@return reference to element for the given index

@pre Object is an array.
@exception std::domain_error if object is not an array
*/
json& json::operator[](const int index)
{
    // this [] operator only works for arrays
    if (type_ != value_type::array)
    {
        throw std::domain_error("cannot add entry with index " +
                                std::to_string(index) + " to " + type_name());
    }

    // return reference to element from array at given index
    return (*value_.array)[static_cast<std::size_t>(index)];
}

/*!
This operator realizes read-only access to array elements given an integer
index.  Bounds will not be checked.

@note The "index" variable should be of type size_t as it is compared against
      size() and used in the at() function. However, the compiler will have
      problems in case integer literals are used. In this case, an implicit
      conversion to both size_t and JSON is possible. Therefore, we use int as
      type and convert it to size_t where necessary.

@param index  the index of the element to return from the array
@return read-only reference to element for the given index

@pre Object is an array.
@exception std::domain_error if object is not an array
*/
const json& json::operator[](const int index) const
{
    // this [] operator only works for arrays
    if (type_ != value_type::array)
    {
        throw std::domain_error("cannot get entry with index " +
                                std::to_string(index) + " from " + type_name());
    }

    // return element from array at given index
    return (*value_.array)[static_cast<std::size_t>(index)];
}

/*!
This function realizes read/write access to array elements given an integer
index. Bounds will be checked.

@note The "index" variable should be of type size_t as it is compared against
      size() and used in the at() function. However, the compiler will have
      problems in case integer literals are used. In this case, an implicit
      conversion to both size_t and JSON is possible. Therefore, we use int as
      type and convert it to size_t where necessary.

@param index  the index of the element to return from the array
@return reference to element for the given index

@pre Object is an array.
@exception std::domain_error if object is not an array
@exception std::out_of_range if index is out of range (via std::vector::at)
*/
json& json::at(const int index)
{
    // this function only works for arrays
    if (type_ != value_type::array)
    {
        throw std::domain_error("cannot add entry with index " +
                                std::to_string(index) + " to " + type_name());
    }

    // return reference to element from array at given index
    return value_.array->at(static_cast<std::size_t>(index));
}

/*!
This operator realizes read-only access to array elements given an integer
index. Bounds will be checked.

@note The "index" variable should be of type size_t as it is compared against
      size() and used in the at() function. However, the compiler will have
      problems in case integer literals are used. In this case, an implicit
      conversion to both size_t and JSON is possible. Therefore, we use int as
      type and convert it to size_t where necessary.

@param index  the index of the element to return from the array
@return read-only reference to element for the given index

@pre Object is an array.
@exception std::domain_error if object is not an array
@exception std::out_of_range if index is out of range (via std::vector::at)
*/
const json& json::at(const int index) const
{
    // this function only works for arrays
    if (type_ != value_type::array)
    {
        throw std::domain_error("cannot get entry with index " +
                                std::to_string(index) + " from " + type_name());
    }

    // return element from array at given index
    return value_.array->at(static_cast<std::size_t>(index));
}

/*!
@copydoc json::operator[](const char* key)
*/
json& json::operator[](const std::string& key)
{
    return operator[](key.c_str());
}

/*!
This operator realizes read/write access to object elements given a string
key.

@param key  the key index of the element to return from the object
@return reference to a JSON object for the given key (null if key does not
        exist)

@pre  Object is an object or a null object.
@post null objects are silently converted to objects.

@exception std::domain_error if object is not an object (or null)
*/
json& json::operator[](const char* key)
{
    // implicitly convert null to object
    if (type_ == value_type::null)
    {
        type_ = value_type::object;
        value_.object = new object_t;
    }

    // this [] operator only works for objects
    if (type_ != value_type::object)
    {
        throw std::domain_error("cannot add entry with key " +
                                std::string(key) + " to " + type_name());
    }

    // if the key does not exist, create it
    if (value_.object->find(key) == value_.object->end())
    {
        (*value_.object)[key] = json();
    }

    // return reference to element from array at given index
    return (*value_.object)[key];
}

/*!
This operator realizes read-only access to object elements given a string
key.

@param key  the key index of the element to return from the object
@return read-only reference to element for the given key

@pre Object is an object.
@exception std::domain_error if object is not an object
@exception std::out_of_range if key is not found in object
*/
const json& json::operator[](const std::string& key) const
{
    // this [] operator only works for objects
    if (type_ != value_type::object)
    {
        throw std::domain_error("cannot get entry with key " +
                                std::string(key) + " from " + type_name());
    }

    // search for the key
    const auto it = value_.object->find(key);

    // make sure the key exists in the object
    if (it == value_.object->end())
    {
        throw std::out_of_range("key " + key + " not found");
    }

    // return element from array at given key
    return it->second;
}

/*!
@copydoc json::at(const char* key)
*/
json& json::at(const std::string& key)
{
    return at(key.c_str());
}

/*!
This function realizes read/write access to object elements given a string
key.

@param key  the key index of the element to return from the object
@return reference to a JSON object for the given key (exception if key does not
        exist)

@pre  Object is an object.

@exception std::domain_error if object is not an object
@exception std::out_of_range if key was not found (via std::map::at)
*/
json& json::at(const char* key)
{
    // this function operator only works for objects
    if (type_ != value_type::object)
    {
        throw std::domain_error("cannot add entry with key " +
                                std::string(key) + " to " + type_name());
    }

    // return reference to element from array at given index
    return value_.object->at(key);
}

/*!
@copydoc json::at(const char *key) const
*/
const json& json::at(const std::string& key) const
{
    return at(key.c_str());
}

/*!
This operator realizes read-only access to object elements given a string
key.

@param key  the key index of the element to return from the object
@return read-only reference to element for the given key

@pre Object is an object.
@exception std::domain_error if object is not an object
@exception std::out_of_range if key is not found (via std::map::at)
*/
const json& json::at(const char* key) const
{
    // this [] operator only works for objects
    if (type_ != value_type::object)
    {
        throw std::domain_error("cannot get entry with key " +
                                std::string(key) + " from " + type_name());
    }

    // return element from array at given key
    return value_.object->at(key);
}


/*!
Returns the size of the JSON object.

@return the size of the JSON object; the size is the number of elements in
        compounds (array and object), 1 for value types (true, false, number,
        string), and 0 for null.

@invariant The size is reported as 0 if and only if empty() would return true.
*/
std::size_t json::size() const noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            return value_.array->size();
        }
        case (value_type::object):
        {
            return value_.object->size();
        }
        case (value_type::null):
        {
            return 0;
        }
        default:
        {
            return 1;
        }
    }
}

/*!
Returns whether a JSON object is empty.

@return true for null objects and empty compounds (array and object); false
        for value types (true, false, number, string) and filled compounds
        (array and object).

@invariant Empty would report true if and only if size() would return 0.
*/
bool json::empty() const noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            return value_.array->empty();
        }
        case (value_type::object):
        {
            return value_.object->empty();
        }
        case (value_type::null):
        {
            return true;
        }
        default:
        {
            return false;
        }
    }
}

/*!
Removes all elements from compounds and resets values to default.

@invariant Clear will set any value type to its default value which is empty
           for compounds, false for booleans, 0 for integer numbers, and 0.0
           for floating numbers.
*/
void json::clear() noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            value_.array->clear();
            break;
        }
        case (value_type::object):
        {
            value_.object->clear();
            break;
        }
        case (value_type::string):
        {
            value_.string->clear();
            break;
        }
        case (value_type::boolean):
        {
            value_.boolean = {};
            break;
        }
        case (value_type::number):
        {
            value_.number = {};
            break;
        }
        case (value_type::number_float):
        {
            value_.number_float = {};
            break;
        }
        default:
        {
            break;
        }
    }
}

json::value_type json::type() const noexcept
{
    return type_;
}

json::iterator json::find(const std::string& key)
{
    return find(key.c_str());
}

json::const_iterator json::find(const std::string& key) const
{
    return find(key.c_str());
}

json::iterator json::find(const char* key)
{
    if (type_ != value_type::object)
    {
        return end();
    }
    else
    {
        const object_t::iterator i = value_.object->find(key);
        if (i != value_.object->end())
        {
            json::iterator result(this);
            delete result.oi_;
            result.oi_ = nullptr;
            result.oi_ = new object_t::iterator(i);
            return result;
        }
        else
        {
            return end();
        }
    }
}

json::const_iterator json::find(const char* key) const
{
    if (type_ != value_type::object)
    {
        return end();
    }
    else
    {
        const object_t::const_iterator i = value_.object->find(key);
        if (i != value_.object->end())
        {
            json::const_iterator result(this);
            delete result.oi_;
            result.oi_ = nullptr;
            result.oi_ = new object_t::const_iterator(i);
            return result;
        }
        else
        {
            return end();
        }
    }
}

bool json::operator==(const json& o) const noexcept
{
    switch (type_)
    {
        case (value_type::array):
        {
            if (o.type_ == value_type::array)
            {
                return *value_.array == *o.value_.array;
            }
            break;
        }
        case (value_type::object):
        {
            if (o.type_ == value_type::object)
            {
                return *value_.object == *o.value_.object;
            }
            break;
        }
        case (value_type::null):
        {
            if (o.type_ == value_type::null)
            {
                return true;
            }
            break;
        }
        case (value_type::string):
        {
            if (o.type_ == value_type::string)
            {
                return *value_.string == *o.value_.string;
            }
            break;
        }
        case (value_type::boolean):
        {
            if (o.type_ == value_type::boolean)
            {
                return value_.boolean == o.value_.boolean;
            }
            break;
        }
        case (value_type::number):
        {
            if (o.type_ == value_type::number)
            {
                return value_.number == o.value_.number;
            }
            if (o.type_ == value_type::number_float)
            {
                return value_.number == static_cast<number_t>(o.value_.number_float);
            }
            break;
        }
        case (value_type::number_float):
        {
            if (o.type_ == value_type::number)
            {
                return value_.number_float == static_cast<number_float_t>(o.value_.number);
            }
            if (o.type_ == value_type::number_float)
            {
                return value_.number_float == o.value_.number_float;
            }
            break;
        }
    }

    return false;
}

bool json::operator!=(const json& o) const noexcept
{
    return not operator==(o);
}


json::iterator json::begin() noexcept
{
    return json::iterator(this);
}

json::iterator json::end() noexcept
{
    return json::iterator();
}

json::const_iterator json::begin() const noexcept
{
    return json::const_iterator(this);
}

json::const_iterator json::end() const noexcept
{
    return json::const_iterator();
}

json::const_iterator json::cbegin() const noexcept
{
    return json::const_iterator(this);
}

json::const_iterator json::cend() const noexcept
{
    return json::const_iterator();
}


json::iterator::iterator(json* j) : object_(j)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            vi_ = new array_t::iterator(object_->value_.array->begin());
        }
        if (object_->type_ == json::value_type::object)
        {
            oi_ = new object_t::iterator(object_->value_.object->begin());
        }
    }
}

json::iterator::iterator(const json::iterator& o) : object_(o.object_)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            vi_ = new array_t::iterator(*(o.vi_));
        }
        if (object_->type_ == json::value_type::object)
        {
            oi_ = new object_t::iterator(*(o.oi_));
        }
    }
}

json::iterator::~iterator()
{
    delete vi_;
    delete oi_;
}

json::iterator& json::iterator::operator=(json::iterator o)
{
    std::swap(object_, o.object_);
    std::swap(vi_, o.vi_);
    std::swap(oi_, o.oi_);
    return *this;
}

bool json::iterator::operator==(const json::iterator& o) const
{
    if (object_ != o.object_)
    {
        return false;
    }

    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            return (vi_ == o.vi_);
        }
        if (object_->type_ == json::value_type::object)
        {
            return (oi_ == o.oi_);
        }
    }

    return true;
}

bool json::iterator::operator!=(const json::iterator& o) const
{
    return not operator==(o);
}

json::iterator& json::iterator::operator++()
{
    // iterator cannot be incremented
    if (object_ == nullptr)
    {
        return *this;
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            if (++(*vi_) == object_->value_.array->end())
            {
                object_ = nullptr;
            }
            break;
        }
        case (json::value_type::object):
        {
            if (++(*oi_) == object_->value_.object->end())
            {
                object_ = nullptr;
            }
            break;
        }
        default:
        {
            object_ = nullptr;
        }
    }
    return *this;
}

json& json::iterator::operator*() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return **vi_;
        }
        case (json::value_type::object):
        {
            return (*oi_)->second;
        }
        default:
        {
            return *object_;
        }
    }
}

json* json::iterator::operator->() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return &(**vi_);
        }
        case (json::value_type::object):
        {
            return &((*oi_)->second);
        }
        default:
        {
            return object_;
        }
    }
}

std::string json::iterator::key() const
{
    if (object_ != nullptr and object_->type_ == json::value_type::object)
    {
        return (*oi_)->first;
    }
    else
    {
        throw std::out_of_range("cannot get key");
    }
}

json& json::iterator::value() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return **vi_;
        }
        case (json::value_type::object):
        {
            return (*oi_)->second;
        }
        default:
        {
            return *object_;
        }
    }
}


json::const_iterator::const_iterator(const json* j) : object_(j)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            vi_ = new array_t::const_iterator(object_->value_.array->begin());
        }
        if (object_->type_ == json::value_type::object)
        {
            oi_ = new object_t::const_iterator(object_->value_.object->begin());
        }
    }
}

json::const_iterator::const_iterator(const json::const_iterator& o) : object_(o.object_)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            vi_ = new array_t::const_iterator(*(o.vi_));
        }
        if (object_->type_ == json::value_type::object)
        {
            oi_ = new object_t::const_iterator(*(o.oi_));
        }
    }
}

json::const_iterator::const_iterator(const json::iterator& o) : object_(o.object_)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            vi_ = new array_t::const_iterator(*(o.vi_));
        }
        if (object_->type_ == json::value_type::object)
        {
            oi_ = new object_t::const_iterator(*(o.oi_));
        }
    }
}

json::const_iterator::~const_iterator()
{
    delete vi_;
    delete oi_;
}

json::const_iterator& json::const_iterator::operator=(json::const_iterator o)
{
    std::swap(object_, o.object_);
    std::swap(vi_, o.vi_);
    std::swap(oi_, o.oi_);
    return *this;
}

bool json::const_iterator::operator==(const json::const_iterator& o) const
{
    if (object_ != o.object_)
    {
        return false;
    }

    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_type::array)
        {
            return (vi_ == o.vi_);
        }
        if (object_->type_ == json::value_type::object)
        {
            return (oi_ == o.oi_);
        }
    }

    return true;
}

bool json::const_iterator::operator!=(const json::const_iterator& o) const
{
    return not operator==(o);
}

json::const_iterator& json::const_iterator::operator++()
{
    // iterator cannot be incremented
    if (object_ == nullptr)
    {
        return *this;
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            if (++(*vi_) == object_->value_.array->end())
            {
                object_ = nullptr;
            }
            break;
        }
        case (json::value_type::object):
        {
            if (++(*oi_) == object_->value_.object->end())
            {
                object_ = nullptr;
            }
            break;
        }
        default:
        {
            object_ = nullptr;
        }
    }
    return *this;
}

const json& json::const_iterator::operator*() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return **vi_;
        }
        case (json::value_type::object):
        {
            return (*oi_)->second;
        }
        default:
        {
            return *object_;
        }
    }
}

const json* json::const_iterator::operator->() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return &(**vi_);
        }
        case (json::value_type::object):
        {
            return &((*oi_)->second);
        }
        default:
        {
            return object_;
        }
    }
}

std::string json::const_iterator::key() const
{
    if (object_ != nullptr and object_->type_ == json::value_type::object)
    {
        return (*oi_)->first;
    }
    else
    {
        throw std::out_of_range("cannot get key");
    }
}

const json& json::const_iterator::value() const
{
    // dereferencing end() is an error
    if (object_ == nullptr)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_type::array):
        {
            return **vi_;
        }
        case (json::value_type::object):
        {
            return (*oi_)->second;
        }
        default:
        {
            return *object_;
        }
    }
}


/*!
Initialize the JSON parser given a string \p s.

@note After initialization, the function @ref parse has to be called manually.

@param s  string to parse

@post \p s is copied to the buffer @ref buffer_ and the first character is
      read. Whitespace is skipped.
*/
json::parser::parser(const char* s)
    :  buffer_(s)
{
    // read first character
    next();
}

/*!
@copydoc json::parser::parser(const char* s)
*/
json::parser::parser(const std::string& s)
    : buffer_(s)
{
    // read first character
    next();
}

/*!
Initialize the JSON parser given an input stream \p _is.

@note After initialization, the function @ref parse has to be called manually.

\param _is input stream to parse

@post \p _is is copied to the buffer @ref buffer_ and the firsr character is
      read. Whitespace is skipped.

*/
json::parser::parser(std::istream& _is)
{
    while (_is)
    {
        std::string input_line;
        std::getline(_is, input_line);
        buffer_ += input_line;
    }

    // read first character
    next();
}

json json::parser::parse()
{
    switch (current_)
    {
        case ('{'):
        {
            // explicitly set result to object to cope with {}
            json result(value_type::object);

            next();

            // process nonempty object
            if (current_ != '}')
            {
                do
                {
                    // key
                    auto key = parseString();

                    // colon
                    expect(':');

                    // value
                    result[std::move(key)] = parse();
                    key.clear();
                }
                while (current_ == ',' and next());
            }

            // closing brace
            expect('}');

            return result;
        }

        case ('['):
        {
            // explicitly set result to array to cope with []
            json result(value_type::array);

            next();

            // process nonempty array
            if (current_ != ']')
            {
                do
                {
                    result.push_back(parse());
                }
                while (current_ == ',' and next());
            }

            // closing bracket
            expect(']');

            return result;
        }

        case ('\"'):
        {
            return json(parseString());
        }

        case ('t'):
        {
            parseTrue();
            return json(true);
        }

        case ('f'):
        {
            parseFalse();
            return json(false);
        }

        case ('n'):
        {
            parseNull();
            return json();
        }

        case ('-'):
        case ('0'):
        case ('1'):
        case ('2'):
        case ('3'):
        case ('4'):
        case ('5'):
        case ('6'):
        case ('7'):
        case ('8'):
        case ('9'):
        {
            // remember position of number's first character
            const auto _firstpos_ = pos_ - 1;

            while (next() and (std::isdigit(current_) or current_ == '.'
                               or current_ == 'e' or current_ == 'E'
                               or current_ == '+' or current_ == '-'));

            try
            {
                const auto float_val = std::stod(buffer_.substr(_firstpos_, pos_ - _firstpos_));
                const auto int_val = static_cast<int>(float_val);

                // check if conversion loses precision
                if (float_val == int_val)
                {
                    // we would not lose precision -> int
                    return json(int_val);
                }
                else
                {
                    // we would lose precision -> float
                    return json(float_val);
                }
            }
            catch (...)
            {
                error("error translating " +
                      buffer_.substr(_firstpos_, pos_ - _firstpos_) + " to number");
            }
        }

        default:
        {
            error("unexpected character");
        }
    }
}

/*!
This function reads the next character from the buffer while ignoring all
trailing whitespace. If another character could be read, the function returns
true. If the end of the buffer is reached, false is returned.

@return whether another non-whitespace character could be read

@post current_ holds the next character
*/
bool json::parser::next()
{
    if (pos_ == buffer_.size())
    {
        return false;
    }

    current_ = buffer_[pos_++];

    // skip trailing whitespace
    while (std::isspace(current_))
    {
        if (pos_ == buffer_.size())
        {
            return false;
        }

        current_ = buffer_[pos_++];
    }

    return true;
}

/*!
This function encapsulates the error reporting functions of the parser class.
It throws a \p std::invalid_argument exception with a description where the
error occurred (given as the number of characters read), what went wrong (using
the error message \p msg), and the last read token.

@param msg  an error message
@return <em>This function does not return.</em>

@exception std::invalid_argument whenever the function is called
*/
void json::parser::error(const std::string& msg) const
{
    throw std::invalid_argument("parse error at position " +
                                std::to_string(pos_) + ": " + msg +
                                ", last read: '" + current_ + "'");
}

/*!
Parses a string after opening quotes (\p ") where read.

@return the parsed string

@pre  An opening quote \p " was read in the main parse function @ref parse.
      pos_ is the position after the opening quote.

@post The character after the closing quote \p " is the current character @ref
      current_. Whitespace is skipped.

@todo Unicode escapes such as \uxxxx are missing - see
      https://github.com/nlohmann/json/issues/12
*/
std::string json::parser::parseString()
{
    // true if and only if the amount of backslashes before the current
    // character is even
    bool evenAmountOfBackslashes = true;

    // the result of the parse process
    std::string result;

    // iterate with pos_ over the whole input until we found the end and return
    // or we exit via error()
    for (; pos_ < buffer_.size(); pos_++)
    {
        char currentChar = buffer_[pos_];

        if (not evenAmountOfBackslashes)
        {
            // uneven amount of backslashes means the user wants to escape
            // something so we know there is a case such as '\X' or '\\\X' but
            // we don't know yet what X is.
            // at this point in the code, the currentChar has the value of X.

            // slash, backslash and quote are copied as is
            if (currentChar == '/' or currentChar == '\\' or currentChar == '"')
            {
                result += currentChar;
            }
            else
            {
                // all other characters are replaced by their respective special
                // character
                switch (currentChar)
                {
                    case 't':
                    {
                        result += '\t';
                        break;
                    }
                    case 'b':
                    {
                        result += '\b';
                        break;
                    }
                    case 'f':
                    {
                        result += '\f';
                        break;
                    }
                    case 'n':
                    {
                        result += '\n';
                        break;
                    }
                    case 'r':
                    {
                        result += '\r';
                        break;
                    }
                    case 'u':
                    {
                        // \uXXXX[\uXXXX] is used for escaping unicode, which
                        // has it's own subroutine.
                        result += parseUnicodeEscape();
                        // the parsing process has brought us one step behind
                        // the unicode escape sequence:
                        // \uXXXX
                        //       ^
                        // we need to go one character back or the parser would
                        // skip the character we are currently pointing at as
                        // the for-loop will decrement pos_ after this iteration
                        pos_--;
                        break;
                    }
                    default:
                    {
                        error("expected one of \\, /, b, f, n, r, t, u behind backslash.");
                    }
                }
            }
        }
        else
        {
            if (currentChar == '"')
            {
                // currentChar is a quote, so we found the end of the string

                // set pos_ behind the trailing quote
                pos_++;
                // find next char to parse
                next();

                // bring the result of the parsing process back to the caller
                return result;
            }
            else if (currentChar != '\\')
            {
                // all non-backslash characters are added to the end of the
                // result string. The only backslashes we want in the result
                // are the ones that are escaped (which happens above).
                result += currentChar;
            }
        }

        // remember if we have an even amount of backslashes before the current
        // character
        if (currentChar == '\\')
        {
            // jump between even/uneven for each backslash we encounter
            evenAmountOfBackslashes = not evenAmountOfBackslashes;
        }
        else
        {
            // zero backslashes are also an even number, so as soon as we
            // encounter a non-backslash the chain of backslashes breaks and
            // we start again from zero
            evenAmountOfBackslashes = true;
        }
    }

    // we iterated over the whole string without finding a unescaped quote
    // so the given string is malformed
    error("expected '\"'");
}



/*!
Turns a code point into it's UTF-8 representation.
You should only pass numbers < 0x10ffff into this function
(everything else is a invalid code point).

@return the UTF-8 representation of the given code point
*/
std::string json::parser::codePointToUTF8(unsigned int codePoint) const
{
    // this method contains a lot of bit manipulations to
    // build the bytes for UTF-8.

    // the '(... >> S) & 0xHH'-patterns are used to retrieve
    // certain bits from the code points.

    // all static casts in this method have boundary checks

    // we initialize all strings with their final length
    // (e.g. 1 to 4 bytes) to save the reallocations.

    if (codePoint <= 0x7f)
    {
        // it's just a ASCII compatible codePoint,
        // so we just interpret the point as a character
        // and return ASCII

        return std::string(1, static_cast<char>(codePoint));
    }
    // if true, we need two bytes to encode this as UTF-8
    else if (codePoint <= 0x7ff)
    {
        // the 0xC0 enables the two most significant two bits
        // to make this a two-byte UTF-8 character.
        std::string result(2, static_cast<char>(0xC0 | ((codePoint >> 6) & 0x1F)));
        result[1] = static_cast<char>(0x80 | (codePoint & 0x3F));
        return result;
    }
    // if true, now we need three bytes to encode this as UTF-8
    else if (codePoint <= 0xffff)
    {
        // the 0xE0 enables the three most significant two bits
        // to make this a three-byte UTF-8 character.
        std::string result(3, static_cast<char>(0xE0 | ((codePoint >> 12) & 0x0F)));
        result[1] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
        result[2] = static_cast<char>(0x80 | (codePoint & 0x3F));
        return result;
    }
    // if true, we need maximal four bytes to encode this as UTF-8
    else if (codePoint <= 0x10ffff)
    {
        // the 0xE0 enables the four most significant two bits
        // to make this a three-byte UTF-8 character.
        std::string result(4, static_cast<char>(0xF0 | ((codePoint >> 18) & 0x07)));
        result[1] = static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F));
        result[2] = static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
        result[3] = static_cast<char>(0x80 | (codePoint & 0x3F));
        return result;
    }
    else
    {
        // Can't be tested without direct access to this private method.
        std::string errorMessage = "Invalid codePoint: ";
        errorMessage += codePoint;
        error(errorMessage);
    }
}

/*!
Parses 4 hexadecimal characters as a number.

@return the value of the number the hexadecimal characters represent.

@pre  pos_ is pointing to the first of the 4 hexadecimal characters.

@post pos_ is pointing to the character after the 4 hexadecimal characters.
*/
unsigned int json::parser::parse4HexCodePoint()
{
    const auto startPos = pos_;

    // check if the  remaining buffer is long enough to even hold 4 characters
    if (pos_ + 3 >= buffer_.size())
    {
        error("Got end of input while parsing unicode escape sequence \\uXXXX");
    }

    // make a string that can hold the pair
    std::string hexCode(4, ' ');

    for (; pos_ < startPos + 4; pos_++)
    {
        // no boundary check here as we already checked above
        char currentChar = buffer_[pos_];

        // check if we have a hexadecimal character
        if ((currentChar >= '0' and currentChar <= '9')
                or (currentChar >= 'a' and currentChar <= 'f')
                or (currentChar >= 'A' and currentChar <= 'F'))
        {
            // all is well, we have valid hexadecimal chars
            // so we copy that char into our string
            hexCode[pos_ - startPos] = currentChar;
        }
        else
        {
            error("Found non-hexadecimal character in unicode escape sequence!");
        }
    }
    // the cast is safe as 4 hex characters can't present more than 16 bits
    // the input to stoul was checked to contain only hexadecimal characters
    // (see above)
    return static_cast<unsigned int>(std::stoul(hexCode, nullptr, 16));
}

/*!
Parses the unicode escape codes as defined in the ECMA-404.
The escape sequence has two forms:
1. \uXXXX
2. \uXXXX\uYYYY
where X and Y are a hexadecimal character (a-zA-Z0-9).

Form 1 just contains the unicode code point in the hexadecimal number XXXX.
Form 2 is encoding a UTF-16 surrogate pair. The high surrogate is XXXX, the low
surrogate is YYYY.

@return the UTF-8 character this unicode escape sequence escaped.

@pre  pos_ is pointing at at the 'u' behind the first backslash.

@post pos_ is pointing at the character behind the last X (or Y in form 2).
*/
std::string json::parser::parseUnicodeEscape()
{
    // jump to the first hex value
    pos_++;
    // parse the hex first hex values
    unsigned int firstCodePoint = parse4HexCodePoint();

    if (firstCodePoint >= 0xD800 and firstCodePoint <= 0xDBFF)
    {
        // we found invalid code points, which means we either have a malformed
        // input or we found a high surrogate.
        // we can only find out by seeing if the next character also wants to
        // encode a unicode character (so, we have the \uXXXX\uXXXX case here).

        // jump behind the next \u
        pos_ += 2;
        // try to parse the next hex values.
        // the method does boundary checking for us, so no need to do that here
        unsigned secondCodePoint = parse4HexCodePoint();
        // ok, we have a low surrogate, check if it is a valid one
        if (secondCodePoint >= 0xDC00 and secondCodePoint <= 0xDFFF)
        {
            // calculate the code point from the pair according to the spec
            unsigned int finalCodePoint =
                // high surrogate occupies the most significant 22 bits
                (firstCodePoint << 10)
                // low surrogate occupies the least significant 15 bits
                + secondCodePoint
                // there is still the 0xD800, 0xDC00 and 0x10000 noise in
                // the result
                // so we have to substract with:
                // (0xD800 << 10) + DC00 - 0x10000 = 0x35FDC00
                - 0x35FDC00;

            // we transform the calculated point into UTF-8
            return codePointToUTF8(finalCodePoint);
        }
        else
        {
            error("missing low surrogate");
        }

    }
    // We have Form 1, so we just interpret the XXXX as a code point
    return codePointToUTF8(firstCodePoint);
}


/*!
This function is called in case a \p "t" is read in the main parse function
@ref parse. In the standard, the \p "true" token is the only candidate, so the
next three characters are expected to be \p "rue". In case of a mismatch, an
error is raised via @ref error.

@pre  A \p "t" was read in the main parse function @ref parse.
@post The character after the \p "true" is the current character. Whitespace is
      skipped.
*/
void json::parser::parseTrue()
{
    if (buffer_.substr(pos_, 3) != "rue")
    {
        error("expected true");
    }

    pos_ += 3;

    // read next character
    next();
}

/*!
This function is called in case an \p "f" is read in the main parse function
@ref parse. In the standard, the \p "false" token is the only candidate, so the
next four characters are expected to be \p "alse". In case of a mismatch, an
error is raised via @ref error.

@pre  An \p "f" was read in the main parse function.
@post The character after the \p "false" is the current character. Whitespace
      is skipped.
*/
void json::parser::parseFalse()
{
    if (buffer_.substr(pos_, 4) != "alse")
    {
        error("expected false");
    }

    pos_ += 4;

    // read next character
    next();
}

/*!
This function is called in case an \p "n" is read in the main parse function
@ref parse. In the standard, the \p "null" token is the only candidate, so the
next three characters are expected to be \p "ull". In case of a mismatch, an
error is raised via @ref error.

@pre  An \p "n" was read in the main parse function.
@post The character after the \p "null" is the current character. Whitespace is
      skipped.
*/
void json::parser::parseNull()
{
    if (buffer_.substr(pos_, 3) != "ull")
    {
        error("expected null");
    }

    pos_ += 3;

    // read next character
    next();
}

/*!
This function wraps functionality to check whether the current character @ref
current_ matches a given character \p c. In case of a match, the next character
of the buffer @ref buffer_ is read. In case of a mismatch, an error is raised
via @ref error.

@param c  character that is expected

@post The next chatacter is read. Whitespace is skipped.
*/
void json::parser::expect(const char c)
{
    if (current_ != c)
    {
        std::string msg = "expected '";
        msg.append(1, c);
        msg += "'";
        error(msg);
    }
    else
    {
        next();
    }
}

}

/*!
This operator implements a user-defined string literal for JSON objects. It can
be used by adding \p "_json" to a string literal and returns a JSON object if
no parse error occurred.

@param s  a string representation of a JSON object
@return a JSON object
*/
nlohmann::json operator "" _json(const char* s, std::size_t)
{
    return nlohmann::json::parse(s);
}
