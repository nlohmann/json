/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2015 Niels Lohmann.

@author Niels Lohmann <http://nlohmann.me>

@see https://github.com/nlohmann/json
*/

#include "json.h"

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
json::json(const value_t t)
    : type_(t)
{
    switch (type_)
    {
        case (value_t::array):
        {
            value_.array = new array_t();
            break;
        }
        case (value_t::object):
        {
            value_.object = new object_t();
            break;
        }
        case (value_t::string):
        {
            value_.string = new string_t();
            break;
        }
        case (value_t::boolean):
        {
            value_.boolean = boolean_t();
            break;
        }
        case (value_t::number):
        {
            value_.number = number_t();
            break;
        }
        case (value_t::number_float):
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
    : type_(value_t::string), value_(new string_t(s))
{}

json::json(std::string&& s)
    : type_(value_t::string), value_(new string_t(std::move(s)))
{}

json::json(const char* s)
    : type_(value_t::string), value_(new string_t(s))
{}

json::json(const bool b) noexcept
    : type_(value_t::boolean), value_(b)
{}

json::json(const array_t& a)
    : type_(value_t::array), value_(new array_t(a))
{}

json::json(array_t&& a)
    : type_(value_t::array), value_(new array_t(std::move(a)))
{}

json::json(const object_t& o)
    : type_(value_t::object), value_(new object_t(o))
{}

json::json(object_t&& o)
    : type_(value_t::object), value_(new object_t(std::move(o)))
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
        if (element.type_ != value_t::array or
                element.size() != 2 or
                element[0].type_ != value_t::string)
        {

            // the initializer list describes an array
            type_ = value_t::array;
            value_ = new array_t(a);
            return;
        }
    }

    // the initializer list is a list of pairs
    type_ = value_t::object;
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
        case (value_t::array):
        {
            value_.array = new array_t(*o.value_.array);
            break;
        }
        case (value_t::object):
        {
            value_.object = new object_t(*o.value_.object);
            break;
        }
        case (value_t::string):
        {
            value_.string = new string_t(*o.value_.string);
            break;
        }
        case (value_t::boolean):
        {
            value_.boolean = o.value_.boolean;
            break;
        }
        case (value_t::number):
        {
            value_.number = o.value_.number;
            break;
        }
        case (value_t::number_float):
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
    o.type_ = value_t::null;
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
        case (value_t::array):
        {
            delete value_.array;
            break;
        }
        case (value_t::object):
        {
            delete value_.object;
            break;
        }
        case (value_t::string):
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
        case (value_t::array):
        {
            return "array";
        }
        case (value_t::object):
        {
            return "object";
        }
        case (value_t::null):
        {
            return "null";
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
        case (value_t::string):
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
        case (value_t::number):
            return value_.number;
        case (value_t::number_float):
            return static_cast<int>(value_.number_float);
        default:
            throw std::logic_error("cannot cast " + type_name() + " to JSON number");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not number (int or float)
*/
template<>
int64_t json::get() const
{
    switch (type_)
    {
        case (value_t::number):
            return value_.number;
        case (value_t::number_float):
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
        case (value_t::number):
            return static_cast<number_float_t>(value_.number);
        case (value_t::number_float):
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
        case (value_t::boolean):
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
    if (type_ == value_t::array)
    {
        return *value_.array;
    }
    if (type_ == value_t::object)
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
    if (type_ == value_t::object)
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

json::operator int64_t() const
{
    return get<int64_t>();
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
        case (value_t::string):
        {
            return std::string("\"") + escapeString(*value_.string) + "\"";
        }

        case (value_t::boolean):
        {
            return value_.boolean ? "true" : "false";
        }

        case (value_t::number):
        {
            return std::to_string(value_.number);
        }

        case (value_t::number_float):
        {
            return std::to_string(value_.number_float);
        }

        case (value_t::array):
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
                    result += prettyPrint ? ",\n" : ",";
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

        case (value_t::object):
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
                    result += prettyPrint ? ",\n" : ",";
                }
                result += indent() + "\"" + i->first + "\":" + (prettyPrint ? " " : "") + i->second.dump(
                              prettyPrint, indentStep,
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

        // actually only value_t::null - but making the compiler happy
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
    if (not(type_ == value_t::null or type_ == value_t::array))
    {
        throw std::runtime_error("cannot add element to " + type_name());
    }

    // transform null object into an array
    if (type_ == value_t::null)
    {
        type_ = value_t::array;
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
    if (not(type_ == value_t::null or type_ == value_t::array))
    {
        throw std::runtime_error("cannot add element to " + type_name());
    }

    // transform null object into an array
    if (type_ == value_t::null)
    {
        type_ = value_t::array;
        value_.array = new array_t;
    }

    // add element to array (move semantics)
    value_.array->emplace_back(std::move(o));
    // invalidate object
    o.type_ = value_t::null;
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
        if (element.type_ != value_t::array or
                element.size() != 2 or
                element[0].type_ != value_t::string)
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
json::reference json::operator[](const int index)
{
    // this [] operator only works for arrays
    if (type_ != value_t::array)
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
json::const_reference json::operator[](const int index) const
{
    // this [] operator only works for arrays
    if (type_ != value_t::array)
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
json::reference json::at(const int index)
{
    // this function only works for arrays
    if (type_ != value_t::array)
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
json::const_reference json::at(const int index) const
{
    // this function only works for arrays
    if (type_ != value_t::array)
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
json::reference json::operator[](const std::string& key)
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
json::reference json::operator[](const char* key)
{
    // implicitly convert null to object
    if (type_ == value_t::null)
    {
        type_ = value_t::object;
        value_.object = new object_t;
    }

    // this [] operator only works for objects
    if (type_ != value_t::object)
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
json::const_reference json::operator[](const std::string& key) const
{
    // this [] operator only works for objects
    if (type_ != value_t::object)
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
json::reference json::at(const std::string& key)
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
json::reference json::at(const char* key)
{
    // this function operator only works for objects
    if (type_ != value_t::object)
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
json::const_reference json::at(const std::string& key) const
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
json::const_reference json::at(const char* key) const
{
    // this [] operator only works for objects
    if (type_ != value_t::object)
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
json::size_type json::size() const noexcept
{
    switch (type_)
    {
        case (value_t::array):
        {
            return value_.array->size();
        }
        case (value_t::object):
        {
            return value_.object->size();
        }
        case (value_t::null):
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
Returns the maximal size of the JSON object.

@return the maximal size of the JSON object; the maximal size is the maximal
        number of elements in compounds (array and object), 1 for value types
        (true, false, number, string), and 0 for null.
*/
json::size_type json::max_size() const noexcept
{
    switch (type_)
    {
        case (value_t::array):
        {
            return value_.array->max_size();
        }
        case (value_t::object):
        {
            return value_.object->max_size();
        }
        case (value_t::null):
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
        case (value_t::array):
        {
            return value_.array->empty();
        }
        case (value_t::object):
        {
            return value_.object->empty();
        }
        case (value_t::null):
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
        case (value_t::array):
        {
            value_.array->clear();
            break;
        }
        case (value_t::object):
        {
            value_.object->clear();
            break;
        }
        case (value_t::string):
        {
            value_.string->clear();
            break;
        }
        case (value_t::boolean):
        {
            value_.boolean = {};
            break;
        }
        case (value_t::number):
        {
            value_.number = {};
            break;
        }
        case (value_t::number_float):
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

void json::swap(json& o) noexcept
{
    std::swap(type_, o.type_);
    std::swap(value_, o.value_);
}

json::value_t json::type() const noexcept
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
    auto result = end();

    if (type_ == value_t::object)
    {
        delete result.oi_;
        result.oi_ = new object_t::iterator(value_.object->find(key));
        result.invalid = (*(result.oi_) == value_.object->end());
    }

    return result;
}

json::const_iterator json::find(const char* key) const
{
    auto result = cend();

    if (type_ == value_t::object)
    {
        delete result.oi_;
        result.oi_ = new object_t::const_iterator(value_.object->find(key));
        result.invalid = (*(result.oi_) == value_.object->cend());
    }

    return result;
}

bool json::operator==(const json& o) const noexcept
{
    switch (type_)
    {
        case (value_t::array):
        {
            if (o.type_ == value_t::array)
            {
                return *value_.array == *o.value_.array;
            }
            break;
        }
        case (value_t::object):
        {
            if (o.type_ == value_t::object)
            {
                return *value_.object == *o.value_.object;
            }
            break;
        }
        case (value_t::null):
        {
            if (o.type_ == value_t::null)
            {
                return true;
            }
            break;
        }
        case (value_t::string):
        {
            if (o.type_ == value_t::string)
            {
                return *value_.string == *o.value_.string;
            }
            break;
        }
        case (value_t::boolean):
        {
            if (o.type_ == value_t::boolean)
            {
                return value_.boolean == o.value_.boolean;
            }
            break;
        }
        case (value_t::number):
        {
            if (o.type_ == value_t::number)
            {
                return value_.number == o.value_.number;
            }
            if (o.type_ == value_t::number_float)
            {
                return value_.number == static_cast<number_t>(o.value_.number_float);
            }
            break;
        }
        case (value_t::number_float):
        {
            if (o.type_ == value_t::number)
            {
                return value_.number_float == static_cast<number_float_t>(o.value_.number);
            }
            if (o.type_ == value_t::number_float)
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
    return json::iterator(this, true);
}

json::iterator json::end() noexcept
{
    return json::iterator(this, false);
}

json::const_iterator json::begin() const noexcept
{
    return json::const_iterator(this, true);
}

json::const_iterator json::end() const noexcept
{
    return json::const_iterator(this, false);
}

json::const_iterator json::cbegin() const noexcept
{
    return json::const_iterator(this, true);
}

json::const_iterator json::cend() const noexcept
{
    return json::const_iterator(this, false);
}

json::reverse_iterator json::rbegin() noexcept
{
    return reverse_iterator(end());
}

json::reverse_iterator json::rend() noexcept
{
    return reverse_iterator(begin());
}

json::const_reverse_iterator json::crbegin() const noexcept
{
    return const_reverse_iterator(cend());
}

json::const_reverse_iterator json::crend() const noexcept
{
    return const_reverse_iterator(cbegin());
}


json::iterator::iterator(json* j, bool begin)
    : object_(j), invalid(not begin or j == nullptr)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_t::array)
        {
            if (begin)
            {
                vi_ = new array_t::iterator(object_->value_.array->begin());
                invalid = (*vi_ == object_->value_.array->end());
            }
            else
            {
                vi_ = new array_t::iterator(object_->value_.array->end());
            }
        }
        else if (object_->type_ == json::value_t::object)
        {
            if (begin)
            {
                oi_ = new object_t::iterator(object_->value_.object->begin());
                invalid = (*oi_ == object_->value_.object->end());
            }
            else
            {
                oi_ = new object_t::iterator(object_->value_.object->end());
            }
        }
    }
}

json::iterator::iterator(const json::iterator& o)
    : object_(o.object_), invalid(o.invalid)
{
    if (o.vi_ != nullptr)
    {
        vi_ = new array_t::iterator(*(o.vi_));
    }

    if (o.oi_ != nullptr)
    {
        oi_ = new object_t::iterator(*(o.oi_));
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
    std::swap(invalid, o.invalid);
    return *this;
}

bool json::iterator::operator==(const json::iterator& o) const
{
    if (object_ != nullptr and o.object_ != nullptr)
    {
        if (object_->type_ == json::value_t::array and o.object_->type_ == json::value_t::array)
        {
            return (*vi_ == *(o.vi_));
        }
        if (object_->type_ == json::value_t::object and o.object_->type_ == json::value_t::object)
        {
            return (*oi_ == *(o.oi_));
        }

        if (invalid == o.invalid and object_ == o.object_)
        {
            return true;
        }
    }
    return false;
}

bool json::iterator::operator!=(const json::iterator& o) const
{
    return not operator==(o);
}

json::iterator& json::iterator::operator++()
{
    if (object_ != nullptr)
    {
        switch (object_->type_)
        {
            case (json::value_t::array):
            {
                std::advance(*vi_, 1);
                invalid = (*vi_ == object_->value_.array->end());
                break;
            }
            case (json::value_t::object):
            {
                std::advance(*oi_, 1);
                invalid = (*oi_ == object_->value_.object->end());
                break;
            }
            default:
            {
                invalid = true;
                break;
            }
        }
    }

    return *this;
}

json::iterator& json::iterator::operator--()
{
    if (object_ != nullptr)
    {
        switch (object_->type_)
        {
            case (json::value_t::array):
            {
                invalid = (*vi_ == object_->value_.array->begin());
                std::advance(*vi_, -1);
                break;
            }
            case (json::value_t::object):
            {
                invalid = (*oi_ == object_->value_.object->begin());
                std::advance(*oi_, -1);
                break;
            }
            default:
            {
                invalid = true;
                break;
            }
        }
    }

    return *this;
}

json& json::iterator::operator*() const
{
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return **vi_;
        }
        case (json::value_t::object):
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
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return &(**vi_);
        }
        case (json::value_t::object):
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
    if (object_ == nullptr or invalid or object_->type_ != json::value_t::object)
    {
        throw std::out_of_range("cannot get value");
    }

    return (*oi_)->first;
}

json& json::iterator::value() const
{
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return **vi_;
        }
        case (json::value_t::object):
        {
            return (*oi_)->second;
        }
        default:
        {
            return *object_;
        }
    }
}


json::const_iterator::const_iterator(const json* j, bool begin)
    : object_(j), invalid(not begin or j == nullptr)
{
    if (object_ != nullptr)
    {
        if (object_->type_ == json::value_t::array)
        {
            if (begin)
            {
                vi_ = new array_t::const_iterator(object_->value_.array->cbegin());
                invalid = (*vi_ == object_->value_.array->cend());
            }
            else
            {
                vi_ = new array_t::const_iterator(object_->value_.array->cend());
            }
        }
        else if (object_->type_ == json::value_t::object)
        {
            if (begin)
            {
                oi_ = new object_t::const_iterator(object_->value_.object->cbegin());
                invalid = (*oi_ == object_->value_.object->cend());
            }
            else
            {
                oi_ = new object_t::const_iterator(object_->value_.object->cend());
            }
        }
    }
}

json::const_iterator::const_iterator(const json::const_iterator& o)
    : object_(o.object_), invalid(o.invalid)
{
    if (o.vi_ != nullptr)
    {
        vi_ = new array_t::const_iterator(*(o.vi_));
    }
    if (o.oi_ != nullptr)
    {
        oi_ = new object_t::const_iterator(*(o.oi_));
    }
}

json::const_iterator::const_iterator(const json::iterator& o)
    : object_(o.object_), invalid(o.invalid)
{
    if (o.vi_ != nullptr)
    {
        vi_ = new array_t::const_iterator(*(o.vi_));
    }
    if (o.oi_ != nullptr)
    {
        oi_ = new object_t::const_iterator(*(o.oi_));
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
    std::swap(invalid, o.invalid);
    return *this;
}

bool json::const_iterator::operator==(const json::const_iterator& o) const
{
    if (object_ != nullptr and o.object_ != nullptr)
    {
        if (object_->type_ == json::value_t::array and o.object_->type_ == json::value_t::array)
        {
            return (*vi_ == *(o.vi_));
        }
        if (object_->type_ == json::value_t::object and o.object_->type_ == json::value_t::object)
        {
            return (*oi_ == *(o.oi_));
        }
        if (invalid == o.invalid and object_ == o.object_)
        {
            return true;
        }
    }

    return false;
}

bool json::const_iterator::operator!=(const json::const_iterator& o) const
{
    return not operator==(o);
}

json::const_iterator& json::const_iterator::operator++()
{
    if (object_ != nullptr)
    {
        switch (object_->type_)
        {
            case (json::value_t::array):
            {
                std::advance(*vi_, 1);
                invalid = (*vi_ == object_->value_.array->end());
                break;
            }
            case (json::value_t::object):
            {
                std::advance(*oi_, 1);
                invalid = (*oi_ == object_->value_.object->end());
                break;
            }
            default:
            {
                invalid = true;
                break;
            }
        }
    }

    return *this;
}

json::const_iterator& json::const_iterator::operator--()
{
    if (object_ != nullptr)
    {
        switch (object_->type_)
        {
            case (json::value_t::array):
            {
                invalid = (*vi_ == object_->value_.array->begin());
                std::advance(*vi_, -1);
                break;
            }
            case (json::value_t::object):
            {
                invalid = (*oi_ == object_->value_.object->begin());
                std::advance(*oi_, -1);
                break;
            }
            default:
            {
                invalid = true;
                break;
            }
        }
    }

    return *this;
}

const json& json::const_iterator::operator*() const
{
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return **vi_;
        }
        case (json::value_t::object):
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
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return &(**vi_);
        }
        case (json::value_t::object):
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
    if (object_ == nullptr or invalid or object_->type_ != json::value_t::object)
    {
        throw std::out_of_range("cannot get value");
    }

    return (*oi_)->first;
}

const json& json::const_iterator::value() const
{
    if (object_ == nullptr or invalid)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (object_->type_)
    {
        case (json::value_t::array):
        {
            return **vi_;
        }
        case (json::value_t::object):
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
            json result(value_t::object);

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
            json result(value_t::array);

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
                const auto float_val = std::stold(buffer_.substr(_firstpos_, pos_ - _firstpos_));
                const auto int_val = static_cast<number_t>(float_val);

                // check if conversion loses precision
                if (float_val == int_val)
                {
                    // we would not lose precision -> int
                    return json(int_val);
                }
                else
                {
                    // we would lose precision -> float
                    return json(static_cast<number_float_t>(float_val));
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
