/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2014 Niels Lohmann.

@author Niels Lohmann <http://nlohmann.me>

@see https://github.com/nlohmann/json
*/

#include "JSON.h"

#include <cctype>     // std::isdigit, std::isspace
#include <cstddef>    // size_t
#include <cstdlib>    // std::atof
#include <cstring>    // std::strlen, std::strchr, std::strcpy, std::strncmp
#include <stdexcept>  // std::runtime_error
#include <utility>    // std::swap, std::move


////////////////////
// STATIC MEMBERS //
////////////////////

std::mutex JSON::_token;


///////////////////////////////////
// CONSTRUCTORS OF UNION "value" //
///////////////////////////////////

JSON::value::value(array_t* _array): array(_array) {}
JSON::value::value(object_t* _object): object(_object) {}
JSON::value::value(string_t* _string): string(_string) {}
JSON::value::value(boolean_t _boolean) : boolean(_boolean) {}
JSON::value::value(number_t _number) : number(_number) {}
JSON::value::value(number_float_t _number_float) : number_float(_number_float) {}


/////////////////////////////////
// CONSTRUCTORS AND DESTRUCTOR //
/////////////////////////////////

/*!
Construct an empty JSON given the type.

@param t  the type from the @ref JSON::type enumeration.

@post Memory for array, object, and string are allocated.
*/
JSON::JSON(const value_type t) noexcept
    : _type(t)
{
    switch (_type)
    {
        case (value_type::array):
        {
            _value.array = new array_t();
            break;
        }
        case (value_type::object):
        {
            _value.object = new object_t();
            break;
        }
        case (value_type::string):
        {
            _value.string = new string_t();
            break;
        }
        case (value_type::boolean):
        {
            _value.boolean = boolean_t();
            break;
        }
        case (value_type::number):
        {
            _value.number = number_t();
            break;
        }
        case (value_type::number_float):
        {
            _value.number_float = number_float_t();
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
JSON::JSON(std::nullptr_t) noexcept : JSON()
{}

/*!
Construct a string JSON object.

@param s  a string to initialize the JSON object with
*/
JSON::JSON(const std::string& s) noexcept
    : _type(value_type::string), _value(new string_t(s))
{}

JSON::JSON(std::string&& s) noexcept
    : _type(value_type::string), _value(new string_t(std::move(s)))
{}

JSON::JSON(const char* s) noexcept
    : _type(value_type::string), _value(new string_t(s))
{}

JSON::JSON(const bool b) noexcept
    : _type(value_type::boolean), _value(b)
{}

JSON::JSON(const int i) noexcept
    : _type(value_type::number), _value(i)
{}

JSON::JSON(const double f) noexcept
    : _type(value_type::number_float), _value(f)
{}

JSON::JSON(const array_t& a) noexcept
    : _type(value_type::array), _value(new array_t(a))
{}

JSON::JSON(array_t&& a) noexcept
    : _type(value_type::array), _value(new array_t(std::move(a)))
{}

JSON::JSON(const object_t& o) noexcept
    : _type(value_type::object), _value(new object_t(o))
{}

JSON::JSON(object_t&& o) noexcept
    : _type(value_type::object), _value(new object_t(std::move(o)))
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
JSON::JSON(list_init_t a) noexcept
{
    // check if each element is an array with two elements whose first element
    // is a string
    for (const auto& element : a)
    {
        if (element._type != value_type::array or
                element.size() != 2 or
                element[0]._type != value_type::string)
        {

            // the initializer list describes an array
            _type = value_type::array;
            _value = new array_t(a);
            return;
        }
    }

    // the initializer list is a list of pairs
    _type = value_type::object;
    _value = new object_t();
    for (const JSON& element : a)
    {
        const std::string k = element[0];
        _value.object->emplace(std::make_pair(std::move(k),
                                              std::move(element[1])));
    }
}

/*!
A copy constructor for the JSON class.

@param o  the JSON object to copy
*/
JSON::JSON(const JSON& o) noexcept
    : _type(o._type)
{
    switch (_type)
    {
        case (value_type::array):
        {
            _value.array = new array_t(*o._value.array);
            break;
        }
        case (value_type::object):
        {
            _value.object = new object_t(*o._value.object);
            break;
        }
        case (value_type::string):
        {
            _value.string = new string_t(*o._value.string);
            break;
        }
        case (value_type::boolean):
        {
            _value.boolean = o._value.boolean;
            break;
        }
        case (value_type::number):
        {
            _value.number = o._value.number;
            break;
        }
        case (value_type::number_float):
        {
            _value.number_float = o._value.number_float;
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
JSON::JSON(JSON&& o) noexcept
    : _type(std::move(o._type)), _value(std::move(o._value))
{
    // invalidate payload
    o._value = {};
}

/*!
A copy assignment operator for the JSON class, following the copy-and-swap
idiom.

@param o  A JSON object to assign to this object.
*/
JSON& JSON::operator=(JSON o) noexcept
{
    std::swap(_type, o._type);
    std::swap(_value, o._value);
    return *this;
}

JSON::~JSON() noexcept
{
    switch (_type)
    {
        case (value_type::array):
        {
            delete _value.array;
            break;
        }
        case (value_type::object):
        {
            delete _value.object;
            break;
        }
        case (value_type::string):
        {
            delete _value.string;
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
JSON JSON::parse(const std::string& s)
{
    JSON j;
    Parser(s).parse(j);
    return j;
}

/*!
@param s  a string representation of a JSON object
@return a JSON object
*/
JSON JSON::parse(const char* s)
{
    JSON j;
    Parser(s).parse(j);
    return j;
}


const std::string JSON::_typename() const noexcept
{
    switch (_type)
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
std::string JSON::get() const
{
    switch (_type)
    {
        case (value_type::string):
            return *_value.string;
        default:
            throw std::logic_error("cannot cast " + _typename() + " to JSON string");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not number (int or float)
*/
template<>
int JSON::get() const
{
    switch (_type)
    {
        case (value_type::number):
            return _value.number;
        case (value_type::number_float):
            return static_cast<number_t>(_value.number_float);
        default:
            throw std::logic_error("cannot cast " + _typename() + " to JSON number");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not number (int or float)
*/
template<>
double JSON::get() const
{
    switch (_type)
    {
        case (value_type::number):
            return static_cast<number_float_t>(_value.number);
        case (value_type::number_float):
            return _value.number_float;
        default:
            throw std::logic_error("cannot cast " + _typename() + " to JSON number");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is not boolean
*/
template<>
bool JSON::get() const
{
    switch (_type)
    {
        case (value_type::boolean):
            return _value.boolean;
        default:
            throw std::logic_error("cannot cast " + _typename() + " to JSON Boolean");
    }
}

/*!
@exception std::logic_error if the function is called for JSON objects whose
    type is an object
*/
template<>
JSON::array_t JSON::get() const
{
    if (_type == value_type::array)
    {
        return *_value.array;
    }
    if (_type == value_type::object)
    {
        throw std::logic_error("cannot cast " + _typename() + " to JSON array");
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
JSON::object_t JSON::get() const
{
    if (_type == value_type::object)
    {
        return *_value.object;
    }
    else
    {
        throw std::logic_error("cannot cast " + _typename() + " to JSON object");
    }
}

JSON::operator const std::string() const
{
    return get<std::string>();
}

JSON::operator int() const
{
    return get<int>();
}

JSON::operator double() const
{
    return get<double>();
}

JSON::operator bool() const
{
    return get<bool>();
}

JSON::operator array_t() const
{
    return get<array_t>();
}

JSON::operator object_t() const
{
    return get<object_t>();
}

const std::string JSON::toString() const noexcept
{
    switch (_type)
    {
        case (value_type::string):
        {
            return std::string("\"") + *_value.string + "\"";
        }

        case (value_type::boolean):
        {
            return _value.boolean ? "true" : "false";
        }

        case (value_type::number):
        {
            return std::to_string(_value.number);
        }

        case (value_type::number_float):
        {
            return std::to_string(_value.number_float);
        }

        case (value_type::array):
        {
            std::string result;

            for (array_t::const_iterator i = _value.array->begin(); i != _value.array->end(); ++i)
            {
                if (i != _value.array->begin())
                {
                    result += ", ";
                }
                result += i->toString();
            }

            return "[" + result + "]";
        }

        case (value_type::object):
        {
            std::string result;

            for (object_t::const_iterator i = _value.object->begin(); i != _value.object->end(); ++i)
            {
                if (i != _value.object->begin())
                {
                    result += ", ";
                }
                result += "\"" + i->first + "\": " + i->second.toString();
            }

            return "{" + result + "}";
        }

        // actually only value_type::null - but making the compiler happy
        default:
        {
            return "null";
        }
    }
}


///////////////////////////////////////////
// ADDING ELEMENTS TO OBJECTS AND ARRAYS //
///////////////////////////////////////////

JSON& JSON::operator+=(const JSON& o)
{
    push_back(o);
    return *this;
}

JSON& JSON::operator+=(const std::string& s)
{
    push_back(JSON(s));
    return *this;
}

JSON& JSON::operator+=(const char* s)
{
    push_back(JSON(s));
    return *this;
}

JSON& JSON::operator+=(std::nullptr_t)
{
    push_back(JSON());
    return *this;
}

JSON& JSON::operator+=(bool b)
{
    push_back(JSON(b));
    return *this;
}

/*!
Adds a number (int) to the current object. This is done by wrapping the number
into a JSON and call push_back for this.

@param i  A number (int) to add to the array.
*/
JSON& JSON::operator+=(int i)
{
    push_back(JSON(i));
    return *this;
}

/*!
Adds a number (float) to the current object. This is done by wrapping the
number into a JSON and call push_back for this.

@param f  A number (float) to add to the array.
*/
JSON& JSON::operator+=(double f)
{
    push_back(JSON(f));
    return *this;
}

/*!
@todo comment me
*/
JSON& JSON::operator+=(const object_t::value_type& p)
{
    return operator[](p.first) = p.second;
}

/*!
@todo comment me
*/
JSON& JSON::operator+=(list_init_t a)
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
void JSON::push_back(const JSON& o)
{
    // push_back only works for null objects or arrays
    if (not(_type == value_type::null or _type == value_type::array))
    {
        throw std::runtime_error("cannot add element to " + _typename());
    }

    std::lock_guard<std::mutex> lg(_token);

    // transform null object into an array
    if (_type == value_type::null)
    {
        _type = value_type::array;
        _value.array = new array_t;
    }

    // add element to array
    _value.array->push_back(o);
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
void JSON::push_back(JSON&& o)
{
    // push_back only works for null objects or arrays
    if (not(_type == value_type::null or _type == value_type::array))
    {
        throw std::runtime_error("cannot add element to " + _typename());
    }

    std::lock_guard<std::mutex> lg(_token);

    // transform null object into an array
    if (_type == value_type::null)
    {
        _type = value_type::array;
        _value.array = new array_t;
    }

    // add element to array (move semantics)
    _value.array->emplace_back(std::move(o));
    // invalidate object
    o._type = value_type::null;
}

void JSON::push_back(const std::string& s)
{
    push_back(JSON(s));
}

void JSON::push_back(const char* s)
{
    push_back(JSON(s));
}

void JSON::push_back(std::nullptr_t)
{
    push_back(JSON());
}

void JSON::push_back(bool b)
{
    push_back(JSON(b));
}

/*!
Adds a number (int) to the current object. This is done by wrapping the number
into a JSON and call push_back for this.

@param i  A number (int) to add to the array.
*/
void JSON::push_back(int i)
{
    push_back(JSON(i));
}

/*!
Adds a number (float) to the current object. This is done by wrapping the
number into a JSON and call push_back for this.

@param f  A number (float) to add to the array.
*/
void JSON::push_back(double f)
{
    push_back(JSON(f));
}

/*!
@todo comment me
*/
void JSON::push_back(const object_t::value_type& p)
{
    operator[](p.first) = p.second;
}

/*!
@todo comment me
*/
void JSON::push_back(list_init_t a)
{
    bool is_array = false;

    // check if each element is an array with two elements whose first element
    // is a string
    for (const auto& element : a)
    {
        if (element._type != value_type::array or
                element.size() != 2 or
                element[0]._type != value_type::string)
        {
            // the initializer list describes an array
            is_array = true;
            break;
        }
    }

    if (is_array)
    {
        for (const JSON& element : a)
        {
            push_back(element);
        }
    }
    else
    {
        for (const JSON& element : a)
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
JSON& JSON::operator[](const int index)
{
    // this [] operator only works for arrays
    if (_type != value_type::array)
    {
        throw std::domain_error("cannot add entry with index " +
                                std::to_string(index) + " to " + _typename());
    }

    std::lock_guard<std::mutex> lg(_token);

    // return reference to element from array at given index
    return (*_value.array)[static_cast<size_t>(index)];
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
const JSON& JSON::operator[](const int index) const
{
    // this [] operator only works for arrays
    if (_type != value_type::array)
    {
        throw std::domain_error("cannot get entry with index " +
                                std::to_string(index) + " from " + _typename());
    }

    // return element from array at given index
    return (*_value.array)[static_cast<size_t>(index)];
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
JSON& JSON::at(const int index)
{
    // this function only works for arrays
    if (_type != value_type::array)
    {
        throw std::domain_error("cannot add entry with index " +
                                std::to_string(index) + " to " + _typename());
    }

    std::lock_guard<std::mutex> lg(_token);

    // return reference to element from array at given index
    return _value.array->at(static_cast<size_t>(index));
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
const JSON& JSON::at(const int index) const
{
    // this function only works for arrays
    if (_type != value_type::array)
    {
        throw std::domain_error("cannot get entry with index " +
                                std::to_string(index) + " from " + _typename());
    }

    // return element from array at given index
    return _value.array->at(static_cast<size_t>(index));
}

/*!
@copydoc JSON::operator[](const char* key)
*/
JSON& JSON::operator[](const std::string& key)
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
JSON& JSON::operator[](const char* key)
{
    std::lock_guard<std::mutex> lg(_token);

    // implicitly convert null to object
    if (_type == value_type::null)
    {
        _type = value_type::object;
        _value.object = new object_t;
    }

    // this [] operator only works for objects
    if (_type != value_type::object)
    {
        throw std::domain_error("cannot add entry with key " +
                                std::string(key) + " to " + _typename());
    }

    // if the key does not exist, create it
    if (_value.object->find(key) == _value.object->end())
    {
        (*_value.object)[key] = JSON();
    }

    // return reference to element from array at given index
    return (*_value.object)[key];
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
const JSON& JSON::operator[](const std::string& key) const
{
    // this [] operator only works for objects
    if (_type != value_type::object)
    {
        throw std::domain_error("cannot get entry with key " +
                                std::string(key) + " from " + _typename());
    }

    // search for the key
    const auto it = _value.object->find(key);

    // make sure the key exists in the object
    if (it == _value.object->end())
    {
        throw std::out_of_range("key " + key + " not found");
    }

    // return element from array at given key
    return it->second;
}

/*!
@copydoc JSON::at(const char* key)
*/
JSON& JSON::at(const std::string& key)
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
JSON& JSON::at(const char* key)
{
    std::lock_guard<std::mutex> lg(_token);

    // this function operator only works for objects
    if (_type != value_type::object)
    {
        throw std::domain_error("cannot add entry with key " +
                                std::string(key) + " to " + _typename());
    }

    // return reference to element from array at given index
    return _value.object->at(key);
}

/*!
@copydoc JSON::at(const char *key) const
*/
const JSON& JSON::at(const std::string& key) const
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
const JSON& JSON::at(const char* key) const
{
    // this [] operator only works for objects
    if (_type != value_type::object)
    {
        throw std::domain_error("cannot get entry with key " +
                                std::string(key) + " from " + _typename());
    }

    // return element from array at given key
    return _value.object->at(key);
}


/*!
Returns the size of the JSON object.

@return the size of the JSON object; the size is the number of elements in
        compounds (array and object), 1 for value types (true, false, number,
        string), and 0 for null.

@invariant The size is reported as 0 if and only if empty() would return true.
*/
size_t JSON::size() const noexcept
{
    switch (_type)
    {
        case (value_type::array):
        {
            return _value.array->size();
        }
        case (value_type::object):
        {
            return _value.object->size();
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
bool JSON::empty() const noexcept
{
    switch (_type)
    {
        case (value_type::array):
        {
            return _value.array->empty();
        }
        case (value_type::object):
        {
            return _value.object->empty();
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
void JSON::clear() noexcept
{
    switch (_type)
    {
        case (value_type::array):
        {
            _value.array->clear();
            break;
        }
        case (value_type::object):
        {
            _value.object->clear();
            break;
        }
        case (value_type::string):
        {
            _value.string->clear();
            break;
        }
        case (value_type::boolean):
        {
            _value.boolean = {};
            break;
        }
        case (value_type::number):
        {
            _value.number = {};
            break;
        }
        case (value_type::number_float):
        {
            _value.number_float = {};
            break;
        }
        default:
        {
            break;
        }
    }
}

JSON::value_type JSON::type() const noexcept
{
    return _type;
}

JSON::iterator JSON::find(const std::string& key)
{
    return find(key.c_str());
}

JSON::const_iterator JSON::find(const std::string& key) const
{
    return find(key.c_str());
}

JSON::iterator JSON::find(const char* key)
{
    if (_type != value_type::object)
    {
        return end();
    }
    else
    {
        const object_t::iterator i = _value.object->find(key);
        if (i != _value.object->end())
        {
            JSON::iterator result(this);
            delete result._oi;
            result._oi = new object_t::iterator(i);
            return result;
        }
        else
        {
            return end();
        }
    }
}

JSON::const_iterator JSON::find(const char* key) const
{
    if (_type != value_type::object)
    {
        return end();
    }
    else
    {
        const object_t::const_iterator i = _value.object->find(key);
        if (i != _value.object->end())
        {
            JSON::const_iterator result(this);
            delete result._oi;
            result._oi = new object_t::const_iterator(i);
            return result;
        }
        else
        {
            return end();
        }
    }
}

bool JSON::operator==(const JSON& o) const noexcept
{
    switch (_type)
    {
        case (value_type::array):
        {
            if (o._type == value_type::array)
            {
                return *_value.array == *o._value.array;
            }
            break;
        }
        case (value_type::object):
        {
            if (o._type == value_type::object)
            {
                return *_value.object == *o._value.object;
            }
            break;
        }
        case (value_type::null):
        {
            if (o._type == value_type::null)
            {
                return true;
            }
            break;
        }
        case (value_type::string):
        {
            if (o._type == value_type::string)
            {
                return *_value.string == *o._value.string;
            }
            break;
        }
        case (value_type::boolean):
        {
            if (o._type == value_type::boolean)
            {
                return _value.boolean == o._value.boolean;
            }
            break;
        }
        case (value_type::number):
        {
            if (o._type == value_type::number)
            {
                return _value.number == o._value.number;
            }
            if (o._type == value_type::number_float)
            {
                return _value.number == static_cast<number_t>(o._value.number_float);
            }
            break;
        }
        case (value_type::number_float):
        {
            if (o._type == value_type::number)
            {
                return _value.number_float == static_cast<number_float_t>(o._value.number);
            }
            if (o._type == value_type::number_float)
            {
                return _value.number_float == o._value.number_float;
            }
            break;
        }
    }

    return false;
}

bool JSON::operator!=(const JSON& o) const noexcept
{
    return not operator==(o);
}


JSON::iterator JSON::begin() noexcept
{
    return JSON::iterator(this);
}

JSON::iterator JSON::end() noexcept
{
    return JSON::iterator();
}

JSON::const_iterator JSON::begin() const noexcept
{
    return JSON::const_iterator(this);
}

JSON::const_iterator JSON::end() const noexcept
{
    return JSON::const_iterator();
}

JSON::const_iterator JSON::cbegin() const noexcept
{
    return JSON::const_iterator(this);
}

JSON::const_iterator JSON::cend() const noexcept
{
    return JSON::const_iterator();
}


JSON::iterator::iterator(JSON* j) : _object(j)
{
    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            _vi = new array_t::iterator(_object->_value.array->begin());
        }
        if (_object->_type == value_type::object)
        {
            _oi = new object_t::iterator(_object->_value.object->begin());
        }
    }
}

JSON::iterator::iterator(const JSON::iterator& o) : _object(o._object)
{
    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            _vi = new array_t::iterator(*(o._vi));
        }
        if (_object->_type == value_type::object)
        {
            _oi = new object_t::iterator(*(o._oi));
        }
    }
}

JSON::iterator::~iterator()
{
    delete _vi;
    delete _oi;
}

JSON::iterator& JSON::iterator::operator=(JSON::iterator o)
{
    std::swap(_object, o._object);
    std::swap(_vi, o._vi);
    std::swap(_oi, o._oi);
    return *this;
}

bool JSON::iterator::operator==(const JSON::iterator& o) const
{
    if (_object != o._object)
    {
        return false;
    }

    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            return (_vi == o._vi);
        }
        if (_object->_type == value_type::object)
        {
            return (_oi == o._oi);
        }
    }

    return true;
}

bool JSON::iterator::operator!=(const JSON::iterator& o) const
{
    return not operator==(o);
}

JSON::iterator& JSON::iterator::operator++()
{
    // iterator cannot be incremented
    if (_object == nullptr)
    {
        return *this;
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            if (++(*_vi) == _object->_value.array->end())
            {
                _object = nullptr;
            }
            break;
        }
        case (value_type::object):
        {
            if (++(*_oi) == _object->_value.object->end())
            {
                _object = nullptr;
            }
            break;
        }
        default:
        {
            _object = nullptr;
        }
    }
    return *this;
}

JSON& JSON::iterator::operator*() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return **_vi;
        }
        case (value_type::object):
        {
            return (*_oi)->second;
        }
        default:
        {
            return *_object;
        }
    }
}

JSON* JSON::iterator::operator->() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return &(**_vi);
        }
        case (value_type::object):
        {
            return &((*_oi)->second);
        }
        default:
        {
            return _object;
        }
    }
}

std::string JSON::iterator::key() const
{
    if (_object != nullptr and _object->_type == value_type::object)
    {
        return (*_oi)->first;
    }
    else
    {
        throw std::out_of_range("cannot get key");
    }
}

JSON& JSON::iterator::value() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return **_vi;
        }
        case (value_type::object):
        {
            return (*_oi)->second;
        }
        default:
        {
            return *_object;
        }
    }
}


JSON::const_iterator::const_iterator(const JSON* j) : _object(j)
{
    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            _vi = new array_t::const_iterator(_object->_value.array->begin());
        }
        if (_object->_type == value_type::object)
        {
            _oi = new object_t::const_iterator(_object->_value.object->begin());
        }
    }
}

JSON::const_iterator::const_iterator(const JSON::const_iterator& o) : _object(o._object)
{
    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            _vi = new array_t::const_iterator(*(o._vi));
        }
        if (_object->_type == value_type::object)
        {
            _oi = new object_t::const_iterator(*(o._oi));
        }
    }
}

JSON::const_iterator::const_iterator(const JSON::iterator& o) : _object(o._object)
{
    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            _vi = new array_t::const_iterator(*(o._vi));
        }
        if (_object->_type == value_type::object)
        {
            _oi = new object_t::const_iterator(*(o._oi));
        }
    }
}

JSON::const_iterator::~const_iterator()
{
    delete _vi;
    delete _oi;
}

JSON::const_iterator& JSON::const_iterator::operator=(JSON::const_iterator o)
{
    std::swap(_object, o._object);
    std::swap(_vi, o._vi);
    std::swap(_oi, o._oi);
    return *this;
}

bool JSON::const_iterator::operator==(const JSON::const_iterator& o) const
{
    if (_object != o._object)
    {
        return false;
    }

    if (_object != nullptr)
    {
        if (_object->_type == value_type::array)
        {
            return (_vi == o._vi);
        }
        if (_object->_type == value_type::object)
        {
            return (_oi == o._oi);
        }
    }

    return true;
}

bool JSON::const_iterator::operator!=(const JSON::const_iterator& o) const
{
    return not operator==(o);
}

JSON::const_iterator& JSON::const_iterator::operator++()
{
    // iterator cannot be incremented
    if (_object == nullptr)
    {
        return *this;
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            if (++(*_vi) == _object->_value.array->end())
            {
                _object = nullptr;
            }
            break;
        }
        case (value_type::object):
        {
            if (++(*_oi) == _object->_value.object->end())
            {
                _object = nullptr;
            }
            break;
        }
        default:
        {
            _object = nullptr;
        }
    }
    return *this;
}

const JSON& JSON::const_iterator::operator*() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return **_vi;
        }
        case (value_type::object):
        {
            return (*_oi)->second;
        }
        default:
        {
            return *_object;
        }
    }
}

const JSON* JSON::const_iterator::operator->() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return &(**_vi);
        }
        case (value_type::object):
        {
            return &((*_oi)->second);
        }
        default:
        {
            return _object;
        }
    }
}

std::string JSON::const_iterator::key() const
{
    if (_object != nullptr and _object->_type == value_type::object)
    {
        return (*_oi)->first;
    }
    else
    {
        throw std::out_of_range("cannot get key");
    }
}

const JSON& JSON::const_iterator::value() const
{
    // dereferencing end() is an error
    if (_object == nullptr)
    {
        throw std::out_of_range("cannot get value");
    }

    switch (_object->_type)
    {
        case (value_type::array):
        {
            return **_vi;
        }
        case (value_type::object):
        {
            return (*_oi)->second;
        }
        default:
        {
            return *_object;
        }
    }
}


/*!
Initialize the JSON parser given a string \p s.

@note After initialization, the function @ref parse has to be called manually.

@param s  string to parse

@post \p s is copied to the buffer @ref _buffer and the firsr character is
      read. Whitespace is skipped.
*/
JSON::Parser::Parser(const char* s)
    : _length(std::strlen(s)), _buffer(new char[_length + 1])
{
    std::strcpy(_buffer, s);

    // read first character
    next();
}

/*!
@copydoc JSON::Parser::Parser(const char* s)
*/
JSON::Parser::Parser(const std::string& s)
    : _length(s.length()), _buffer(new char[_length + 1])
{
    std::strcpy(_buffer, s.c_str());

    // read first character
    next();
}

/*!
Initialize the JSON parser given an input stream \p _is.

@note After initialization, the function @ref parse has to be called manually.

\param _is input stream to parse

@post \p _is is copied to the buffer @ref _buffer and the firsr character is
      read. Whitespace is skipped.

*/
JSON::Parser::Parser(std::istream& _is)
{
    // copy stream to string
    std::string input_line, string_input;

    // from http://www.manticmoo.com/articles/jeff/programming/c++/making-io-streams-efficient-in-c++.php
    //  Don't sync C++ and C I/O
    std::ios_base::sync_with_stdio(false);
    while (_is)
    {
        std::getline(_is, input_line);
        string_input += input_line;
    }

    _length = string_input.size();
    _buffer = new char[_length + 1];
    std::strcpy(_buffer, string_input.c_str());

    // read first character
    next();
}

/*!
@post Memory allocated for @ref _buffer (by the constructors) is released.
*/
JSON::Parser::~Parser()
{
    delete [] _buffer;
}

/*!
@param[out] result  the JSON to parse to
*/
void JSON::Parser::parse(JSON& result)
{
    switch (_current)
    {
        case ('{'):
        {
            // explicitly set result to object to cope with {}
            result._type = value_type::object;
            result._value.object = new object_t;

            next();

            // process nonempty object
            if (_current != '}')
            {
                do
                {
                    // key
                    const auto key = parseString();

                    // colon
                    expect(':');

                    // value
                    parse(result[key]);
                }
                while (_current == ',' && next());
            }

            // closing brace
            expect('}');

            break;
        }

        case ('['):
        {
            // explicitly set result to array to cope with []
            result._type = value_type::array;
            result._value.array = new array_t;

            next();

            // process nonempty array
            if (_current != ']')
            {
                size_t element_count = 0;
                do
                {
                    // add a dummy value and continue parsing at its position
                    result += JSON();
                    parse(result[element_count++]);
                }
                while (_current == ',' && next());
            }

            // closing bracket
            expect(']');

            break;
        }

        case ('\"'):
        {
            result._type = value_type::string;
            result._value.string = new string_t(std::move(parseString()));
            break;
        }

        case ('t'):
        {
            parseTrue();
            result._type = value_type::boolean;
            result._value.boolean = true;
            break;
        }

        case ('f'):
        {
            parseFalse();
            result._type = value_type::boolean;
            result._value.boolean = false;
            break;
        }

        case ('n'):
        {
            parseNull();
            // nothing to do with result: is null by default
            break;
        }

        default:
        {
            if (std::isdigit(_current) || _current == '-')
            {
                // collect number in tmp string
                std::string tmp;
                do
                {
                    tmp += _current;
                }
                while (next() && (std::isdigit(_current) || _current == '.'
                                  || _current == 'e' || _current == 'E'
                                  || _current == '+' || _current == '-'));

                try
                {
                    const auto float_val = std::stod(tmp);
                    const auto int_val = static_cast<int>(float_val);

                    // check if conversion loses precision
                    if (float_val == int_val)
                    {
                        // we would not lose precision -> int
                        result._type = value_type::number;
                        result._value.number = int_val;
                    }
                    else
                    {
                        // we would lose precision -> float
                        result._type = value_type::number_float;
                        result._value.number_float = float_val;
                    }
                }
                catch (...)
                {
                    error("error while translating " + tmp + " to number");
                }

                break;
            }
            else
            {
                error("unexpected character");
            }
        }
    }
}

/*!
This function reads the next character from the buffer while ignoring all
trailing whitespace. If another character could be read, the function returns
true. If the end of the buffer is reached, false is returned.

@return whether another non-whitespace character could be read

@post _current holds the next character
*/
bool JSON::Parser::next()
{
    if (_pos == _length)
    {
        return false;
    }

    _current = _buffer[_pos++];

    // skip trailing whitespace
    while (std::isspace(_current))
    {
        if (_pos == _length)
        {
            return false;
        }

        _current = _buffer[_pos++];
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
void JSON::Parser::error(const std::string& msg)
{
    throw std::invalid_argument("parse error at position " +
                                std::to_string(_pos) + ": " + msg +
                                ", last read: '" + _current + "'");
}

/*!
Parses a string after opening quotes (\p ") where read.

@return the parsed string

@pre  An opening quote \p " was read in the main parse function @ref parse.

@post The character after the closing quote \p " is the current character @ref
      _current. Whitespace is skipped.
*/
std::string JSON::Parser::parseString()
{
    // get position of closing quotes
    char* p = std::strchr(_buffer + _pos, '\"');

    // if the closing quotes are escaped (viz. *(p-1) is '\\'), we continue
    // looking for the "right" quotes
    while (p != nullptr and * (p - 1) == '\\')
    {
        // length of the string so far
        const size_t length = static_cast<size_t>(p - _buffer) - _pos;
        // continue checking after escaped quote
        p = std::strchr(_buffer + _pos + length + 1, '\"');
    }

    // check if closing quotes were found
    if (p == nullptr)
    {
        error("expected '\"'");
    }

    // copy string to return value
    const size_t length = static_cast<size_t>(p - _buffer) - _pos;
    const std::string result(_buffer + _pos, length);

    // +1 to "eat" closing quote
    _pos += length + 1;

    // read next character
    next();

    return result;
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
void JSON::Parser::parseTrue()
{
    if (std::strncmp(_buffer + _pos, "rue", 3))
    {
        error("expected true");
    }

    _pos += 3;

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
void JSON::Parser::parseFalse()
{
    if (std::strncmp(_buffer + _pos, "alse", 4))
    {
        error("expected false");
    }

    _pos += 4;

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
void JSON::Parser::parseNull()
{
    if (std::strncmp(_buffer + _pos, "ull", 3))
    {
        error("expected null");
    }

    _pos += 3;

    // read next character
    next();
}

/*!
This function wraps functionality to check whether the current character @ref
_current matches a given character \p c. In case of a match, the next character
of the buffer @ref _buffer is read. In case of a mismatch, an error is raised
via @ref error.

@param c  character that is expected

@post The next chatacter is read. Whitespace is skipped.
*/
void JSON::Parser::expect(const char c)
{
    if (_current != c)
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

/*!
This operator implements a user-defined string literal for JSON objects. It can
be used by adding \p "_json" to a string literal and returns a JSON object if
no parse error occurred.

@param s  a string representation of a JSON object
@return a JSON object
*/
JSON operator "" _json(const char* s, size_t)
{
    return JSON::parse(s);
}
