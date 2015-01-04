/*!
@file
@copyright The code is licensed under the MIT License
           <http://opensource.org/licenses/MIT>,
           Copyright (c) 2013-2014 Niels Lohmann.

@author Niels Lohmann <http://nlohmann.me>

@see https://github.com/nlohmann/json
*/

#include "json.h"

#include <cctype>     // std::isdigit, std::isspace
#include <cstddef>    // size_t
#include <stdexcept>  // std::runtime_error
#include <utility>    // std::swap, std::move


////////////////////
// STATIC MEMBERS //
////////////////////

std::mutex json::_token;


///////////////////////////////////
// CONSTRUCTORS OF UNION "value" //
///////////////////////////////////

json::value::value(array_t* _array): array(_array) {}
json::value::value(object_t* _object): object(_object) {}
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
json::json(const value_type t) noexcept
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
json::json(std::nullptr_t) noexcept : json()
{}

/*!
Construct a string JSON object.

@param s  a string to initialize the JSON object with
*/
json::json(const std::string& s) noexcept
    : _type(value_type::string), _value(new string_t(s))
{}

json::json(std::string&& s) noexcept
    : _type(value_type::string), _value(new string_t(std::move(s)))
{}

json::json(const char* s) noexcept
    : _type(value_type::string), _value(new string_t(s))
{}

json::json(const bool b) noexcept
    : _type(value_type::boolean), _value(b)
{}

json::json(const int i) noexcept
    : _type(value_type::number), _value(i)
{}

json::json(const double f) noexcept
    : _type(value_type::number_float), _value(f)
{}

json::json(const array_t& a) noexcept
    : _type(value_type::array), _value(new array_t(a))
{}

json::json(array_t&& a) noexcept
    : _type(value_type::array), _value(new array_t(std::move(a)))
{}

json::json(const object_t& o) noexcept
    : _type(value_type::object), _value(new object_t(o))
{}

json::json(object_t&& o) noexcept
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
json::json(list_init_t a) noexcept
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
    for (const json& element : a)
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
json::json(const json& o) noexcept
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
json::json(json&& o) noexcept
    : _type(std::move(o._type)), _value(std::move(o._value))
{
    // invalidate payload
    o._type = value_type::null;
    o._value = {};
}

/*!
A copy assignment operator for the JSON class, following the copy-and-swap
idiom.

@param o  A JSON object to assign to this object.
*/
json& json::operator=(json o) noexcept
{
    std::swap(_type, o._type);
    std::swap(_value, o._value);
    return *this;
}

json::~json() noexcept
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


const std::string json::_typename() const noexcept
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
std::string json::get() const
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
int json::get() const
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
double json::get() const
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
bool json::get() const
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
json::array_t json::get() const
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
json::object_t json::get() const
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

json::operator const std::string() const
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

const std::string json::toString() const noexcept
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
void json::push_back(json&& o)
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
const json& json::operator[](const int index) const
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
json& json::at(const int index)
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
const json& json::at(const int index) const
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
        (*_value.object)[key] = json();
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
const json& json::operator[](const std::string& key) const
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
size_t json::size() const noexcept
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
bool json::empty() const noexcept
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
void json::clear() noexcept
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

json::value_type json::type() const noexcept
{
    return _type;
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
    if (_type != value_type::object)
    {
        return end();
    }
    else
    {
        const object_t::iterator i = _value.object->find(key);
        if (i != _value.object->end())
        {
            json::iterator result(this);
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

json::const_iterator json::find(const char* key) const
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
            json::const_iterator result(this);
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

bool json::operator==(const json& o) const noexcept
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


json::iterator::iterator(json* j) : _object(j)
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

json::iterator::iterator(const json::iterator& o) : _object(o._object)
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

json::iterator::~iterator()
{
    delete _vi;
    delete _oi;
}

json::iterator& json::iterator::operator=(json::iterator o)
{
    std::swap(_object, o._object);
    std::swap(_vi, o._vi);
    std::swap(_oi, o._oi);
    return *this;
}

bool json::iterator::operator==(const json::iterator& o) const
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

bool json::iterator::operator!=(const json::iterator& o) const
{
    return not operator==(o);
}

json::iterator& json::iterator::operator++()
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

json& json::iterator::operator*() const
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

json* json::iterator::operator->() const
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

std::string json::iterator::key() const
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

json& json::iterator::value() const
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


json::const_iterator::const_iterator(const json* j) : _object(j)
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

json::const_iterator::const_iterator(const json::const_iterator& o) : _object(o._object)
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

json::const_iterator::const_iterator(const json::iterator& o) : _object(o._object)
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

json::const_iterator::~const_iterator()
{
    delete _vi;
    delete _oi;
}

json::const_iterator& json::const_iterator::operator=(json::const_iterator o)
{
    std::swap(_object, o._object);
    std::swap(_vi, o._vi);
    std::swap(_oi, o._oi);
    return *this;
}

bool json::const_iterator::operator==(const json::const_iterator& o) const
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

bool json::const_iterator::operator!=(const json::const_iterator& o) const
{
    return not operator==(o);
}

json::const_iterator& json::const_iterator::operator++()
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

const json& json::const_iterator::operator*() const
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

const json* json::const_iterator::operator->() const
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

std::string json::const_iterator::key() const
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

const json& json::const_iterator::value() const
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

@post \p s is copied to the buffer @ref _buffer and the first character is
      read. Whitespace is skipped.
*/
json::parser::parser(const char* s)
    :  _buffer(s)
{
    // read first character
    next();
}

/*!
@copydoc json::parser::parser(const char* s)
*/
json::parser::parser(const std::string& s)
    : _buffer(s)
{
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
json::parser::parser(std::istream& _is)
{
    while (_is)
    {
        std::string input_line;
        std::getline(_is, input_line);
        _buffer += input_line;
    }

    // read first character
    next();
}

json json::parser::parse()
{
    switch (_current)
    {
        case ('{'):
        {
            // explicitly set result to object to cope with {}
            json result(value_type::object);

            next();

            // process nonempty object
            if (_current != '}')
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
                while (_current == ',' and next());
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
            if (_current != ']')
            {
                do
                {
                    result.push_back(parse());
                }
                while (_current == ',' and next());
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
            const auto _first_pos = _pos - 1;

            while (next() and (std::isdigit(_current) || _current == '.'
                               || _current == 'e' || _current == 'E'
                               || _current == '+' || _current == '-'));

            try
            {
                const auto float_val = std::stod(_buffer.substr(_first_pos, _pos - _first_pos));
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
                      _buffer.substr(_first_pos, _pos - _first_pos) + " to number");
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

@post _current holds the next character
*/
bool json::parser::next()
{
    if (_pos == _buffer.size())
    {
        return false;
    }

    _current = _buffer[_pos++];

    // skip trailing whitespace
    while (std::isspace(_current))
    {
        if (_pos == _buffer.size())
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
void json::parser::error(const std::string& msg)
{
    throw std::invalid_argument("parse error at position " +
                                std::to_string(_pos) + ": " + msg +
                                ", last read: '" + _current + "'");
}

/*!
Parses a string after opening quotes (\p ") where read.

@return the parsed string

@pre  An opening quote \p " was read in the main parse function @ref parse.
      _pos is the position after the opening quote.

@post The character after the closing quote \p " is the current character @ref
      _current. Whitespace is skipped.
*/
std::string json::parser::parseString()
{
    // get position of closing quotes
    auto quote_pos = _buffer.find_first_of("\"", _pos);

    // if the closing quotes are escaped (character before the quotes is a
    // backslash), we continue looking for the final quotes
    while (quote_pos != std::string::npos and _buffer[quote_pos - 1] == '\\')
    {
        quote_pos = _buffer.find_first_of("\"", quote_pos + 1);
    }

    // check if closing quotes were found
    if (quote_pos == std::string::npos)
    {
        error("expected '\"'");
    }

    // store the coordinates of the string for the later return value
    const auto stringBegin = _pos;
    const auto stringLength = quote_pos - _pos;

    // set buffer position to the position behind (+1) the closing quote
    _pos = quote_pos + 1;

    // read next character
    next();

    // return the string value
    return _buffer.substr(stringBegin, stringLength);
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
    if (_buffer.substr(_pos, 3) != "rue")
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
void json::parser::parseFalse()
{
    if (_buffer.substr(_pos, 4) != "alse")
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
void json::parser::parseNull()
{
    if (_buffer.substr(_pos, 3) != "ull")
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
void json::parser::expect(const char c)
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
json operator "" _json(const char* s, size_t)
{
    return json::parse(s);
}
