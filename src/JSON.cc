#include "JSON.h"

#include <utility>
#include <stdexcept>
#include <fstream>
#include <cctype>
#include <iostream>
#include <streambuf>
#include <sstream>
#include <cstring>
#include <cstdlib>

// allow us to use "nullptr" everywhere
#include <cstddef>
#ifndef nullptr
#define nullptr NULL
#endif


/////////////////////
// HELPER FUNCTION //
/////////////////////

#ifndef __cplusplus11
inline std::string int_to_string(int i) {
    std::stringstream s;
    s << i;
    return s.str();
}
#endif


////////////////////
// STATIC MEMBERS //
////////////////////

#ifdef __cplusplus11
/// a mutex to ensure thread safety
std::mutex JSON::_token;
#endif


/////////////////////////////////
// CONSTRUCTORS AND DESTRUCTOR //
/////////////////////////////////

JSON::JSON() : _type(null) {}

JSON::JSON(json_t type) : _type(type) {
    switch (_type) {
        case (array): {
            _value.array = new array_t();
            break;
        }
        case (object): {
            _value.object = new object_t();
            break;
        }
        case (string): {
            _value.string = new string_t();
            break;
        }
        case (boolean): {
            _value.boolean = false;
            break;
        }
        case (number): {
            _value.number = 0;
            break;
        }
        case (number_float): {
            _value.number_float = 0.0;
            break;
        }
        case (null): {
            break;
        }
    }
}

JSON::JSON(const std::string& s) : _type(string), _value(new string_t(s)) {}
JSON::JSON(const char* s) : _type(string), _value(new string_t(s)) {}
JSON::JSON(char* s) : _type(string), _value(new string_t(s)) {}
JSON::JSON(const bool b) : _type(boolean), _value(b) {}
JSON::JSON(const int i) : _type(number), _value(i) {}
JSON::JSON(const double f) : _type(number_float), _value(f) {}
JSON::JSON(array_t a) : _type(array), _value(new array_t(a)) {}
JSON::JSON(object_t o) : _type(object), _value(new object_t(o)) {}

#ifdef __cplusplus11
JSON::JSON(array_init_t a) : _type(array), _value(new array_t(a)) {}
#endif

/// copy constructor
JSON::JSON(const JSON& o) : _type(o._type) {
    switch (_type) {
        case (array): {
            _value.array = new array_t(*o._value.array);
            break;
        }
        case (object): {
            _value.object = new object_t(*o._value.object);
            break;
        }
        case (string): {
            _value.string = new string_t(*o._value.string);
            break;
        }
        case (boolean): {
            _value.boolean = o._value.boolean;
            break;
        }
        case (number): {
            _value.number = o._value.number;
            break;
        }
        case (number_float): {
            _value.number_float = o._value.number_float;
            break;
        }
        case (null): {
            break;
        }
    }
}

#ifdef __cplusplus11
/// move constructor
JSON::JSON(JSON&& o) : _type(std::move(o._type)), _value(std::move(o._value)) {}
#endif

/// copy assignment
#ifdef __cplusplus11
JSON& JSON::operator=(JSON o) {
    std::swap(_type, o._type);
    std::swap(_value, o._value);
    return *this;
}
#else
JSON& JSON::operator=(const JSON& o) {
    // check for self-assignment
    if (&o == this) {
        return *this;
    }

    // first delete original value
    switch (_type) {
        case (array): {
            delete _value.array;
            break;
        }
        case (object): {
            delete _value.object;
            break;
        }
        case (string): {
            delete _value.string;
            break;
        }
        case (boolean): {
            break;
        }
        case (number): {
            break;
        }
        case (number_float): {
            break;
        }
        case (null): {
            break;
        }
    }

    // then copy given value from o
    _type = o._type;
    switch (_type) {
        case (array): {
            _value.array = new array_t(*o._value.array);
            break;
        }
        case (object): {
            _value.object = new object_t(*o._value.object);
            break;
        }
        case (string): {
            _value.string = new string_t(*o._value.string);
            break;
        }
        case (boolean): {
            _value.boolean = o._value.boolean;
            break;
        }
        case (number): {
            _value.number = o._value.number;
            break;
        }
        case (number_float): {
            _value.number_float = o._value.number_float;
            break;
        }
        case (null): {
            break;
        }
    }

    return *this;
}
#endif

/// destructor
JSON::~JSON() {
    switch (_type) {
        case (array): {
            delete _value.array;
            break;
        }
        case (object): {
            delete _value.object;
            break;
        }
        case (string): {
            delete _value.string;
            break;
        }
        case (boolean): {
            break;
        }
        case (number): {
            break;
        }
        case (number_float): {
            break;
        }
        case (null): {
            break;
        }
    }
}


///////////////////////////////
// OPERATORS AND CONVERSIONS //
///////////////////////////////

JSON::operator const std::string() const {
    switch (_type) {
        case (string):
            return *_value.string;
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON string");
    }
}


JSON::operator int() const {
    switch (_type) {
        case (number):
            return _value.number;
        case (number_float):
            return static_cast<number_t>(_value.number_float);
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON number");
    }
}

JSON::operator double() const {
    switch (_type) {
        case (number):
            return static_cast<number_float_t>(_value.number);
        case (number_float):
            return _value.number_float;
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON number");
    }
}

JSON::operator bool() const {
    switch (_type) {
        case (boolean):
            return _value.boolean;
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON Boolean");
    }
}

JSON::operator std::vector<JSON>() const {
    if (_type == array) {
        return *_value.array;
    }
    if (_type == object) {
        throw std::runtime_error("cannot cast " + _typename() + " to JSON array");
    }

    std::vector<JSON> result;
    result.push_back(*this);
    return result;
}

JSON::operator std::map<std::string, JSON>() const {
    if (_type == object) {
        return *_value.object;
    } else {
        throw std::runtime_error("cannot cast " + _typename() + " to JSON object");
    }
}

const std::string JSON::toString() const {
    switch (_type) {
        case (null): {
            return "null";
        }

        case (string): {
            return std::string("\"") + *_value.string + "\"";
        }

        case (boolean): {
            return _value.boolean ? "true" : "false";
        }

        case (number): {
#ifdef __cplusplus11
            return std::to_string(_value.number);
#else
            std::stringstream s;
            s << _value.number;
            return s.str();
#endif
        }

        case (number_float): {
#ifdef __cplusplus11
            return std::to_string(_value.number_float);
#else
            std::stringstream s;
            s << _value.number_float;
            return s.str();
#endif
        }

        case (array): {
            std::string result;

            for (array_t::const_iterator i = _value.array->begin(); i != _value.array->end(); ++i) {
                if (i != _value.array->begin()) {
                    result += ", ";
                }
                result += (*i).toString();
            }

            return "[" + result + "]";
        }

        case (object): {
            std::string result;

            for (object_t::const_iterator i = _value.object->begin(); i != _value.object->end(); ++i) {
                if (i != _value.object->begin()) {
                    result += ", ";
                }
                result += "\"" + i->first + "\": " + (i->second).toString();
            }

            return "{" + result + "}";
        }
    }
}


///////////////////////////////////////////
// ADDING ELEMENTS TO OBJECTS AND ARRAYS //
///////////////////////////////////////////

JSON& JSON::operator+=(const JSON& o) {
    push_back(o);
    return *this;
}

JSON& JSON::operator+=(const std::string& s) {
    push_back(JSON(s));
    return *this;
}

JSON& JSON::operator+=(const char* s) {
    push_back(JSON(s));
    return *this;
}

JSON& JSON::operator+=(bool b) {
    push_back(JSON(b));
    return *this;
}

JSON& JSON::operator+=(int i) {
    push_back(JSON(i));
    return *this;
}

JSON& JSON::operator+=(double f) {
    push_back(JSON(f));
    return *this;
}

void JSON::push_back(const JSON& o) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (not(_type == null or _type == array)) {
        throw std::runtime_error("cannot add element to " + _typename());
    }

    if (_type == null) {
        _type = array;
        _value.array = new array_t;
    }

    _value.array->push_back(o);
}

void JSON::push_back(const std::string& s) {
    push_back(JSON(s));
}

void JSON::push_back(const char* s) {
    push_back(JSON(s));
}

void JSON::push_back(bool b) {
    push_back(JSON(b));
}

void JSON::push_back(int i) {
    push_back(JSON(i));
}

void JSON::push_back(double f) {
    push_back(JSON(f));
}

/// operator to set an element in an object
JSON& JSON::operator[](int index) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type != array) {
#ifdef __cplusplus11
        throw std::runtime_error("cannot add entry with index " + std::to_string(index) + " to " + _typename());
#else
        throw std::runtime_error("cannot add entry with index " + int_to_string(index) + " to " + _typename());
#endif
    }

    if (index >= (int)_value.array->size()) {
#ifdef __cplusplus11
        throw std::runtime_error("cannot access element at index " + std::to_string(index));
#else
        throw std::runtime_error("cannot access element at index " + int_to_string(index));
#endif
    }

    return _value.array->at(index);
}

/// operator to get an element in an object
const JSON& JSON::operator[](const int index) const {
    if (_type != array) {
#ifdef __cplusplus11
        throw std::runtime_error("cannot get entry with index " + std::to_string(index) + " from " + _typename());
#else
        throw std::runtime_error("cannot get entry with index " + int_to_string(index) + " from " + _typename());
#endif
    }

    if (index >= (int)_value.array->size()) {
#ifdef __cplusplus11
        throw std::runtime_error("cannot access element at index " + std::to_string(index));
#else
        throw std::runtime_error("cannot access element at index " + int_to_string(index));
#endif
    }

    return _value.array->at(index);
}

/// operator to set an element in an object
JSON& JSON::operator[](const std::string& key) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type == null) {
        _type = object;
        _value.object = new object_t;
    }

    if (_type != object) {
        throw std::runtime_error("cannot add entry with key " + std::string(key) + " to " + _typename());
    }

    if (_value.object->find(key) == _value.object->end()) {
        (*_value.object)[key] = JSON();
    }

    return (*_value.object)[key];
}

/// operator to set an element in an object
JSON& JSON::operator[](const char* key) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type == null) {
        _type = object;
        _value.object = new object_t;
    }

    if (_type != object) {
        throw std::runtime_error("cannot add entry with key " + std::string(key) + " to " + _typename());
    }

    if (_value.object->find(key) == _value.object->end()) {
        (*_value.object)[key] = JSON();
    }

    return (*_value.object)[key];
}

/// operator to get an element in an object
const JSON& JSON::operator[](const std::string& key) const {
    if (_type != object) {
        throw std::runtime_error("cannot get entry with key " + std::string(key) + " from " + _typename());
    }

    if (_value.object->find(key) == _value.object->end()) {
        throw std::runtime_error("key " + key + " not found");
    } else {
        return _value.object->find(key)->second;
    }
}

/// return the number of stored values
size_t JSON::size() const {
    switch (_type) {
        case (array): {
            return _value.array->size();
        }
        case (object): {
            return _value.object->size();
        }
        case (null): {
            return 0;
        }
        case (string): {
            return 1;
        }
        case (boolean): {
            return 1;
        }
        case (number): {
            return 1;
        }
        case (number_float): {
            return 1;
        }
    }
}

/// checks whether object is empty
bool JSON::empty() const {
    switch (_type) {
        case (array): {
            return _value.array->empty();
        }
        case (object): {
            return _value.object->empty();
        }
        case (null): {
            return true;
        }
        case (string): {
            return false;
        }
        case (boolean): {
            return false;
        }
        case (number): {
            return false;
        }
        case (number_float): {
            return false;
        }
    }
}

/// return the type of the object
JSON::json_t JSON::type() const {
    return _type;
}

JSON::iterator JSON::find(const std::string& key) {
    return find(key.c_str());
}

JSON::const_iterator JSON::find(const std::string& key) const {
    return find(key.c_str());
}

JSON::iterator JSON::find(const char* key) {
    if (_type != object) {
        return end();
    } else {
        const object_t::iterator i = _value.object->find(key);
        if (i != _value.object->end()) {
            JSON::iterator result;
            result._object = this;
            result._oi = new object_t::iterator(i);
            return result;
        } else {
            return end();
        }
    }
}

JSON::const_iterator JSON::find(const char* key) const {
    if (_type != object) {
        return end();
    } else {
        const object_t::const_iterator i = _value.object->find(key);
        if (i != _value.object->end()) {
            JSON::const_iterator result;
            result._object = this;
            result._oi = new object_t::const_iterator(i);
            return result;
        } else {
            return end();
        }
    }
}

/// direct access to the underlying payload
JSON::value JSON::data() {
    return _value;
}

/// direct access to the underlying payload
const JSON::value JSON::data() const {
    return _value;
}

/// lexicographically compares the values
bool JSON::operator==(const JSON& o) const {
    switch (_type) {
        case (array): {
            if (o._type == array) {
                return *_value.array == *o._value.array;
            }
        }
        case (object): {
            if (o._type == object) {
                return *_value.object == *o._value.object;
            }
        }
        case (null): {
            if (o._type == null) {
                return true;
            }
        }
        case (string): {
            if (o._type == string) {
                return *_value.string == *o._value.string;
            }
        }
        case (boolean): {
            if (o._type == boolean) {
                return _value.boolean == o._value.boolean;
            }
        }
        case (number): {
            if (o._type == number) {
                return _value.number == o._value.number;
            }
            if (o._type == number_float) {
                return _value.number == static_cast<number_t>(o._value.number_float);
            }
        }
        case (number_float): {
            if (o._type == number) {
                return _value.number_float == static_cast<number_float_t>(o._value.number);
            }
            if (o._type == number_float) {
                return _value.number_float == o._value.number_float;
            }
        }
    }

    return false;
}

/// lexicographically compares the values
bool JSON::operator!=(const JSON& o) const {
    return not operator==(o);
}


/// return the type as string
std::string JSON::_typename() const {
    switch (_type) {
        case (array): {
            return "array";
        }
        case (object): {
            return "object";
        }
        case (null): {
            return "null";
        }
        case (string): {
            return "string";
        }
        case (boolean): {
            return "boolean";
        }
        case (number): {
            return "number";
        }
        case (number_float): {
            return "number";
        }
    }
}


JSON::parser::parser(char* s) : _pos(0) {
    _length = std::strlen(s);
    _buffer = new char[_length + 1];
    std::strcpy(_buffer, s);

    // read first character
    next();
}

JSON::parser::parser(std::string& s) : _pos(0) {
    _length = s.length();
    _buffer = new char[_length + 1];
    std::strcpy(_buffer, s.c_str());

    // read first character
    next();
}

JSON::parser::parser(std::istream& _is) : _pos(0) {
    // determine length of input stream
    _is.seekg(0, std::ios::end);
    _length = _is.tellg();
    _is.seekg(0, std::ios::beg);

    // copy stream to buffer
    _buffer = new char[_length + 1];
    _is.read(_buffer, _length);

    // read first character
    next();
}

JSON::parser::~parser() {
    delete [] _buffer;
}

void JSON::parser::error(std::string msg = "") {
#ifdef __cplusplus11
    throw std::runtime_error("parse error at position " + std::to_string(_pos) + ": " + msg + ", last read: '" + _current + "'");
#else
    throw std::runtime_error("parse error at position " + int_to_string(_pos) + ": " + msg + ", last read: '" + _current + "'");
#endif
}

bool JSON::parser::next() {
    if (_pos == _length) {
        return false;
    }

    _current = _buffer[_pos++];

    // skip trailing whitespace
    while (std::isspace(_current)) {
        if (_pos == _length) {
            return false;
        }

        _current = _buffer[_pos++];
    }

    return true;
}

std::string JSON::parser::parseString() {
    // get position of closing quotes
    char* p = std::strchr(_buffer + _pos, '\"');

    // if the closing quotes are escaped (viz. *(p-1) is '\\'),
    // we continue looking for the "right" quotes
    while (p != nullptr and * (p - 1) == '\\') {
        // length of the string so far
        const size_t length = p - _buffer - _pos;
        // continue checking after escaped quote
        p = std::strchr(_buffer + _pos + length + 1, '\"');
    }

    // check if closing quotes were found
    if (p == nullptr) {
        error("expected '\"'");
    }

    // copy string to return value
    const size_t length = p - _buffer - _pos;
    char* tmp = new char[length + 1];
    std::strncpy(tmp, _buffer + _pos, length);
    tmp[length] = 0;
    std::string result(tmp);
    delete [] tmp;

    // +1 to eat closing quote
    _pos += length + 1;

    // read next character
    next();

    return result;
}

void JSON::parser::parseTrue() {
    if (std::strncmp(_buffer + _pos, "rue", 3)) {
        error("expected true");
    }

    _pos += 3;

    // read next character
    next();
}

void JSON::parser::parseFalse() {
    if (std::strncmp(_buffer + _pos, "alse", 4)) {
        error("expected false");
    }

    _pos += 4;

    // read next character
    next();
}

void JSON::parser::parseNull() {
    if (std::strncmp(_buffer + _pos, "ull", 3)) {
        error("expected null");
    }

    _pos += 3;

    // read next character
    next();
}

void JSON::parser::expect(char c) {
    if (_current != c) {
        std::string msg = "expected '";
        msg.append(1, c);
        msg += "'";
        error(msg.c_str());
    } else {
        next();
    }
}

void JSON::parser::parse(JSON& result) {
    if (!_buffer) {
        error("unexpected end of file");
    }

    switch (_current) {
        case ('{'): {
            // explicitly set result to object to cope with {}
            result._type = object;
            result._value.object = new object_t;

            next();

            // process nonempty object
            if (_current != '}') {
                do {
                    // key
                    const std::string key = parseString();

                    // colon
                    expect(':');

                    // value
                    parse(result[key]);
                } while (_current == ',' && next());
            }

            // closing brace
            expect('}');

            break;
        }

        case ('['): {
            // explicitly set result to array to cope with []
            result._type = array;
            result._value.array = new array_t;

            next();

            // process nonempty array
            if (_current != ']') {
                size_t element_count = 0;
                do {
                    // add a dummy value and continue parsing at its position
                    result += JSON();
                    parse(result[element_count++]);
                } while (_current == ',' && next());
            }

            // closing bracket
            expect(']');

            break;
        }

        case ('\"'): {
            result._type = string;
            result._value.string = new string_t(parseString());
            break;
        }

        case ('t'): {
            parseTrue();
            result._type = boolean;
            result._value.boolean = true;
            break;
        }

        case ('f'): {
            parseFalse();
            result._type = boolean;
            result._value.boolean = false;
            break;
        }

        case ('n'): {
            parseNull();
            // nothing to do with result: is null by default
            break;
        }

        default: {
            if (std::isdigit(_current) || _current == '-') {
                // collect number in tmp string
                std::string tmp;
                do {
                    tmp += _current;
                    next();
                } while (std::isdigit(_current) || _current == '.' || _current == 'e' || _current == 'E' || _current == '+' || _current == '-');

                if (tmp.find(".") == std::string::npos) {
                    // integer (we use atof, because it can cope with e)
                    result._type = number;
                    result._value.number = std::atof(tmp.c_str());
                } else {
                    // float
                    result._type = number_float;
                    result._value.number_float = std::atof(tmp.c_str());
                }
                break;
            } else {
                error("unexpected character");
            }
        }
    }
}



// http://stackoverflow.com/questions/7758580/writing-your-own-stl-container/7759622#7759622

JSON::iterator JSON::begin() {
    return JSON::iterator(this);
}
JSON::iterator JSON::end() {
    return JSON::iterator();
}

JSON::iterator::iterator() : _object(nullptr), _vi(nullptr), _oi(nullptr) {}

JSON::iterator::iterator(JSON* j) : _object(j), _vi(nullptr), _oi(nullptr) {
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::iterator(_object->_value.array->begin());
                break;
            }
            case (object): {
                _oi = new object_t::iterator(_object->_value.object->begin());
                break;
            }
            default: {
                break;
            }
        }
}

JSON::iterator::iterator(const JSON::iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::iterator(*(o._vi));
                break;
            }
            case (object): {
                _oi = new object_t::iterator(*(o._oi));
                break;
            }
            default: {
                break;
            }
        }
}

JSON::iterator::~iterator() {
    delete _vi;
    delete _oi;
}

JSON::iterator& JSON::iterator::operator=(const JSON::iterator& o) {
    _object = o._object;
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::iterator(*(o._vi));
                break;
            }
            case (object): {
                _oi = new object_t::iterator(*(o._oi));
                break;
            }
            default: {
                break;
            }
        }
    return *this;
}

bool JSON::iterator::operator==(const JSON::iterator& o) const {
    return _object == o._object;
}

bool JSON::iterator::operator!=(const JSON::iterator& o) const {
    return _object != o._object;
}


JSON::iterator& JSON::iterator::operator++() {
    // iterator cannot be incremented
    if (_object == nullptr) {
        return *this;
    }

    switch (_object->_type) {
        case (array): {
            if (++(*_vi) == _object->_value.array->end()) {
                _object = nullptr;
            }
            break;
        }
        case (object): {
            if (++(*_oi) == _object->_value.object->end()) {
                _object = nullptr;
            }
            break;
        }
        default: {
            _object = nullptr;
        }
    }
    return *this;
}

JSON& JSON::iterator::operator*() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return **_vi;
        }
        case (object): {
            return (*_oi)->second;
        }
        default: {
            return *_object;
        }
    }
}

JSON* JSON::iterator::operator->() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return &(**_vi);
        }
        case (object): {
            return &((*_oi)->second);
        }
        default: {
            return _object;
        }
    }
}

std::string JSON::iterator::key() const {
    if (_object != nullptr and _object->_type == object) {
        return (*_oi)->first;
    } else {
        throw std::runtime_error("cannot get key");
    }
}

JSON& JSON::iterator::value() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return **_vi;
        }
        case (object): {
            return (*_oi)->second;
        }
        default: {
            return *_object;
        }
    }
}




JSON::const_iterator JSON::begin() const {
    return JSON::const_iterator(this);
}
JSON::const_iterator JSON::end() const {
    return JSON::const_iterator();
}

JSON::const_iterator JSON::cbegin() const {
    return JSON::const_iterator(this);
}
JSON::const_iterator JSON::cend() const {
    return JSON::const_iterator();
}

JSON::const_iterator::const_iterator() : _object(nullptr), _vi(nullptr), _oi(nullptr) {}

JSON::const_iterator::const_iterator(const JSON* j) : _object(j), _vi(nullptr), _oi(nullptr) {
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::const_iterator(_object->_value.array->begin());
                break;
            }
            case (object): {
                _oi = new object_t::const_iterator(_object->_value.object->begin());
                break;
            }
            default: {
                break;
            }
        }
}

JSON::const_iterator::const_iterator(const JSON::const_iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::const_iterator(*(o._vi));
                break;
            }
            case (object): {
                _oi = new object_t::const_iterator(*(o._oi));
                break;
            }
            default: {
                break;
            }
        }
}

JSON::const_iterator::const_iterator(const JSON::iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::const_iterator(*(o._vi));
                break;
            }
            case (object): {
                _oi = new object_t::const_iterator(*(o._oi));
                break;
            }
            default: {
                break;
            }
        }
}

JSON::const_iterator::~const_iterator() {
    delete _vi;
    delete _oi;
}

JSON::const_iterator& JSON::const_iterator::operator=(const JSON::const_iterator& o) {
    _object = o._object;
    if (_object != nullptr)
        switch (_object->_type) {
            case (array): {
                _vi = new array_t::const_iterator(*(o._vi));
                break;
            }
            case (object): {
                _oi = new object_t::const_iterator(*(o._oi));
                break;
            }
            default: {
                break;
            }
        }
    return *this;
}

bool JSON::const_iterator::operator==(const JSON::const_iterator& o) const {
    return _object == o._object;
}

bool JSON::const_iterator::operator!=(const JSON::const_iterator& o) const {
    return _object != o._object;
}


JSON::const_iterator& JSON::const_iterator::operator++() {
    // iterator cannot be incremented
    if (_object == nullptr) {
        return *this;
    }

    switch (_object->_type) {
        case (array): {
            if (++(*_vi) == _object->_value.array->end()) {
                _object = nullptr;
            }
            break;
        }
        case (object): {
            if (++(*_oi) == _object->_value.object->end()) {
                _object = nullptr;
            }
            break;
        }
        default: {
            _object = nullptr;
        }
    }
    return *this;
}

const JSON& JSON::const_iterator::operator*() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return **_vi;
        }
        case (object): {
            return (*_oi)->second;
        }
        default: {
            return *_object;
        }
    }
}

const JSON* JSON::const_iterator::operator->() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return &(**_vi);
        }
        case (object): {
            return &((*_oi)->second);
        }
        default: {
            return _object;
        }
    }
}

std::string JSON::const_iterator::key() const {
    if (_object != nullptr and _object->_type == object) {
        return (*_oi)->first;
    } else {
        throw std::runtime_error("cannot get key");
    }
}

const JSON& JSON::const_iterator::value() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array): {
            return **_vi;
        }
        case (object): {
            return (*_oi)->second;
        }
        default: {
            return *_object;
        }
    }
}
