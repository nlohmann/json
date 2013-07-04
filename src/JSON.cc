#include "JSON.h"

#include <utility>
#include <stdexcept>
#include <fstream>
#include <cctype>
#include <iostream>
#include <streambuf>
#include <sstream>

#ifndef __cplusplus11
#include <cstring>
#include <cstdlib>
#endif

#ifdef __cplusplus11
using std::to_string;
#else

inline std::string to_string(double f) {
    std::stringstream s;
    s << f;
    return s.str();
}
#endif

/******************
 * STATIC MEMBERS *
 ******************/

#ifdef __cplusplus11
/// a mutex to ensure thread safety
std::mutex JSON::_token;
#endif

/*******************************
 * CONSTRUCTORS AND DESTRUCTOR *
 *******************************/

JSON::JSON() : _type(null), _payload(nullptr) {}
JSON::JSON(const std::string& s) : _type(string), _payload(new std::string(s)) {}
JSON::JSON(const char* s) : _type(string), _payload(new std::string(s)) {}
JSON::JSON(char* s) : _type(string), _payload(new std::string(s)) {}
JSON::JSON(const bool b) : _type(boolean), _payload(new bool(b)) {}
JSON::JSON(const int i) : _type(number_int), _payload(new int(i)) {}
JSON::JSON(const double f) : _type(number_float), _payload(new double(f)) {}

#ifdef __cplusplus11
JSON::JSON(array_t a) : _type(array), _payload(new std::vector<JSON>(a)) {}

JSON::JSON(object_t o) : _type(object), _payload(new std::map<std::string, JSON>) {
    (*this)[std::get<0>(o)] = std::get<1>(o);
}
#endif

/// copy constructor
JSON::JSON(const JSON& o) : _type(o._type) {
    switch (_type) {
        case (array):
            _payload = new std::vector<JSON>(*static_cast<std::vector<JSON>*>(o._payload));
            break;
        case (object):
            _payload = new std::map<std::string, JSON>(*static_cast<std::map<std::string, JSON>*>(o._payload));
            break;
        case (string):
            _payload = new std::string(*static_cast<std::string*>(o._payload));
            break;
        case (boolean):
            _payload = new bool(*static_cast<bool*>(o._payload));
            break;
        case (number_int):
            _payload = new int(*static_cast<int*>(o._payload));
            break;
        case (number_float):
            _payload = new double(*static_cast<double*>(o._payload));
            break;
        case (null):
            break;
    }
}

#ifdef __cplusplus11
/// move constructor
JSON::JSON(JSON&& o) : _type(std::move(o._type)), _payload(std::move(o._payload)) {}
#endif

/// copy assignment
#ifdef __cplusplus11
JSON& JSON::operator=(JSON o) {
    std::swap(_type, o._type);
    std::swap(_payload, o._payload);
    return *this;
}
#else
JSON& JSON::operator=(const JSON& o) {
    // check for self-assignment
    if (&o == this) {
        return *this;
    }

    switch (_type) {
        case (array): {
            delete static_cast<std::vector<JSON>*>(_payload);
            break;
        }
        case (object): {
            delete static_cast<std::map<std::string, JSON>*>(_payload);
            break;
        }
        case (string): {
            delete static_cast<std::string*>(_payload);
            break;
        }
        case (boolean): {
            delete static_cast<bool*>(_payload);
            break;
        }
        case (number_int): {
            delete static_cast<int*>(_payload);
            break;
        }
        case (number_float): {
            delete static_cast<double*>(_payload);
            break;
        }
        case (null): {
            break;
        }
    }

    _type = o._type;
    switch (_type) {
        case (array): {
            _payload = new std::vector<JSON>(*static_cast<std::vector<JSON>*>(o._payload));
            break;
        }
        case (object): {
            _payload = new std::map<std::string, JSON>(*static_cast<std::map<std::string, JSON>*>(o._payload));
            break;
        }
        case (string): {
            _payload = new std::string(*static_cast<std::string*>(o._payload));
            break;
        }
        case (boolean): {
            _payload = new bool(*static_cast<bool*>(o._payload));
            break;
        }
        case (number_int): {
            _payload = new int(*static_cast<int*>(o._payload));
            break;
        }
        case (number_float): {
            _payload = new double(*static_cast<double*>(o._payload));
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
            delete static_cast<std::vector<JSON>*>(_payload);
            break;
        }
        case (object): {
            delete static_cast<std::map<std::string, JSON>*>(_payload);
            break;
        }
        case (string): {
            delete static_cast<std::string*>(_payload);
            break;
        }
        case (boolean): {
            delete static_cast<bool*>(_payload);
            break;
        }
        case (number_int): {
            delete static_cast<int*>(_payload);
            break;
        }
        case (number_float): {
            delete static_cast<double*>(_payload);
            break;
        }
        case (null): {
            break;
        }
    }
}


/*****************************
 * OPERATORS AND CONVERSIONS *
 *****************************/

JSON::operator const std::string() const {
    switch (_type) {
        case (string):
            return *static_cast<std::string*>(_payload);
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON string");
    }
}


JSON::operator int() const {
    switch (_type) {
        case (number_int):
            return *static_cast<int*>(_payload);
        case (number_float):
            return static_cast<int>(*static_cast<double*>(_payload));
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON number");
    }
}

JSON::operator double() const {
    switch (_type) {
        case (number_int):
            return static_cast<double>(*static_cast<int*>(_payload));
        case (number_float):
            return *static_cast<double*>(_payload);
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON number");
    }
}

JSON::operator bool() const {
    switch (_type) {
        case (boolean):
            return *static_cast<bool*>(_payload);
        default:
            throw std::runtime_error("cannot cast " + _typename() + " to JSON Boolean");
    }
}

const std::string JSON::toString() const {
    switch (_type) {
        case (null): {
            return "null";
        }

        case (string): {
            return std::string("\"") + *static_cast<std::string*>(_payload) + "\"";
        }

        case (boolean): {
            return *static_cast<bool*>(_payload) ? "true" : "false";
        }

        case (number_int): {
            return to_string(*static_cast<int*>(_payload));
        }

        case (number_float): {
            return to_string(*static_cast<double*>(_payload));
        }

        case (array): {
            std::string result;

            const std::vector<JSON>* array = static_cast<std::vector<JSON>*>(_payload);
            for (std::vector<JSON>::const_iterator i = array->begin(); i != array->end(); ++i) {
                if (i != array->begin()) {
                    result += ", ";
                }
                result += (*i).toString();
            }

            return "[" + result + "]";
        }

        case (object): {
            std::string result;

            const std::map<std::string, JSON>* object = static_cast<std::map<std::string, JSON>*>(_payload);
            for (std::map<std::string, JSON>::const_iterator i = object->begin(); i != object->end(); ++i) {
                if (i != object->begin()) {
                    result += ", ";
                }
                result += "\"" + i->first + "\": " + (i->second).toString();
            }

            return "{" + result + "}";
        }
    }
}


/*****************************************
 * ADDING ELEMENTS TO OBJECTS AND ARRAYS *
 *****************************************/

JSON& JSON::operator+=(const JSON& o) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (not(_type == null or _type == array)) {
        throw std::runtime_error("cannot add element to " + _typename());
    }

    if (_type == null) {
        _type = array;
        _payload = new std::vector<JSON>;
    }

    static_cast<std::vector<JSON>*>(_payload)->push_back(o);

    return *this;
}

JSON& JSON::operator+=(const std::string& s) {
    JSON tmp(s);
    operator+=(tmp);
    return *this;
}

JSON& JSON::operator+=(const char* s) {
    JSON tmp(s);
    operator+=(tmp);
    return *this;
}

JSON& JSON::operator+=(bool b) {
    JSON tmp(b);
    operator+=(tmp);
    return *this;
}

JSON& JSON::operator+=(int i) {
    JSON tmp(i);
    operator+=(tmp);
    return *this;
}

JSON& JSON::operator+=(double f) {
    JSON tmp(f);
    operator+=(tmp);
    return *this;
}

/// operator to set an element in an object
JSON& JSON::operator[](int index) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type != array) {
        throw std::runtime_error("cannot add entry with index " + to_string(index) + " to " + _typename());
    }

    std::vector<JSON>* array = static_cast<std::vector<JSON>*>(_payload);

    if (index >= array->size()) {
        throw std::runtime_error("cannot access element at index " + to_string(index));
    }

    return array->at(index);
}

/// operator to get an element in an object
const JSON& JSON::operator[](const int index) const {
    if (_type != array) {
        throw std::runtime_error("cannot get entry with index " + to_string(index) + " from " + _typename());
    }

    std::vector<JSON>* array = static_cast<std::vector<JSON>*>(_payload);

    if (index >= array->size()) {
        throw std::runtime_error("cannot access element at index " + to_string(index));
    }

    return array->at(index);
}

/// operator to set an element in an object
JSON& JSON::operator[](const std::string& key) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type == null) {
        _type = object;
        _payload = new std::map<std::string, JSON>;
    }

    if (_type != object) {
        throw std::runtime_error("cannot add entry with key " + std::string(key) + " to " + _typename());
    }

    std::map<std::string, JSON>* object = static_cast<std::map<std::string, JSON>*>(_payload);
    if (object->find(key) == object->end()) {
        (*object)[key] = JSON();
    }

    return (*object)[key];
}

/// operator to set an element in an object
JSON& JSON::operator[](const char* key) {
#ifdef __cplusplus11
    std::lock_guard<std::mutex> lg(_token);
#endif

    if (_type == null) {
        _type = object;
        _payload = new std::map<std::string, JSON>;
    }

    if (_type != object) {
        throw std::runtime_error("cannot add entry with key " + std::string(key) + " to " + _typename());
    }

    std::map<std::string, JSON>* object = static_cast<std::map<std::string, JSON>*>(_payload);
    if (object->find(key) == object->end()) {
        (*object)[key] = JSON();
    }

    return (*object)[key];
}

/// operator to get an element in an object
const JSON& JSON::operator[](const std::string& key) const {
    if (_type != object) {
        throw std::runtime_error("cannot get entry with key " + std::string(key) + " from " + _typename());
    }

    const std::map<std::string, JSON>* object = static_cast<std::map<std::string, JSON>*>(_payload);
    if (object->find(key) == object->end()) {
        throw std::runtime_error("key " + key + " not found");
    } else {
        return object->find(key)->second;
    }
}

/// return the number of stored values
size_t JSON::size() const {
    switch (_type) {
        case (array):
            return static_cast<std::vector<JSON>*>(_payload)->size();
        case (object):
            return static_cast<std::map<std::string, JSON>*>(_payload)->size();
        case (null):
            return 0;
        case (string):
            return 1;
        case (boolean):
            return 1;
        case (number_int):
            return 1;
        case (number_float):
            return 1;
    }
}

/// checks whether object is empty
bool JSON::empty() const {
    switch (_type) {
        case (array):
            return static_cast<std::vector<JSON>*>(_payload)->empty();
        case (object):
            return static_cast<std::map<std::string, JSON>*>(_payload)->empty();
        case (null):
            return true;
        case (string):
            return false;
        case (boolean):
            return false;
        case (number_int):
            return false;
        case (number_float):
            return false;
    }
}

/// return the type of the object
JSON::json_t JSON::type() const {
    return _type;
}

/// direct access to the underlying payload
void* JSON::data() {
    return _payload;
}

/// direct access to the underlying payload
const void* JSON::data() const {
    return _payload;
}

/// lexicographically compares the values
bool JSON::operator==(const JSON& o) const {
    switch (_type) {
        case (array): {
            if (o._type == array) {
                std::vector<JSON>* a = static_cast<std::vector<JSON>*>(_payload);
                std::vector<JSON>* b = static_cast<std::vector<JSON>*>(o._payload);
                return *a == *b;
            }
        }
        case (object): {
            if (o._type == object) {
                std::map<std::string, JSON>* a = static_cast<std::map<std::string, JSON>*>(_payload);
                std::map<std::string, JSON>* b = static_cast<std::map<std::string, JSON>*>(o._payload);
                return *a == *b;
            }
        }
        case (null): {
            if (o._type == null) {
                return true;
            }
        }
        case (string): {
            if (o._type == string) {
                const std::string a = *this;
                const std::string b = o;
                return a == b;
            }
        }
        case (boolean): {
            if (o._type == boolean) {
                bool a = *this;
                bool b = o;
                return a == b;
            }
        }
        case (number_int): {
            if (o._type == number_int or o._type == number_float) {
                int a = *this;
                int b = o;
                return a == b;
            }
        }
        case (number_float): {
            if (o._type == number_int or o._type == number_float) {
                double a = *this;
                double b = o;
                return a == b;
            }
        }
    }

    return false;
}



/// return the type as string
std::string JSON::_typename() const {
    switch (_type) {
        case (array):
            return "array";
        case (object):
            return "object";
        case (null):
            return "null";
        case (string):
            return "string";
        case (boolean):
            return "boolean";
        case (number_int):
            return "number";
        case (number_float):
            return "number";
    }
}


JSON::parser::parser(char* s) : _pos(0) {
    _buffer = new char[strlen(s) + 1];
    strcpy(_buffer, s);

    // read first character
    next();
}

JSON::parser::parser(std::string& s) : _pos(0) {
    _buffer = new char[s.length() + 1];
    strcpy(_buffer, s.c_str());

    // read first character
    next();
}

JSON::parser::parser(std::istream& _is) : _pos(0) {
    // determine length of input stream
    _is.seekg(0, std::ios::end);
    std::streampos length = _is.tellg();
    _is.seekg(0, std::ios::beg);

    // copy stream to buffer
    _buffer = new char[length];
    _is.read(_buffer, length);

    // read first character
    next();
}

JSON::parser::~parser() {
    delete [] _buffer;
}

void JSON::parser::error(std::string msg) {
    throw std::runtime_error("parse error at position " + to_string(_pos) + ": " + msg + ", last read: '" + _current + "'");
}

bool JSON::parser::next() {
    _current = _buffer[_pos++];

    // skip trailing whitespace
    while (std::isspace(_current)) {
        _current = _buffer[_pos++];
    }

    return true;
}

std::string JSON::parser::parseString() {
    // get position of closing quotes
    char* p = strchr(_buffer + _pos, '\"');

    // if the closing quotes are escaped (viz. *(p-1) is '\\'),
    // we continue looking for the "right" quotes
    while (p != nullptr and * (p - 1) == '\\') {
        // length of the string so far
        const size_t length = p - _buffer - _pos;
        // continue checking after escaped quote
        p = strchr(_buffer + _pos + length + 1, '\"');
    }

    // check if closing quotes were found
    if (p == nullptr) {
        error("expected '\"'");
    }

    // copy string to return value
    const size_t length = p - _buffer - _pos;
    char* tmp = new char[length + 1];
    strncpy(tmp, _buffer + _pos, length);
    std::string result(tmp);
    delete [] tmp;

    // +1 to eat closing quote
    _pos += length + 1;

    // read next character
    next();

    return result;
}

void JSON::parser::parseTrue() {
    if (strncmp(_buffer + _pos, "rue", 3)) {
        error("expected true");
    }

    _pos += 3;

    // read next character
    next();
}

void JSON::parser::parseFalse() {
    if (strncmp(_buffer + _pos, "alse", 4)) {
        error("expected false");
    }

    _pos += 4;

    // read next character
    next();
}

void JSON::parser::parseNull() {
    if (strncmp(_buffer + _pos, "ull", 3)) {
        error("expected null");
    }

    _pos += 3;

    // read next character (optional?)
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
            result._payload = new std::map<std::string, JSON>;

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
            result._payload = new std::vector<JSON>;

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
            result._payload = new std::string(parseString());
            break;
        }

        case ('t'): {
            parseTrue();
            result._type = boolean;
            result._payload = new bool(true);
            break;
        }

        case ('f'): {
            parseFalse();
            result._type = boolean;
            result._payload = new bool(false);
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
                    result._type = number_int;
                    result._payload = new int(std::atof(tmp.c_str()));
                } else {
                    // float
                    result._type = number_float;
                    result._payload = new double(std::atof(tmp.c_str()));
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
    switch (_object->_type) {
        case (array): {
            _vi = new std::vector<JSON>::iterator(static_cast<std::vector<JSON>*>(_object->_payload)->begin());
            break;
        }
        case (object): {
            _oi = new std::map<std::string, JSON>::iterator(static_cast<std::map<std::string, JSON>*>(_object->_payload)->begin());
            break;
        }
        default:
            break;
    }
}

JSON::iterator::iterator(const JSON::iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    switch (_object->_type) {
        case (array): {
            _vi = new std::vector<JSON>::iterator(static_cast<std::vector<JSON>*>(_object->_payload)->begin());
            break;
        }
        case (object): {
            _oi = new std::map<std::string, JSON>::iterator(static_cast<std::map<std::string, JSON>*>(_object->_payload)->begin());
            break;
        }
        default:
            break;
    }
}

JSON::iterator::~iterator() {
    delete _vi;
    delete _oi;
}

JSON::iterator& JSON::iterator::operator=(const JSON::iterator& o) {
    _object = o._object;
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
            if (++(*_vi) == static_cast<std::vector<JSON>*>(_object->_payload)->end()) {
                _object = nullptr;
            }
            break;
        }
        case (object): {
            if (++(*_oi) == static_cast<std::map<std::string, JSON>*>(_object->_payload)->end()) {
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
        case (array):
            return **_vi;
        case (object):
            return (*_oi)->second;
        default:
            return *_object;
    }
}

JSON* JSON::iterator::operator->() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array):
            return &(**_vi);
        case (object):
            return &((*_oi)->second);
        default:
            return _object;
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
        case (array):
            return **_vi;
        case (object):
            return (*_oi)->second;
        default:
            return *_object;
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
    switch (_object->_type) {
        case (array): {
            _vi = new std::vector<JSON>::const_iterator(static_cast<std::vector<JSON>*>(_object->_payload)->begin());
            break;
        }
        case (object): {
            _oi = new std::map<std::string, JSON>::const_iterator(static_cast<std::map<std::string, JSON>*>(_object->_payload)->begin());
            break;
        }
        default:
            break;
    }
}

JSON::const_iterator::const_iterator(const JSON::const_iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    switch (_object->_type) {
        case (array): {
            _vi = new std::vector<JSON>::const_iterator(static_cast<std::vector<JSON>*>(_object->_payload)->begin());
            break;
        }
        case (object): {
            _oi = new std::map<std::string, JSON>::const_iterator(static_cast<std::map<std::string, JSON>*>(_object->_payload)->begin());
            break;
        }
        default:
            break;
    }
}

JSON::const_iterator::const_iterator(const JSON::iterator& o) : _object(o._object), _vi(nullptr), _oi(nullptr) {
    switch (_object->_type) {
        case (array): {
            _vi = new std::vector<JSON>::const_iterator(static_cast<std::vector<JSON>*>(_object->_payload)->begin());
            break;
        }
        case (object): {
            _oi = new std::map<std::string, JSON>::const_iterator(static_cast<std::map<std::string, JSON>*>(_object->_payload)->begin());
            break;
        }
        default:
            break;
    }
}

JSON::const_iterator::~const_iterator() {
    delete _vi;
    delete _oi;
}

JSON::const_iterator& JSON::const_iterator::operator=(const JSON::const_iterator& o) {
    _object = o._object;
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
            if (++(*_vi) == static_cast<std::vector<JSON>*>(_object->_payload)->end()) {
                _object = nullptr;
            }
            break;
        }
        case (object): {
            if (++(*_oi) == static_cast<std::map<std::string, JSON>*>(_object->_payload)->end()) {
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
        case (array):
            return **_vi;
        case (object):
            return (*_oi)->second;
        default:
            return *_object;
    }
}

const JSON* JSON::const_iterator::operator->() const {
    if (_object == nullptr) {
        throw std::runtime_error("cannot get value");
    }

    switch (_object->_type) {
        case (array):
            return &(**_vi);
        case (object):
            return &((*_oi)->second);
        default:
            return _object;
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
        case (array):
            return **_vi;
        case (object):
            return (*_oi)->second;
        default:
            return *_object;
    }
}
