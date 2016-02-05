# JSON for Modern C++

These pages contain the API documentation of JSON for Modern C++, a C++11 header-only JSON class.

- @link nlohmann::basic_json `basic_json` class @endlink
- [Functions](functions_func.html)
  - object inspection
    - @link nlohmann::basic_json::dump dump @endlink -- value serialization
    - @link nlohmann::basic_json::type type @endlink -- type of the value
    - @link nlohmann::basic_json::is_primitive is_primitive @endlink,
      @link nlohmann::basic_json::is_structured is_structured @endlink,
      @link nlohmann::basic_json::is_null is_null @endlink,
      @link nlohmann::basic_json::is_boolean is_boolean @endlink,
      @link nlohmann::basic_json::is_number is_number @endlink,
      @link nlohmann::basic_json::is_number_integer is_number_integer @endlink,
      @link nlohmann::basic_json::is_number_unsigned is_number_unsigned @endlink,
      @link nlohmann::basic_json::is_number_float is_number_float @endlink,
      @link nlohmann::basic_json::is_object is_object @endlink,
      @link nlohmann::basic_json::is_array is_array @endlink,
      @link nlohmann::basic_json::is_string is_string @endlink,
      @link nlohmann::basic_json::is_discarded is_discarded @endlink -- check for value type
    - @link nlohmann::basic_json::operator value_t() const operator value_t @endlink -- type of the value (implicit conversion)
  - value access
    - @link nlohmann::basic_json::get get @endlink -- get a value
    - @link nlohmann::basic_json::get_ptr get_ptr @endlink -- get a value pointer
    - @link nlohmann::basic_json::get_ref get_ref @endlink -- get a value reference
    - @link nlohmann::basic_json::operator ValueType() const operator ValueType @endlink -- get a value (implicit conversion)
  - element access
    - @link nlohmann::basic_json::at(size_type) at @endlink -- access array element with bounds checking
    - @link nlohmann::basic_json::at(const typename object_t::key_type & 	key) at @endlink -- access object element with bounds checking
    - @link nlohmann::basic_json::operator[](size_type) operator[] @endlink -- access array element
    - @link nlohmann::basic_json::operator[](const typename object_t::key_type & 	key) operator[] @endlink -- access object element
    - @link nlohmann::basic_json::value value @endlink -- access object element with default value
    - @link nlohmann::basic_json::front front @endlink -- access the first element
    - @link nlohmann::basic_json::back back @endlink -- access the last element 
  - iterators
    - begin, cbegin
    - end, cend
    - rbegin, crbegin
    - rend, crend
  - capacity
    - @link nlohmann::basic_json::empty empty @endlink -- checks whether the container is empty
    - @link nlohmann::basic_json::size size @endlink -- returns the number of elements
    - @link nlohmann::basic_json::max_size max_size @endlink -- returns the maximum possible number of elements
  - modifiers
    - @link nlohmann::basic_json::clear clear @endlink -- clears the contents
    - @link nlohmann::basic_json::push_back(const nlohmann::basic_json &) push_back @endlink -- add an object to an array
    - @link nlohmann::basic_json::operator+=(const nlohmann::basic_json &) operator+= @endlink -- add an object to an array
    - @link nlohmann::basic_json::insert insert @endlink -- inserts elements
    - @link nlohmann::basic_json::swap swap @endlink -- exchanges the values
  - lexicographical comparison operators
  - serialization
  - deserialization
- Types
  - @link nlohmann::basic_json::array_t arrays @endlink
  - @link nlohmann::basic_json::object_t objects @endlink
  - @link nlohmann::basic_json::string_t strings @endlink
  - @link nlohmann::basic_json::boolean_t booleans @endlink
  - numbers
    - @link nlohmann::basic_json::number_integer_t signed integers @endlink
    - @link nlohmann::basic_json::number_unsigned_t unsigned integers @endlink
    - @link nlohmann::basic_json::number_float_t floating-point @endlink

@copyright Copyright &copy; 2013-2016 Niels Lohmann. The code is licensed under the [MIT License](http://opensource.org/licenses/MIT).

@author [Niels Lohmann](http://nlohmann.me)
@see https://github.com/nlohmann/json to download the source code

@version 2.0.0
