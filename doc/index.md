# JSON for Modern C++

These pages contain the API documentation of JSON for Modern C++, a C++11 header-only JSON class.

# Contents

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

# Container function overview

The container functions known from STL have been extended to support the different value types from JSON. However, not all functions can be applied to all value types. Note that the signature of some functions differ between the types; for instance, `at` may be called with either a string to address a key in an object or with an integer to address a value in an array.

<table>
  <tr>
    <th rowspan="2">group</td>
    <th rowspan="2">function</td>
    <th colspan="6">JSON value type</th>
  </tr>
  <tr>
    <th>object</th>
    <th>array</th>
    <th>string</th>
    <th>number</th>
    <th>boolean</th>
    <th>null</th>
  </tr>
  <tr>
    <td rowspan="8">iterators</td>
    <td>`begin`</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::begin `begin` @endlink (returns `end()`)</td>
  </tr>
  <tr>
    <td>`cbegin`</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cbegin `cbegin` @endlink (returns `cend()`)</td>
  </tr>
  <tr>
    <td>`end`</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::end `end` @endlink</td>
  </tr>
  <tr>
    <td>`cend`</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::cend `cend` @endlink</td>
  </tr>
  <tr>
    <td>`rbegin`</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rbegin `rbegin` @endlink</td>
  </tr>
  <tr>
    <td>`crbegin`</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crbegin `crbegin` @endlink</td>
  </tr>
  <tr>
    <td>`rend`</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::rend `rend` @endlink</td>
  </tr>
  <tr>
    <td>`crend`</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::crend `crend` @endlink</td>
  </tr>
  <tr>
    <td rowspan="4">element<br>access</td>
    <td>`at`</td>
    <td class="ok_green">@link nlohmann::basic_json::at(const typename object_t::key_type & key) `at` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::at(size_type) `at` @endlink</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
  </tr>
  <tr>
    <td>`operator[]`</td>
    <td class="ok_green">@link nlohmann::basic_json::operator[](const typename object_t::key_type &key) `operator[]` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::operator[](size_type) `operator[]` @endlink</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="ok_green">@link nlohmann::basic_json::operator[](const typename object_t::key_type & key) `operator[]` @endlink (creates object)<br>@link nlohmann::basic_json::operator[](size_type) `operator[]` @endlink (creates array)</td>
  </tr>
  <tr>
    <td>`front`</td>
    <td class="ok_green">@link nlohmann::basic_json::front `front` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::front `front` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::front `front` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::front `front` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::front `front` @endlink</td>
    <td class="nok_throws">throws `std::out_of_range`</td>
  </tr>
  <tr>
    <td>`back`</td>
    <td class="ok_green">@link nlohmann::basic_json::back `back` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::back `back` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::back `back` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::back `back` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::back `back` @endlink</td>
    <td class="nok_throws">throws `std::out_of_range`</td>
  </tr>
  <tr>
    <td rowspan="3">capacity</td>
    <td>`empty`</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink (returns `false`)</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink (returns `false`)</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink (returns `false`)</td>
    <td class="ok_green">@link nlohmann::basic_json::empty `empty` @endlink (returns `true`)</td>
  </tr>
  <tr>
    <td>`size`</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::size `size` @endlink (returns `0`)</td>
  </tr>
  <tr>
    <td>`max_size_`</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink (returns `1`)</td>
    <td class="ok_green">@link nlohmann::basic_json::max_size `max_size` @endlink (returns `0`)</td>
  </tr>
  <tr>
    <td rowspan="5">modifiers</td>
    <td>`clear`</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::clear `clear` @endlink</td>
  </tr>
  <tr>
    <td>`insert`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="ok_green">@link nlohmann::basic_json::insert `insert` @endlink</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
  </tr>
  <tr>
    <td>`erase`</td>
    <td class="ok_green">@link nlohmann::basic_json::erase `erase` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::erase `erase` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::erase `erase` @endlink (converts to null)</td>
    <td class="ok_green">@link nlohmann::basic_json::erase `erase` @endlink (converts to null)</td>
    <td class="ok_green">@link nlohmann::basic_json::erase `erase` @endlink (converts to null)</td>
    <td class="nok_throws">throws</td>
  </tr>
  <tr>
    <td>`push_back`</td>
    <td class="ok_green">@link nlohmann::basic_json::push_back(const typename object_t::value_type & val) `push_back` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::push_back(const nlohmann::basic_json &) `push_back` @endlink</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="nok_throws">throws `std::domain_error`</td>
    <td class="ok_green">@link nlohmann::basic_json::push_back(const typename object_t::value_type & val) `push_back` @endlink (creates object)<br>@link nlohmann::basic_json::push_back(const nlohmann::basic_json &) `push_back` @endlink (creates array)</td>
  </tr>
  <tr>
    <td>`swap`</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::swap `swap` @endlink</td>
  </tr>
  <tr>
    <td rowspan="2">lookup</td>
    <td>`find`</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink (returns `end()`)</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink (returns `end()`)</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink (returns `end()`)</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink (returns `end()`)</td>
    <td class="ok_green">@link nlohmann::basic_json::find `find` @endlink (returns `end()`)</td>
  </tr>
  <tr>
    <td>`count`</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink (returns `0`)</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink (returns `0`)</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink (returns `0`)</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink (returns `0`)</td>
    <td class="ok_green">@link nlohmann::basic_json::count `count` @endlink (returns `0`)</td>
  </tr>
</table>

@copyright Copyright &copy; 2013-2016 Niels Lohmann. The code is licensed under the [MIT License](http://opensource.org/licenses/MIT).

@author [Niels Lohmann](http://nlohmann.me)
@see https://github.com/nlohmann/json to download the source code

@version 2.0.0
