# nlohmann::basic_json

Defined in header `<json.hpp>`

```cpp
template <
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = int64_t,
    class NumberFloatType = double,
    template<typename U> class Allocator = std::allocator
> class basic_json;
```

## Template Parameters

- `ObjectType` - The type to store collection of name/value pairs. It can be any associative container that can hold key-value pairs as long as the key type is the same as `StringType`. The value type is again `nlohmann::basic_json`. The parameter `ObjectType` defaults to [`std::map`](http://en.cppreference.com/w/cpp/container/map).
- `ArrayType` - The type to store ordered value lists. It can be any sequence container. The parameter `ArrayType` defaults to a [`std::vector`](http://en.cppreference.com/w/cpp/container/vector) whose elements are of type `nlohmann::basic_json`.
- `StringType` - The type to store string values. The parameter `StringType` defaults to [`std::string`](http://en.cppreference.com/w/cpp/string/basic_string).
- `BooleanType`
- `NumberIntegerType`
- `NumberFloatType`
- `Allocator` - An allocator that is used to acquire memory to store the elements. The type must meet the requirements of [`Allocator`](http://en.cppreference.com/w/cpp/concept/Allocator).

## Specializations

A standard JSON type `nlohmann::json` is defined in `<json.hpp>` which uses the default types:

```cpp
using json = basic_json<
    std::map,
    std::vector,
    std::string,
    bool,
    int64_t,
    double,
    std::allocator
>
```


## Iterator invalidation

## Member types

- `value_type`
- `reference`
- `const_reference`
- `difference_type`
- `size_type`
- `allocator_type`
- `pointer`
- `const_pointer`
- `iterator`
- `const_iterator`
- `reverse_iterator`
- `const_reverse_iterator`
- `object_t`
- `array_t`
- `string_t`
- `boolean_t`
- `number_integer_t`
- `number_float_t`
- `list_init_t`
- `json_value`

## Member functions

- constructor
- destructor
- `operator=`
- `get_allocator`

### Object inspection

- `dump`
- `type`
- `is_null`
- `is_boolean`
- `is_number`
- `is_object`
- `is_array`
- `is_string`
- `operator value_t`
- `std::hash`

### Value conversion

- `get`
- implicit conversion

### Element access

- `at`
- `operator[]`
- `erase`
- `find`
- `count`

### Iterators

- `begin` / `cbegin`
- `end` / `cend`
- `rbegin` / `crbegin`
- `rend` / `crend`

### Capacity

- [`empty`](empty)
- `size`
- `max_size`

### Modifiers

- `clear`
- `push_back`
- `operator+=`
- `erase`
- `swap`
- `std::swap`

### Comparisons

- `operator==`
- `operator!=`
- `operator<`
- `operator<=`
- `operator>`
- `operator>=`

### Serialization

- `dump`
- `operator<<`
- `operator>>`

### Deserialization

- `parse`
- `operator<<`
- `operator>>`
