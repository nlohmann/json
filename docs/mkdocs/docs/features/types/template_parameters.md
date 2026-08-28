# Template Parameter Requirements

Class [`basic_json`](../../api/basic_json/index.md) is configurable through eleven template parameters. The library
never formally states what a type passed for one of these parameters has to provide -- the requirements are implied by
the way the library uses the resulting [`object_t`](../../api/basic_json/object_t.md),
[`array_t`](../../api/basic_json/array_t.md), [`string_t`](../../api/basic_json/string_t.md), etc. This page collects
these requirements so they do not have to be discovered by trial and error.

## How to read this page

Requirements are split into two groups:

- **Always required** -- needed to instantiate `basic_json` at all, or needed by functions that virtually every program
  uses (construction, element access, [`dump`](../../api/basic_json/dump.md)).
- **Required for ...** -- only needed when a particular part of the API is instantiated. Member function templates are
  only instantiated when they are used, so a type may be perfectly usable even though it does not satisfy these
  requirements, as long as the corresponding functions are never called.

!!! warning "Requirements are not checked"

    Apart from a `#!cpp static_assert` on the array iterator category, the requirements below are not diagnosed with
    dedicated error messages. Violating them results in a compiler error somewhere inside the library -- or, in the two
    cases described in [Cross-specialization conversions](#cross-specialization-conversions), in silently wrong
    behavior at runtime.

## Overview

| Template parameter                                                | Default                           | Notable substitutes                                                    |
|-------------------------------------------------------------------|-----------------------------------|------------------------------------------------------------------------|
| [`ObjectType`](#objecttype)                                       | `std::map`                        | [`nlohmann::ordered_map`](../../api/ordered_map.md), `tsl::ordered_map` |
| [`ArrayType`](#arraytype)                                         | `std::vector`                     | vector-like containers only                                            |
| [`StringType`](#stringtype)                                       | `std::string`                     | `std::string`-like types over `char`                                   |
| [`BooleanType`](#booleantype)                                     | `bool`                            | (none)                                                                 |
| [`NumberIntegerType`](#numberintegertype-and-numberunsignedtype)  | `std::int64_t`                    | any signed integer type                                                |
| [`NumberUnsignedType`](#numberintegertype-and-numberunsignedtype) | `std::uint64_t`                   | any unsigned integer type                                              |
| [`NumberFloatType`](#numberfloattype)                             | `double`                          | `float`, `long double`                                                 |
| [`AllocatorType`](#allocatortype)                                 | `std::allocator`                  | stateless allocators                                                   |
| [`JSONSerializer`](#jsonserializer)                               | `adl_serializer`                  | serializers with the same interface                                    |
| [`BinaryType`](#binarytype)                                       | `#!cpp std::vector<std::uint8_t>` | contiguous byte containers                                             |
| [`CustomBaseClass`](#custombaseclass)                             | `void`                            | any default-constructible class                                        |

## `ObjectType`

`ObjectType` is instantiated as

```cpp
using object_t = ObjectType<StringType,                                    // key_type
                            basic_json,                                    // mapped_type
                            default_object_comparator_t,                   // key_compare
                            AllocatorType<std::pair<const StringType,
                                                    basic_json>>>;         // allocator_type
```

i.e., the template arguments follow the order and meaning of `std::map`.

### Always required

- The template must be usable with **four** type arguments in the order shown above. The third argument is a
  **comparator**; containers that expect something else in this position (e.g., a hash function) need an alias template
  or wrapper -- see [Notes](#notes).
- Member types `key_type`, `mapped_type`, `value_type`, `iterator`, and **`key_compare`**.
- `value_type` must behave like `#!cpp std::pair<const key_type, mapped_type>`; the library accesses `.first` and
  `.second` on it.
- `iterator` must be default-constructible and satisfy
  [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator). The type returned
  by `cbegin()`/`cend()` must satisfy the same requirements.
- Constructors: default, copy, move, and from an iterator range `(first, last)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`,
  `find(key)`, `count(key)`, `emplace(key, value)`, `insert(value_type)`, `insert(first, last)`, `operator[](key)`,
  `erase(iterator)`, `erase(first, last)`, and `erase(key)`.
- `emplace` and `insert(value_type)` must return `#!cpp std::pair<iterator, bool>` and must have **unique-key**
  semantics; multimaps cannot be used.
- The type must be swappable (via `std::swap` or an ADL `swap`).
- The comparison operators `==`, `!=`, `<`, `<=`, `>`, and `>=` (or `<=>` in C++20) must be available; they implement
  [`basic_json`'s comparison operators](../../api/basic_json/operator_eq.md).

### Required for heterogeneous key lookup

The overloads of [`at`](../../api/basic_json/at.md), [`operator[]`](../../api/basic_json/operator%5B%5D.md),
[`find`](../../api/basic_json/find.md), [`contains`](../../api/basic_json/contains.md),
[`count`](../../api/basic_json/count.md), [`erase`](../../api/basic_json/erase.md), and
[`value`](../../api/basic_json/value.md) that accept a key type other than `object_t::key_type` require

- a **transparent** comparator, i.e. [`object_comparator_t`](../../api/basic_json/object_comparator_t.md) has a member
  type `is_transparent` (this is why the default comparator is `#!cpp std::less<>` since C++14), and
- corresponding heterogeneous `find`, `count`, `erase`, and `operator[]` overloads on the container.

### Notes

#### `key_compare` is mandatory

[`object_comparator_t`](../../api/basic_json/object_comparator_t.md) is defined as

```cpp
using type = typename std::conditional<has_key_compare<object_t>::value,
                                       typename object_t::key_compare,
                                       default_object_comparator_t>::type;
```

Both type arguments of `#!cpp std::conditional` have to name valid types, so `#!cpp object_t::key_compare` must exist
even when `has_key_compare<object_t>` evaluates to `#!cpp false`. A container without a `key_compare` member type
therefore fails to compile.

#### `std::unordered_map` cannot be used directly

`#!cpp std::unordered_map` fails on both counts: it has no `key_compare` member type, and its third template parameter
is a hash function rather than a comparator. It can be used through a wrapper that fixes the argument order and adds
the missing member type:

```cpp
template<class Key, class T, class IgnoredCompare, class Allocator>
struct unordered_map_object
    : std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
    using key_compare = std::equal_to<Key>;
};

using unordered_json = nlohmann::basic_json<unordered_map_object>;
```

The same pattern (ignoring the third argument) is how [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) and
similar containers are integrated; see [Object Order](../object_order.md).

#### `capacity()` marks a container as insertion-ordered

With [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) enabled, the library detects insertion-ordered maps by
probing for a `capacity()` member function (`nlohmann::ordered_map` inherits it from `std::vector`) and refreshes all
parent pointers after every insertion. An `ObjectType` that happens to have a `capacity()` member is therefore treated
conservatively -- this is correct, but slower.

#### Key order and duplicate keys

The library does not sort or de-duplicate keys itself; the behavior described in
[`object_t`](../../api/basic_json/object_t.md) is entirely the behavior of the chosen container.

## `ArrayType`

`ArrayType` is instantiated as

```cpp
using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;
```

### Always required

- The template must be usable with **two** type arguments (value type and allocator).
- Member types `value_type` and `iterator`.
- Constructors: default, copy, move, from an iterator range `(first, last)`, and from `(count, value)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`,
  `operator[](size_type)`, `at(size_type)`, `back()`, `push_back()`, `emplace_back()`, `pop_back()`, `resize()`,
  `insert()` (single element, count, range, and initializer list), `erase(pos)`, `erase(first, last)`, and
  **`capacity()`**.
- `iterator` must be default-constructible, and it as well as the type returned by `cbegin()`/`cend()` must satisfy
  [LegacyRandomAccessIterator](https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator).
  A `#!cpp static_assert` only checks for
  [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator), but
  [`dump`](../../api/basic_json/dump.md) (`cend() - 1`),
  [`erase(idx)`](../../api/basic_json/erase.md) (`begin() + idx`), and the random-access operations of
  [`basic_json::iterator`](../../api/basic_json/begin.md) require random access.
- The type must be swappable and provide the comparison operators `==`, `!=`, `<`, `<=`, `>`, `>=` (or `<=>`).

!!! note "`capacity()` is required unconditionally"

    [`push_back`](../../api/basic_json/push_back.md), [`emplace_back`](../../api/basic_json/emplace_back.md),
    [`operator+=`](../../api/basic_json/operator+=.md), and
    [`operator[]`](../../api/basic_json/operator%5B%5D.md) with an array index read `array_t::capacity()` to
    detect reallocations, regardless of whether [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) is enabled.
    Consequently `#!cpp std::deque` and `#!cpp std::list` cannot be used as `ArrayType` as-is. A `std::deque` becomes
    usable when wrapped in a type that adds a `capacity()` member function; `#!cpp std::list` additionally lacks
    `operator[]` and random-access iterators and cannot be used at all.

## `StringType`

`StringType` is used **both** for JSON string values and for the keys of JSON objects
(`string_t` and `object_t::key_type`).

### Always required

- A member type `value_type` that is one byte wide and `char`-compatible. The library stores and processes UTF-8
  encoded `char` data and passes `data()` to `#!cpp std::strtoull`/`#!cpp std::strtoll` and to `#!cpp std::memcpy`.
  `#!cpp std::wstring`, `#!cpp std::u16string`, and `#!cpp std::u32string` are **not** valid choices; see the FAQ on
  [wide string handling](../../home/faq.md#wide-string-handling).
- Constructors: default, copy, move, from `#!cpp const char*`, from `#!cpp (const char*, size_type)`, and from
  `#!cpp (size_type, char)`.
- Member functions `size()`, `empty()`, `clear()`, `resize(n)`, `resize(n, c)`, `reserve(n)`, `back()`, `c_str()`,
  `data()`, `push_back(char)`, and `operator[]` (const and non-const, returning references).
- `data()` must return a pointer to a contiguous, null-terminated buffer: the parser hands it to
  `#!cpp std::strtoull`, and the binary readers write into `#!cpp &s[n]` with `#!cpp std::memcpy`.
- `append(const char*, size_type)` -- used by [`dump`](../../api/basic_json/dump.md) -- plus at least one of
  `append(str)`, `operator+=`, `append(first, last)`, or `append(data, size)`, which the library's internal string
  concatenation selects between.
- The comparison operators `==` and `!=` against another `StringType` and against `#!cpp const char*`, and `<` for use
  as a key of the chosen [`ObjectType`](#objecttype) (with the default comparator, `#!cpp std::less<>` must be able to
  compare two `StringType` values and a `StringType` with the key types used for lookup).

### Required for JSON Pointer, `flatten`, and `diff`

- A static member `npos`, and the member functions `find(const StringType&, size_type)`,
  `find_first_of(char, size_type)`, `substr(pos, count)`, and `replace(pos, count, const StringType&)` -- these
  implement the escaping and unescaping of reference tokens described in RFC 6901.
- Conversion of a `#!cpp std::size_t` to `StringType`: either the type is assignable from the result of
  `#!cpp std::to_string`, or an overload `#!cpp void int_to_string(StringType&, std::size_t)` must be found by ADL.
- `begin()` and `end()` -- used by
  [`operator[](const json_pointer&)`](../../api/basic_json/operator%5B%5D.md) to decide whether a reference token
  denotes an array index.
- Streamability to `#!cpp std::ostream` for `#!cpp operator<<(std::ostream&, const json_pointer&)`.

### Required for other functionality

| Functionality                                               | Additional requirement                            |
|-------------------------------------------------------------|---------------------------------------------------|
| [`to_bson`](../../api/basic_json/to_bson.md)                | `find(value_type)` and `npos`                     |
| [`std::hash<basic_json>`](../../api/basic_json/std_hash.md) | a specialization of `#!cpp std::hash<StringType>` |
| exception messages                                          | `data()` and `size()`, or `begin()` and `end()`   |

!!! tip "Reference implementation"

    The unit test `tests/src/unit-alt-string.cpp` contains `alt_string`, a minimal string type that satisfies the
    requirements needed for the tested subset of the API. It is a good starting point for a custom `StringType`.

## `BooleanType`

`boolean_t` is stored **directly** inside `basic_json`, as a member of an anonymous union.

### Always required

- A literal type that is trivially default-constructible, trivially copyable, and trivially destructible; otherwise the
  union's special member functions are deleted.
- Constructible from `#!cpp bool` via `#!cpp static_cast` and contextually convertible to `#!cpp bool`.
- Comparison operators `==`, `!=`, `<`, `<=`, `>`, `>=` (or `<=>`).
- Convertible from and to `#!cpp bool` through the serializer, because
  [`get<bool>()`](../../api/basic_json/get.md) is used internally.

There is little reason to use anything other than `#!cpp bool` here.

## `NumberIntegerType` and `NumberUnsignedType`

Both types are stored **directly** inside `basic_json`'s union.

### Always required

- `#!cpp std::is_integral` must be satisfied: `NumberIntegerType` must be a **signed** integer type,
  `NumberUnsignedType` an **unsigned** integer type. Class types are not supported -- among others, the constructors
  taking integer values are constrained on `#!cpp std::is_integral`.
- Trivially default-constructible, trivially copyable, and trivially destructible (union member).
- `#!cpp std::numeric_limits` must be specialized for both types.
- `NumberUnsignedType` must be able to represent the absolute value of every `NumberIntegerType` value; serialization
  of negative numbers converts the value to `NumberUnsignedType`.
- Both types must fit into the internal 64-character number buffer used by
  [`dump`](../../api/basic_json/dump.md), which is the case for all standard integer types.
- [`std::hash<basic_json>`](../../api/basic_json/std_hash.md) additionally requires `#!cpp std::hash` specializations.

### Notes

The number types influence what the parser accepts: an integer literal that does not round-trip through the chosen type
is stored as [`number_float_t`](../../api/basic_json/number_float_t.md) instead. Choosing types narrower than 64 bits
therefore silently changes parse results rather than raising an error. See
[Number Handling](number_handling.md) for details.

## `NumberFloatType`

`number_float_t` is stored **directly** inside `basic_json`'s union.

### Always required

- Trivially default-constructible, trivially copyable, and trivially destructible (union member).
- `#!cpp std::numeric_limits` must be specialized; `max_digits10` is used to size the conversion.
- `#!cpp std::isfinite` must be applicable to the type.

### Required for parsing and serialization

`NumberFloatType` must be one of `#!cpp float`, `#!cpp double`, or `#!cpp long double`:

- The [parser](../parsing/index.md) converts number literals with `#!cpp std::strtof`, `#!cpp std::strtod`, or
  `#!cpp std::strtold`; the library provides overloads for exactly these three types.
- [`dump`](../../api/basic_json/dump.md) falls back to `#!cpp std::snprintf` with the `%g` and `%Lg` conversion
  specifiers, for which the library likewise provides only `#!cpp double` and `#!cpp long double` overloads
  (`#!cpp float` is promoted to `#!cpp double`).

If `#!cpp std::numeric_limits<NumberFloatType>` describes an IEEE 754 binary32 or binary64 number, `dump` uses the
Grisu2 algorithm, which produces the shortest representation that round-trips. Otherwise the `snprintf` fallback with
`max_digits10` digits is used.

## `AllocatorType`

`AllocatorType` is instantiated with **one** argument, for each of `object_t`, `array_t`, `string_t`, `binary_t`,
`basic_json`, and `#!cpp std::pair<const StringType, basic_json>`.

### Always required

- The template must be usable with exactly one type argument. The library instantiates `AllocatorType<T>` directly and
  never uses `#!cpp std::allocator_traits<...>::rebind_alloc`.
- It must satisfy the [Allocator](https://en.cppreference.com/w/cpp/named_req/Allocator) named requirement so that
  `#!cpp std::allocator_traits` can be used with it.
- It must be **default-constructible and stateless**. Objects are allocated with a default-constructed allocator and
  deallocated with a *different* default-constructed allocator, and
  [`get_allocator()`](../../api/basic_json/get_allocator.md) returns a default-constructed instance. Allocators
  carrying state are not supported.
- It must support **incomplete types**: `AllocatorType<basic_json>` is instantiated inside the definition of
  `basic_json` itself.
- `#!cpp std::allocator_traits<AllocatorType<basic_json>>::pointer` becomes
  [`basic_json::pointer`](../../api/basic_json/index.md#container-types), and iterators are constructed from raw
  `#!cpp basic_json*` values. The `pointer` type must therefore be a plain pointer; fancy pointers are not supported.

## `JSONSerializer`

`JSONSerializer` is instantiated as `JSONSerializer<T, void>` and defaults to
[`adl_serializer`](../../api/adl_serializer/index.md).

### Always required

- The template must accept **two** type arguments, the second one defaulted (it exists so that partial specializations
  can be constrained by SFINAE).
- For every type `T` that is converted **to** a JSON value, a static member function
  `#!cpp static void to_json(basic_json&, T)` must exist.
- For every type `T` that is converted **from** a JSON value, either
  `#!cpp static void from_json(const basic_json&, T&)` or `#!cpp static T from_json(const basic_json&)` must exist.
  The latter form is required for types that are not default-constructible; see
  [Arbitrary Types Conversions](../arbitrary_types.md).
- To support the [converting constructor](../../api/basic_json/basic_json.md) between different `basic_json`
  specializations, `to_json` must be available for `boolean_t`, `number_integer_t`, `number_unsigned_t`,
  `number_float_t`, `string_t`, `object_t`, `array_t`, and `binary_t` of the *source* specialization.

## `BinaryType`

`BinaryType` is not a JSON type; it is used for the byte strings of the
[binary formats](../binary_formats/index.md). It is wrapped as

```cpp
using binary_t = nlohmann::byte_container_with_subtype<BinaryType>;
```

### Always required

- A non-`final` class type -- [`byte_container_with_subtype`](../../api/byte_container_with_subtype/index.md) derives
  from it publicly.
- A member type `value_type` that is **exactly one byte** wide (e.g., `#!cpp std::uint8_t`, `#!cpp char`, or
  `#!cpp std::byte`). Readers and writers reinterpret the container's storage as raw bytes, so a container such as
  `#!cpp std::vector<std::intptr_t>` produces wrong results.
- Contiguous storage: the binary readers `#!cpp std::memcpy` into `#!cpp &binary[n]`, the writers `reinterpret_cast`
  `data()`.
- Default-constructible, copy-constructible, and move-constructible.
- Member functions `size()`, `empty()`, `clear()`, `data()`, `resize()`, `push_back()`, `operator[]`, `back()`,
  `begin()`, `end()`, `cbegin()`, and `cend()` with random-access iterators.
- Comparison operators: `==` is used by
  [`byte_container_with_subtype`](../../api/byte_container_with_subtype/index.md), the relational operators by
  [`basic_json`'s comparison operators](../../api/basic_json/operator_le.md).

See [`binary_t`](../../api/basic_json/binary_t.md) for how a non-default `BinaryType` changes the meaning of assigning
such a container to a `basic_json` value.

## `CustomBaseClass`

`CustomBaseClass` is an extension point: unless it is `#!cpp void` (the default, which selects the empty
`nlohmann::json_default_base`), `basic_json` publicly derives from it.

### Always required

- A non-`final`, default-constructible class type.
- `basic_json` is copy-/move-constructible and copy-/move-assignable only if `CustomBaseClass` is.

### Notes

`basic_json` is documented to be a
[StandardLayoutType](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType). Because `basic_json` has
non-static data members of its own, a `CustomBaseClass` with non-static data members forfeits this guarantee.

Note the namespace of `CustomBaseClass` becomes an associated namespace of `basic_json` for the purpose of
argument-dependent lookup.

See [`json_base_class_t`](../../api/basic_json/json_base_class_t.md) for an example.

## Cross-specialization conversions

Converting a value from one `basic_json` specialization into another (see the
[converting constructor](../../api/basic_json/basic_json.md)) imposes two additional requirements that fail
**silently** rather than at compile time:

- The target `string_t` must be directly constructible from the source `string_t`. Otherwise the string is converted to
  an array of character codes.
- The target `object_t::key_type` must be directly constructible from the source object's key type. Otherwise the
  object is converted to an array of key/value pairs.

See [issue #3425](https://github.com/nlohmann/json/issues/3425), [`string_t`](../../api/basic_json/string_t.md), and
[`object_t`](../../api/basic_json/object_t.md).

## See also

- [Types](index.md) -- overview of how JSON values are stored
- [Number Handling](number_handling.md) -- how the number types affect parsing and serialization
- [Object Order](../object_order.md) -- using an insertion-ordered `ObjectType`
- [`basic_json`](../../api/basic_json/index.md) -- API documentation of the class template
