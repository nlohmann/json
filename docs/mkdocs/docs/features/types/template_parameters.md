# Template Parameter Requirements

Class [`basic_json`](../../api/basic_json/index.md) is configurable through eleven template parameters. The library
never formally states what a type passed for one of these parameters has to provide -- the requirements are implied by
the way the library uses the resulting [`object_t`](../../api/basic_json/object_t.md),
[`array_t`](../../api/basic_json/array_t.md), [`string_t`](../../api/basic_json/string_t.md), etc. This page collects
these requirements so they do not have to be discovered by trial and error. Each section lists the concrete types
that are known to work for that parameter and the ones that do not, checked against Boost 1.83, Abseil 20250127.0,
Folly, EASTL 3.21, `ankerl::unordered_dense`, `phmap`, `gtl`, `robin_hood`, `tsl::ordered_map`, and Qt 6.

## How to read this page

Requirements are split into two groups:

- **Always required** -- needed to instantiate `basic_json` at all, or needed by functions that virtually every program
  uses (construction, element access, [`dump`](../../api/basic_json/dump.md)).
- **Required for ...** -- only needed when a particular part of the API is instantiated. Member function templates are
  only instantiated when they are used, so a type may be perfectly usable even though it does not satisfy these
  requirements, as long as the corresponding functions are never called.

!!! warning "Requirements are not checked"

    Three requirements are checked with a `#!cpp static_assert`: the array iterator category, the width of
    [`BinaryType`](#binarytype)'s `value_type`, and [`NumberUnsignedType`](#numberintegertype-and-numberunsignedtype)
    being at least as wide as [`NumberIntegerType`](#numberintegertype-and-numberunsignedtype). The rest are not
    diagnosed with dedicated error messages, and violating most of them results in a compiler error somewhere inside
    the library. Four violations are not caught at compile time at all:

    - A [`StringType`](#stringtype) whose `data()` is not null-terminated compiles and silently misparses numbers,
      because the lexer hands the buffer to `#!cpp std::strtoull`/`#!cpp std::strtoll`/`#!cpp std::strtod`.
    - A stateful [`AllocatorType`](#allocatortype) compiles and silently ignores its state: allocation, deallocation,
      and [`get_allocator()`](../../api/basic_json/get_allocator.md) each use a different default-constructed instance.
    - The two [cross-specialization conversions](#cross-specialization-conversions) below. These abort on an assertion
      in a normal build, and only fail silently under `#!cpp NDEBUG`.

## Overview

| Template parameter                                                | Default                           | Notable substitutes                                                   |
|-------------------------------------------------------------------|-----------------------------------|-----------------------------------------------------------------------|
| [`ObjectType`](#objecttype)                                       | `std::map`                        | [`nlohmann::ordered_map`](../../api/ordered_map.md), Abseil hash maps |
| [`ArrayType`](#arraytype)                                         | `std::vector`                     | `#!cpp std::deque`                                                    |
| [`StringType`](#stringtype)                                       | `std::string`                     | `std::string`-like types over `char`                                  |
| [`BooleanType`](#booleantype)                                     | `bool`                            | none worth using                                                      |
| [`NumberIntegerType`](#numberintegertype-and-numberunsignedtype)  | `std::int64_t`                    | any signed integer type                                               |
| [`NumberUnsignedType`](#numberintegertype-and-numberunsignedtype) | `std::uint64_t`                   | any unsigned integer type at least as wide as `NumberIntegerType`     |
| [`NumberFloatType`](#numberfloattype)                             | `double`                          | `float` (`long double`: no binary formats)                            |
| [`AllocatorType`](#allocatortype)                                 | `std::allocator`                  | stateless allocators                                                  |
| [`JSONSerializer`](#jsonserializer)                               | `adl_serializer`                  | serializers with the same interface                                   |
| [`BinaryType`](#binarytype)                                       | `#!cpp std::vector<std::uint8_t>` | `#!cpp std::vector<char>`                                             |
| [`CustomBaseClass`](#custombaseclass)                             | `void`                            | any default-constructible class                                       |

!!! warning "Third-party containers and incomplete types"

    `object_t` is instantiated inside the definition of `basic_json` -- it is probed for a `key_compare` member to
    form [`object_comparator_t`](../../api/basic_json/object_comparator_t.md) -- i.e. while `basic_json` is still an
    incomplete type. `#!cpp std::map` is required by the standard to support incomplete mapped types; most
    third-party maps are not, and inspecting the mapped type at class scope (for instance with
    `#!cpp std::is_trivially_move_assignable`) makes them unusable as `ObjectType`, no matter how their template
    arguments are adapted. This rules out `absl::btree_map`, `phmap::btree_map`, `gtl::btree_map`,
    `robin_hood::unordered_node_map`, `folly::F14FastMap`, and `eastl::hash_map`.

    `array_t` is only *named* in the class definition and is not instantiated until `basic_json` is complete, so an
    `ArrayType` that inspects its value type at class scope is generally fine -- `boost::container::small_vector` and
    `static_vector` both reject incomplete value types yet work here. `absl::InlinedVector` is the exception: the
    `#!cpp std::is_trivially_move_assignable<basic_json>` it evaluates while instantiating itself re-enters the
    library's own trait machinery mid-instantiation.

!!! note "Folly requires C++20"

    Folly's headers use `#!cpp consteval` and `#!cpp std::type_identity`, so any `basic_json` specialization that
    names a Folly type has to be compiled as C++20 or later, whatever the rest of the library supports.

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
- An optional member type `key_compare`. If it is present it becomes
  [`object_comparator_t`](../../api/basic_json/object_comparator_t.md); otherwise
  [`default_object_comparator_t`](../../api/basic_json/default_object_comparator_t.md) is used.
- Member types `key_type`, `mapped_type`, `value_type`, and `iterator`.
- `value_type` must behave like `#!cpp std::pair<const key_type, mapped_type>`; the library accesses `.first` and
  `.second` on it.
- `iterator` must be default-constructible and satisfy
  [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator). The type returned
  by `cbegin()`/`cend()` must satisfy the same requirements.
- Constructors: default, copy, move, and from an iterator range `(first, last)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`,
  `find(key)`, `count(key)`, `emplace(key, value)`, `insert(value_type)`, `insert(first, last)`, `operator[](key)`,
  `erase(iterator)`, and `erase(first, last)`. `erase(iterator)` may return the following iterator or `#!cpp void`;
  in the latter case the library computes the successor itself, before erasing.
- `erase(key)` is **optional**: if the container does not provide one, the library falls back to `find(key)` followed
  by `erase(iterator)`.
- `at(key)` is required only by [`to_ubjson`](../../api/basic_json/to_ubjson.md) and
  [`to_bjdata`](../../api/basic_json/to_bjdata.md), but every container tried here provides it.
- `emplace` and `insert(value_type)` must return `#!cpp std::pair<iterator, bool>` and must have **unique-key**
  semantics; multimaps cannot be used.
- The type must be swappable (via `std::swap` or an ADL `swap`).
- The comparison operators `==` and `<`; `!=`, `<=`, `>`, and `>=` are derived from them. Where the library uses
  three-way comparison (C++20), `==` and `<=>` are required **instead** -- the six two-way operators do not satisfy
  it. They implement [`basic_json`'s comparison operators](../../api/basic_json/operator_eq.md).

### Required for heterogeneous key lookup

The overloads of [`at`](../../api/basic_json/at.md), [`operator[]`](../../api/basic_json/operator%5B%5D.md),
[`find`](../../api/basic_json/find.md), [`contains`](../../api/basic_json/contains.md),
[`count`](../../api/basic_json/count.md), [`erase`](../../api/basic_json/erase.md), and
[`value`](../../api/basic_json/value.md) that accept a key type other than `object_t::key_type` require

- a **transparent** comparator, i.e. [`object_comparator_t`](../../api/basic_json/object_comparator_t.md) has a member
  type `is_transparent` (this is why the default comparator is `#!cpp std::less<>` since C++14), and
- corresponding heterogeneous `find`, `count`, `erase`, and `operator[]` overloads on the container.

### Notes

#### `std::unordered_map` needs an adapter

`#!cpp std::unordered_map` cannot be passed directly: its third template parameter is a hash function, but
`basic_json` passes a comparator in that position. An alias template or wrapper that restores the expected argument
order makes it usable:

```cpp
template<class Key, class T, class IgnoredCompare, class Allocator>
struct unordered_map_object
    : std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
};

using unordered_json = nlohmann::basic_json<unordered_map_object>;
```

Whether `#!cpp std::unordered_map` can be instantiated at all depends on the standard library: `object_t` is formed
while `basic_json` is still incomplete (see the warning above), and libstdc++ 9 needs the size of the mapped type to
instantiate the hash map's node type, so the adapter does not compile there. Newer libstdc++ versions, and the hash
maps listed below, do not have that problem.

The adapter above works verbatim for Abseil's, Boost's, `phmap`'s and `gtl`'s hash maps, which all place the hash
function third and take a `#!cpp std::pair<const Key, T>` allocator fifth. Two need a different adapter:

- `ankerl::unordered_dense` expects an allocator over `#!cpp std::pair<Key, T>` (non-const key), so the allocator has
  to be rebound to that or dropped.
- `robin_hood`'s fifth parameter is the non-type `MaxLoadFactor100`, so its adapter must drop the allocator entirely.

None of these hash maps defines `key_compare`, so all of them additionally rely on `object_comparator_t` falling back
to [`default_object_comparator_t`](../../api/basic_json/default_object_comparator_t.md); see
[`object_comparator_t`](../../api/basic_json/object_comparator_t.md).

#### Abseil hash maps

`absl::flat_hash_map` and `absl::node_hash_map` tolerate an incomplete value type, but they take a hash function as
their third template argument. The same adapter as for `#!cpp std::unordered_map` makes them usable:

```cpp
template<class Key, class T, class IgnoredCompare, class Allocator>
struct flat_hash_object
    : absl::flat_hash_map<Key, T, absl::Hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = absl::flat_hash_map<Key, T, absl::Hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
};

using flat_hash_json = nlohmann::basic_json<flat_hash_object>;
```

`absl::node_hash_map` keeps references to the mapped values valid across insertions; `absl::flat_hash_map` does not,
which makes it behave like [`ordered_json`](../../api/ordered_json.md) with respect to
[iterator invalidation](../../api/basic_json/index.md#iterator-invalidation). Both expose a `capacity()` member
function, so [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) treats them conservatively and keeps the
parent pointers correct either way.

#### Iteration order

The library never relies on the container's iteration order for correctness; it does determine the order in which
object keys are serialized by [`dump`](../../api/basic_json/dump.md) and visited by
[`items`](../../api/basic_json/items.md). See [Object Order](../object_order.md).

#### `capacity()` marks a container as insertion-ordered

With [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) enabled, the library detects insertion-ordered maps by
probing for a `capacity()` member function (`nlohmann::ordered_map` inherits it from `std::vector`) and refreshes all
parent pointers after every insertion. An `ObjectType` that happens to have a `capacity()` member is therefore treated
conservatively -- this is correct, but slower.

#### Key order and duplicate keys

The library does not sort or de-duplicate keys itself; the behavior described in
[`object_t`](../../api/basic_json/object_t.md) is entirely the behavior of the chosen container.

!!! tip "Reference implementation"

    `docs/mkdocs/docs/examples/custom_object_type.hpp` wraps a private `#!cpp std::map` and satisfies every
    requirement above. It does not define `key_compare`, so `object_comparator_t` falls back to
    [`default_object_comparator_t`](../../api/basic_json/default_object_comparator_t.md) -- a good starting point for
    a custom `ObjectType`.

    ```cpp
    --8<-- "examples/custom_object_type.hpp"
    ```

??? example "Compiling and using it"

    ```cpp
    --8<-- "examples/custom_object_type.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/custom_object_type.output"
    ```

### Compatible containers

| Container                                                                        | Notes                                                                         |
|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `#!cpp std::map` (default)                                                       |                                                                               |
| [`nlohmann::ordered_map`](../../api/ordered_map.md)                              | used by [`ordered_json`](../../api/ordered_json.md); keeps insertion order    |
| [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map)                     | keeps insertion order; adapter puts `fifo_map_compare` in the comparator slot |
| `boost::container::map`, `boost::container::flat_map`                            | no adapter needed                                                             |
| `#!cpp std::unordered_map`                                                       | through the adapter above; not with libstdc++ 9, see the note                 |
| `boost::unordered_map`, `boost::unordered_flat_map`, `boost::unordered_node_map` | through the adapter above                                                     |
| `absl::flat_hash_map`, `absl::node_hash_map`                                     | through the adapter above; `flat_hash_map` moves mapped values on rehash      |
| `phmap::flat_hash_map`, `phmap::node_hash_map`, `gtl::flat_hash_map`             | through the adapter above                                                     |
| `ankerl::unordered_dense::map` and `segmented_map`                               | adapter must rebind or drop the allocator                                     |
| `robin_hood::unordered_flat_map`                                                 | adapter must drop the allocator                                               |
| `folly::F14NodeMap`                                                              | through the adapter above; requires C++20, see the note above                 |
| `folly::sorted_vector_map`                                                       | alias must drop the allocator, whose value type it disagrees on               |

### Containers that cannot be used

| Container                                                                | Reason                                                                                                              |
|--------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `absl::btree_map`, `phmap::btree_map`, `gtl::btree_map`                  | require a complete mapped type                                                                                      |
| `robin_hood::unordered_node_map`, `folly::F14FastMap`, `eastl::hash_map` | require a complete mapped type                                                                                      |
| `eastl::map`                                                             | EASTL iterators do not work with `#!cpp std::iterator_traits`                                                       |
| `tsl::ordered_map`                                                       | its iterators expose the mapped value as `#!cpp const`                                                              |
| `QMap`                                                                   | no `value_type` member type                                                                                         |
| `QHash`                                                                  | its `value_type` is the mapped type rather than a key/value pair, and its iterators dereference to the mapped value |
| `#!cpp std::multimap`, `#!cpp std::unordered_multimap`                   | `emplace` does not return `#!cpp std::pair<iterator, bool>`                                                         |

## `ArrayType`

`ArrayType` is instantiated as

```cpp
using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;
```

### Always required

- The template must be usable with **two** type arguments (value type and allocator).
- Member types `value_type` and `iterator`.
- Constructors: default, copy, and move; and from an iterator range `(first, last)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`,
  `operator[](size_type)`, `back()`, `push_back()`, `emplace_back()`, `pop_back()`, `resize()`,
  `insert()` (single element, count, and range), `erase(pos)`, and `erase(first, last)`.
  `basic_json::insert(pos, initializer_list)` goes through the range overload, so no initializer-list `insert` is
  needed. `at(size_type)` is **not** required: [`basic_json::at(size_type)`](../../api/basic_json/at.md) checks the
  index itself and then uses `operator[]`.
- `iterator` must be default-constructible, and it as well as the type returned by `cbegin()`/`cend()` must satisfy
  [LegacyRandomAccessIterator](https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator).
  A `#!cpp static_assert` only checks for
  [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator), but
  [`dump`](../../api/basic_json/dump.md) (`cend() - 1`),
  [`erase(idx)`](../../api/basic_json/erase.md) (`begin() + idx`), and the random-access operations of
  [`basic_json::iterator`](../../api/basic_json/begin.md) require random access.
- The comparison operators, as for [`ObjectType`](#objecttype): `==` and `<`, or `==` and `<=>` under C++20.

### Required for individual functions

- A member type `value_type`, for [`to_bson`](../../api/basic_json/to_bson.md) of an array.
- A constructor from `(count, value)`, for
  [`basic_json(size_type, const basic_json&)`](../../api/basic_json/basic_json.md).
- Swappability, via `#!cpp std::swap` or an ADL `swap`, for [`swap(array_t&)`](../../api/basic_json/swap.md).

!!! note "`capacity()` is optional"

    With [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) enabled, the library reads `array_t::capacity()`
    to find out whether adding an element reallocated the array and moved its elements, which would invalidate the
    parent pointers. An array type without a `capacity()` member function is handled conservatively: the parent
    pointers of all elements are refreshed after every insertion, which makes adding *n* elements cost O(*n*²). Only
    diagnostics builds pay this; without them `capacity()` is never called.

!!! tip "Reference implementation"

    `docs/mkdocs/docs/examples/custom_array_type.hpp` wraps a private `#!cpp std::vector` and satisfies every
    requirement above -- a good starting point for a custom `ArrayType`.

    ```cpp
    --8<-- "examples/custom_array_type.hpp"
    ```

??? example "Compiling and using it"

    ```cpp
    --8<-- "examples/custom_array_type.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/custom_array_type.output"
    ```

### Compatible containers

| Container                                               | Notes                                                                                     |
|---------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `#!cpp std::vector` (default)                           |                                                                                           |
| `#!cpp std::deque`                                      | references survive appends, but not insertions elsewhere; see the `capacity()` note above |
| `#!cpp std::pmr::vector`                                | through an alias, as the allocator comes from `AllocatorType` instead                     |
| `boost::container::vector`, `deque`, `devector`         |                                                                                           |
| `boost::container::stable_vector`                       | the only one tried that keeps references valid across *every* insertion                   |
| `boost::container::small_vector`, `folly::small_vector` | through an alias that fixes the inline capacity                                           |
| `boost::container::static_vector`                       | through the same kind of alias, for arrays that stay within the fixed capacity            |
| `folly::fbvector`                                       | requires C++20, see the note above                                                        |

### Containers that cannot be used

| Container                           | Reason                                                                                        |
|-------------------------------------|-----------------------------------------------------------------------------------------------|
| `#!cpp std::list`                   | no `operator[]`, and no random-access iterators                                               |
| `eastl::vector`, `QList`, `QVector` | no `max_size()`; they handle the incomplete value type fine                                   |
| `absl::InlinedVector`               | requires a complete value type, see the note above                                            |
| `absl::FixedArray`                  | the size is fixed at construction, so `resize`, `push_back`, `insert` and `erase` are missing |

## `StringType`

`StringType` is used **both** for JSON string values and for the keys of JSON objects
(`string_t` and `object_t::key_type`).

### Always required

- A member type `value_type` that is one byte wide and `char`-compatible. The library stores and processes UTF-8
  encoded `char` data and hands `data()` to `#!cpp std::strtoull`/`#!cpp std::strtoll`.
  `#!cpp std::wstring`, `#!cpp std::u16string`, and `#!cpp std::u32string` are **not** valid choices; see the FAQ on
  [wide string handling](../../home/faq.md#wide-string-handling).
- Constructors: default, copy, move, from `#!cpp const char*` (which must not be `#!cpp explicit`), from
  `#!cpp (const char*, size_type)`, and from `#!cpp (size_type, char)`; and copy or move assignment.
- Member functions `size()`, `clear()`, `resize(n, c)`, `data()`, `push_back(char)`, and `operator[]`
  (const and non-const, returning references). `c_str()` and `back()` are **not** required.
- `data()` must return a pointer to a contiguous, **null-terminated** buffer -- the parser hands it to
  `#!cpp std::strtoull`. A type whose `data()` is not null-terminated does not fail to compile; it silently
  misparses numbers.
- `append(const char*, size_type)`, used by [`dump`](../../api/basic_json/dump.md), and `append(const StringType&)`,
  used by the CBOR reader for indefinite-length strings. The library's internal string concatenation additionally has
  to append a `#!cpp char` and a `#!cpp const char*`; for each it selects between `append(arg)`, `#!cpp operator+=`,
  `append(first, last)`, and `append(data, size)`.
- The comparison operator `==` against another `StringType`, and `<` for use as a key of the chosen
  [`ObjectType`](#objecttype) (with the default comparator, `#!cpp std::less<>` must be able to compare two
  `StringType` values, and a `StringType` with the key types used for lookup). `!=` is never applied to a
  `StringType`, and `==` against `#!cpp const char*` is resolved by the implicit `#!cpp const char*` constructor.

### Required for the binary formats

- `resize(n)`, used by the readers to make room for a block of bytes.
- Non-const `operator[]`, into which the readers `#!cpp std::memcpy` those bytes. A non-`#!cpp const` `data()` would
  serve just as well, but `#!cpp std::string` has only had one since C++17, and the library still supports C++11.

### Required for JSON Pointer, `flatten`, and `diff`

- A static member `npos` and the member function `find_first_of(char, size_type)` -- together with `data()`,
  `reserve(n)`, and `append(const char*, size_type)` they implement the escaping and unescaping of reference tokens
  described in RFC 6901. Neither `find(const StringType&, size_type)`, nor `substr(pos, count)`, nor
  `replace(pos, count, const StringType&)` is required.
- `empty()`.
- `begin()` and `end()` -- used by
  [`operator[](const json_pointer&)`](../../api/basic_json/operator%5B%5D.md) to decide whether a reference token
  denotes an array index.

### Required for other functionality

| Functionality                                                                                                                     | Additional requirement                                                                                                                                                                       |
|-----------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`diff`](../../api/basic_json/diff.md), [`items`](../../api/basic_json/items.md), [`std::hash`](../../api/basic_json/std_hash.md) | conversion of a `#!cpp std::size_t` to `StringType`: either assignability from the result of `#!cpp std::to_string`, or an ADL overload `#!cpp void int_to_string(StringType&, std::size_t)` |
| [`std::hash<basic_json>`](../../api/basic_json/std_hash.md)                                                                       | additionally a specialization of `#!cpp std::hash<StringType>`                                                                                                                               |
| [`to_bson`](../../api/basic_json/to_bson.md)                                                                                      | `find(value_type)` and `npos`                                                                                                                                                                |
| [`parse`](../../api/basic_json/parse.md) from a `string_t`                                                                        | the input adapters must accept it; otherwise pass a character range                                                                                                                          |
| `#!cpp operator<<(std::ostream&, const json_pointer&)`                                                                            | streamability to `#!cpp std::ostream`                                                                                                                                                        |
| exception messages                                                                                                                | `data()` and `size()`, or `begin()` and `end()`                                                                                                                                              |

### Compatible types

| Type                                                            | Notes                                                                                                                                                                                                                                         |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `#!cpp std::string` (default)                                   |                                                                                                                                                                                                                                               |
| `#!cpp std::basic_string` with a custom **stateless** allocator |                                                                                                                                                                                                                                               |
| `#!cpp std::pmr::string`                                        | see the warning below before relying on the memory resource                                                                                                                                                                                   |
| `boost::container::string`                                      | needs a user-supplied `#!cpp std::hash` specialization (Boost provides `boost::hash` instead)                                                                                                                                                 |
| `folly::fbstring`                                               | requires C++20, see the note above                                                                                                                                                                                                            |
| `eastl::string`                                                 | needs a user-supplied `#!cpp std::hash` and an ADL `int_to_string` (it is not assignable from a `#!cpp std::string`); [`parse`](../../api/basic_json/parse.md) does not accept it directly -- pass a character range or a `#!cpp std::string` |
| a custom string class in a user-defined namespace               | if the requirements above are met                                                                                                                                                                                                             |

### Types that cannot be used

| Type                                                                 | Reason                                                                                                  |
|----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `#!cpp std::wstring`, `#!cpp std::u16string`, `#!cpp std::u32string` | the character type is not one byte wide                                                                 |
| `#!cpp std::u8string`                                                | one byte wide, but `#!cpp char8_t` is not `#!cpp char`-compatible                                       |
| `absl::Cord`                                                         | no `value_type`, and the storage is not contiguous                                                      |
| `QString`                                                            | no `append(const char*, size_type)`; its `QChar` is also two bytes wide, though that is never diagnosed |

!!! warning "A `std::pmr::string` mostly does not use the memory resource you choose"

    `basic_json` cannot be given an allocator or a memory resource. `AllocatorType` is default-constructed at every
    allocation and has to be stateless (see [`AllocatorType`](#allocatortype)), and string values the library creates
    are constructed with their own default allocator. So:

    - Every string the library itself produces -- from [`parse`](../../api/basic_json/parse.md), from
      [`dump`](../../api/basic_json/dump.md), or by default construction -- allocates from
      `#!cpp std::pmr::get_default_resource()`.
    - **Copying** an arena-backed string into a value silently drops its memory resource: the copy lands on the
      default resource, because `#!cpp std::pmr::polymorphic_allocator` does not propagate on copy construction.
      Nothing warns about this.
    - **Moving** one in does keep it, and later growth still allocates from that arena -- but it does not survive a
      copy of the enclosing `basic_json`.
    - Passing `#!cpp std::pmr::polymorphic_allocator` as `AllocatorType` does not work around any of this; it does
      not compile.

    Apart from moving a string in, the only way to redirect these allocations is the process-global
    `#!cpp std::pmr::set_default_resource()`.

!!! tip "Reference implementation"

    `docs/mkdocs/docs/examples/custom_string_type.hpp` wraps a private `#!cpp std::string` and satisfies every
    requirement above -- a good starting point for a custom `StringType`. The unit test
    `tests/src/unit-alt-string.cpp` contains a more thorough variant, `alt_string`, exercised against a larger part
    of the API.

    ```cpp
    --8<-- "examples/custom_string_type.hpp"
    ```

??? example "Compiling and using it"

    ```cpp
    --8<-- "examples/custom_string_type.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/custom_string_type.output"
    ```

## `BooleanType`

`boolean_t` is stored **directly** inside `basic_json`, as a member of an anonymous union.

### Always required

- A literal type that is trivially default-constructible, trivially copyable, and trivially destructible; otherwise the
  union's special member functions are deleted.
- **Implicitly** convertible from `#!cpp bool` -- an `#!cpp explicit` constructor is not enough, because the
  `to_json` overload for a custom `BooleanType` is constrained on `#!cpp std::is_convertible` -- and contextually
  convertible to `#!cpp bool` (here an `#!cpp explicit operator bool` is fine).
- Comparison operators `==`, `!=`, `<`, `<=`, `>`, `>=` (or `<=>`).
- Convertible from and to `#!cpp bool` through the serializer, because
  [`get<bool>()`](../../api/basic_json/get.md) is used internally.

There is little reason to use anything other than `#!cpp bool` here.

### Compatible types

`#!cpp bool` is the only usable choice. Another trivially copyable type that is implicitly convertible to and from
`#!cpp bool` -- `#!cpp std::uint8_t`, say -- does compile, and JSON booleans still round-trip, but the type then
serves as both `boolean_t` and an ordinary integer: `basic_json` can no longer be constructed or assigned from a
`#!cpp std::uint8_t` at all (the boolean and unsigned-integer `to_json` overloads become ambiguous), and
[`get<std::uint8_t>()`](../../api/basic_json/get.md) on a number throws
[`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) instead of returning the value.

## `NumberIntegerType` and `NumberUnsignedType`

Both types are stored **directly** inside `basic_json`'s union.

### Always required

- `#!cpp std::is_integral` must be satisfied: `NumberIntegerType` must be a **signed** integer type,
  `NumberUnsignedType` an **unsigned** integer type. Class types are not supported -- among others, the constructors
  taking integer values are constrained on `#!cpp std::is_integral`.
- Trivially default-constructible, trivially copyable, and trivially destructible (union member).
- `#!cpp std::numeric_limits` must be specialized for both types.
- `NumberUnsignedType` must be able to represent the absolute value of every `NumberIntegerType` value; serialization
  of negative numbers converts the value to `NumberUnsignedType`. A `#!cpp static_assert` requires it to be at least as
  wide as `NumberIntegerType`, which is what that amounts to for the standard integer types.
- Both types must fit into the internal 64-character number buffer used by
  [`dump`](../../api/basic_json/dump.md), which is the case for all standard integer types.
- [`std::hash<basic_json>`](../../api/basic_json/std_hash.md) additionally requires `#!cpp std::hash` specializations.

### Notes

The number types influence what the parser accepts: an integer literal that does not round-trip through the chosen type
is stored as [`number_float_t`](../../api/basic_json/number_float_t.md) instead. Choosing types narrower than 64 bits
therefore silently changes parse results rather than raising an error. See
[Number Handling](number_handling.md) for details.

### Compatible types

| Type pair                                                                                    | Support                                                                                                                                                                                          |
|----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `#!cpp std::int64_t` / `#!cpp std::uint64_t` (default)                                       | full                                                                                                                                                                                             |
| `#!cpp std::int32_t` / `#!cpp std::uint32_t`, `#!cpp long long` / `#!cpp unsigned long long` | full; narrower types change which literals the parser can represent                                                                                                                              |
| any other pair of standard signed/unsigned integer types                                     | full                                                                                                                                                                                             |
| class types, enumerations                                                                    | not usable; `#!cpp std::is_integral` must hold                                                                                                                                                   |
| `#!cpp bool`, or a type already used for another member of the union                         | not usable; `#!cpp std::is_integral<bool>` is in fact `#!cpp true`, but the `get_impl_ptr` overloads for `boolean_t`, `number_integer_t`, `number_unsigned_t` and `number_float_t` would collide |

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

### Required for the binary formats

`NumberFloatType` must be `#!cpp float` or `#!cpp double`. The writers for
[CBOR, MessagePack, UBJSON, BJData, and BSON](../binary_formats/index.md) map a floating-point value onto an IEEE 754
binary32 or binary64 field and have no encoding for `#!cpp long double`.

### Compatible types

| Type                     | Support                                                                                                               |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `#!cpp double` (default) | full; short round-trip output through Grisu2                                                                          |
| `#!cpp float`            | full; short round-trip output through Grisu2                                                                          |
| `#!cpp long double`      | `dump` and `parse` only; the binary format writers do not compile, as they only handle IEEE 754 binary32 and binary64 |
| any other type           | not usable                                                                                                            |

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
  carrying state are not supported, so there is no way to tell a `basic_json` where to allocate from; see the note
  under [`StringType`](#stringtype) for what that means in practice. A stateful allocator is **not diagnosed**: it
  compiles and silently ignores the state.
- It must support **incomplete types**: `AllocatorType<basic_json>` is instantiated inside the definition of
  `basic_json` itself.
- `#!cpp std::allocator_traits<AllocatorType<basic_json>>::pointer` becomes
  [`basic_json::pointer`](../../api/basic_json/index.md#container-types), and iterators are constructed from raw
  `#!cpp basic_json*` values. The `pointer` type must therefore be a plain pointer; fancy pointers are not supported.

### Compatible types

| Type                                                              | Support                                |
|-------------------------------------------------------------------|----------------------------------------|
| `#!cpp std::allocator` (default)                                  | full                                   |
| a custom stateless allocator template                             | full                                   |
| stateful allocators, e.g. `#!cpp std::pmr::polymorphic_allocator` | not usable; see the requirements above |

## `JSONSerializer`

`JSONSerializer` is instantiated as `JSONSerializer<T, void>` and defaults to
[`adl_serializer`](../../api/adl_serializer/index.md).

### Always required

- The template must accept **two** type arguments. It does not have to give the second one a default -- `basic_json`
  declares the parameter as `#!cpp template<typename T, typename SFINAE = void> class JSONSerializer`, so uses such as
  `#!cpp JSONSerializer<T>` inside the library supply `#!cpp void` themselves. The second parameter exists so that
  partial specializations can be constrained by SFINAE.
- For every type `T` that is converted **to** a JSON value, a static member function
  `#!cpp static void to_json(basic_json&, T)` must exist.
- For every type `T` that is converted **from** a JSON value, either
  `#!cpp static void from_json(const basic_json&, T&)` or `#!cpp static T from_json(const basic_json&)` must exist.
  The latter form is required for types that are not default-constructible; see
  [Arbitrary Types Conversions](../arbitrary_types.md).
- To support the [converting constructor](../../api/basic_json/basic_json.md) between different `basic_json`
  specializations, `to_json` must be available for `boolean_t`, `number_integer_t`, `number_unsigned_t`,
  `number_float_t`, `string_t`, `object_t`, `array_t`, and `binary_t` of the *source* specialization.

### Compatible types

| Type                                                                      | Support                                                           |
|---------------------------------------------------------------------------|-------------------------------------------------------------------|
| [`nlohmann::adl_serializer`](../../api/adl_serializer/index.md) (default) | full                                                              |
| a class template deriving from `adl_serializer`                           | full; the usual way to change behavior while keeping the defaults |
| an unrelated template with the same interface                             | full, but it has to handle every type the library converts        |

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
  `#!cpp std::byte`). Readers and writers reinterpret the container's storage as raw bytes, so a wider `value_type` is
  rejected with a `#!cpp static_assert`.
- Contiguous storage: the binary readers `#!cpp std::memcpy` into `#!cpp &binary[n]`, the writers `reinterpret_cast`
  `data()`. `#!cpp data() + n` would do for the readers too, but they share one helper with
  [`StringType`](#stringtype), whose non-`#!cpp const` `data()` is C++17 and later only.
- Default-constructible, copy-constructible, and move-constructible.
- Member functions `size()`, `empty()`, `data()`, `resize()`, `operator[]`, `back()`, `begin()`, `end()`, `cbegin()`,
  and `cend()` with random-access iterators, and `insert(pos, first, last)`, which the CBOR reader uses to join the
  chunks of an indefinite-length byte string. `push_back()` is **not** required.
- Comparison operators: `==` is used by
  [`byte_container_with_subtype`](../../api/byte_container_with_subtype/index.md), the relational operators by
  [`basic_json`'s comparison operators](../../api/basic_json/operator_le.md).

### Required for individual functions

- `clear()`, for [`basic_json::clear()`](../../api/basic_json/clear.md).

`max_size()`, `at()`, `reserve()`, `erase()`, `pop_back()`, and `emplace_back()` are **not** used at all.

See [`binary_t`](../../api/basic_json/binary_t.md) for how a non-default `BinaryType` changes the meaning of assigning
such a container to a `basic_json` value.

!!! tip "Reference implementation"

    `docs/mkdocs/docs/examples/custom_binary_type.hpp` wraps a private `#!cpp std::vector<std::uint8_t>` and satisfies
    every requirement above -- a good starting point for a custom `BinaryType`.

    ```cpp
    --8<-- "examples/custom_binary_type.hpp"
    ```

??? example "Compiling and using it"

    ```cpp
    --8<-- "examples/custom_binary_type.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/custom_binary_type.output"
    ```

### Compatible containers

| Container                                                                                   | Notes                                                                     |
|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `#!cpp std::vector<std::uint8_t>` (default)                                                 |                                                                           |
| `#!cpp std::vector<char>`, `#!cpp std::vector<std::byte>`                                   | `dump()` writes the bytes as 0..255 whichever is used                     |
| `boost::container::vector<std::uint8_t>`, `boost::container::small_vector<std::uint8_t, N>` |                                                                           |
| `absl::InlinedVector<std::uint8_t, N>`                                                      | usable here, unlike as an `ArrayType`, because the value type is complete |
| `eastl::vector<std::uint8_t>`                                                               | usable here, unlike as an `ArrayType`, because `max_size()` is not needed |
| `folly::fbvector<std::uint8_t>`                                                             | requires C++20, see the note above                                        |

### Containers that cannot be used

| Container                                            | Reason                                                                                                                                                                                             |
|------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `QByteArray`                                         | no `empty()` (it spells that `isEmpty()`); its `insert` takes an index rather than an iterator; and it converts to `string_t`, which makes `to_json` ambiguous between a string and a binary value |
| `#!cpp std::string`                                  | `binary_t::container_type` and `string_t` would be the same type, so the two [`swap`](../../api/basic_json/swap.md) overloads collide and `basic_json` cannot be instantiated at all               |
| `#!cpp std::deque<std::uint8_t>`                     | storage is not contiguous, so there is no `data()`                                                                                                                                                 |
| containers whose `value_type` is wider than one byte | see above -- accepted by the compiler, wrong at runtime                                                                                                                                            |

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

### Compatible types

| Type                                         | Support                                                                    |
|----------------------------------------------|----------------------------------------------------------------------------|
| `#!cpp void` (default)                       | an empty base class is used; no effect on `basic_json`                     |
| any default-constructible, non-`final` class | full; see [`json_base_class_t`](../../api/basic_json/json_base_class_t.md) |

## Cross-specialization conversions

Converting a value from one `basic_json` specialization into another (see the
[converting constructor](../../api/basic_json/basic_json.md)) imposes two additional requirements that are not
diagnosed at compile time. With assertions enabled they abort on the `#!cpp JSON_ASSERT` at the end of the converting
constructor; under `#!cpp NDEBUG` they fail **silently** at runtime:

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
