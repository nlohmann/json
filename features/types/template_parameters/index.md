# Template Parameter Requirements

Class [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) is configurable through eleven template parameters. The library never formally states what a type passed for one of these parameters has to provide -- the requirements are implied by the way the library uses the resulting [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md), [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), etc. This page collects these requirements so they do not have to be discovered by trial and error. Each section lists the concrete types that are known to work for that parameter and the ones that do not, checked against Boost 1.83, Abseil 20250127.0, Folly, EASTL 3.21, `ankerl::unordered_dense`, `phmap`, `gtl`, `robin_hood`, `tsl::ordered_map`, and Qt 6.

## How to read this page

Requirements are split into two groups:

- **Always required** -- needed to instantiate `basic_json` at all, or needed by functions that virtually every program uses (construction, element access, [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md)).
- **Required for ...** -- only needed when a particular part of the API is instantiated. Member function templates are only instantiated when they are used, so a type may be perfectly usable even though it does not satisfy these requirements, as long as the corresponding functions are never called.

Requirements are not checked

Three requirements are checked with a `static_assert`: the array iterator category, the width of [`BinaryType`](#binarytype)'s `value_type`, and [`NumberUnsignedType`](#numberintegertype-and-numberunsignedtype) being at least as wide as [`NumberIntegerType`](#numberintegertype-and-numberunsignedtype). The rest are not diagnosed with dedicated error messages, and violating most of them results in a compiler error somewhere inside the library. Four violations are not caught at compile time at all:

- A [`StringType`](#stringtype) whose `data()` is not null-terminated compiles and silently misparses numbers, because the lexer hands the buffer to `std::strtoull`/`std::strtoll`/`std::strtod`.
- A stateful [`AllocatorType`](#allocatortype) compiles and silently ignores its state: allocation, deallocation, and [`get_allocator()`](https://json.nlohmann.me/api/basic_json/get_allocator/index.md) each use a different default-constructed instance.
- The two [cross-specialization conversions](#cross-specialization-conversions) below. These abort on an assertion in a normal build, and only fail silently under `NDEBUG`.

## Overview

| Template parameter                                                | Default                     | Notable substitutes                                                                            |
| ----------------------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------- |
| [`ObjectType`](#objecttype)                                       | `std::map`                  | [`nlohmann::ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md), Abseil hash maps |
| [`ArrayType`](#arraytype)                                         | `std::vector`               | `std::deque`                                                                                   |
| [`StringType`](#stringtype)                                       | `std::string`               | `std::string`-like types over `char`                                                           |
| [`BooleanType`](#booleantype)                                     | `bool`                      | none worth using                                                                               |
| [`NumberIntegerType`](#numberintegertype-and-numberunsignedtype)  | `std::int64_t`              | any signed integer type                                                                        |
| [`NumberUnsignedType`](#numberintegertype-and-numberunsignedtype) | `std::uint64_t`             | any unsigned integer type at least as wide as `NumberIntegerType`                              |
| [`NumberFloatType`](#numberfloattype)                             | `double`                    | `float` (`long double`: no binary formats)                                                     |
| [`AllocatorType`](#allocatortype)                                 | `std::allocator`            | stateless allocators                                                                           |
| [`JSONSerializer`](#jsonserializer)                               | `adl_serializer`            | serializers with the same interface                                                            |
| [`BinaryType`](#binarytype)                                       | `std::vector<std::uint8_t>` | `std::vector<char>`                                                                            |
| [`CustomBaseClass`](#custombaseclass)                             | `void`                      | any default-constructible class                                                                |

Third-party containers and incomplete types

`object_t` is instantiated inside the definition of `basic_json` -- it is probed for a `key_compare` member to form [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md) -- i.e. while `basic_json` is still an incomplete type. `std::map` is required by the standard to support incomplete mapped types; most third-party maps are not, and inspecting the mapped type at class scope (for instance with `std::is_trivially_move_assignable`) makes them unusable as `ObjectType`, no matter how their template arguments are adapted. This rules out `absl::btree_map`, `phmap::btree_map`, `gtl::btree_map`, `robin_hood::unordered_node_map`, `folly::F14FastMap`, and `eastl::hash_map`.

`array_t` is only *named* in the class definition and is not instantiated until `basic_json` is complete, so an `ArrayType` that inspects its value type at class scope is generally fine -- `boost::container::small_vector` and `static_vector` both reject incomplete value types yet work here. `absl::InlinedVector` is the exception: the `std::is_trivially_move_assignable<basic_json>` it evaluates while instantiating itself re-enters the library's own trait machinery mid-instantiation.

Folly requires C++20

Folly's headers use `consteval` and `std::type_identity`, so any `basic_json` specialization that names a Folly type has to be compiled as C++20 or later, whatever the rest of the library supports.

## `ObjectType`

`ObjectType` is instantiated as

```
using object_t = ObjectType<StringType,                                    // key_type
                            basic_json,                                    // mapped_type
                            default_object_comparator_t,                   // key_compare
                            AllocatorType<std::pair<const StringType,
                                                    basic_json>>>;         // allocator_type
```

i.e., the template arguments follow the order and meaning of `std::map`.

### Always required

- The template must be usable with **four** type arguments in the order shown above. The third argument is a **comparator**; containers that expect something else in this position (e.g., a hash function) need an alias template or wrapper -- see [Notes](#notes).
- An optional member type `key_compare`. If it is present it becomes [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md); otherwise [`default_object_comparator_t`](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md) is used.
- Member types `key_type`, `mapped_type`, `value_type`, and `iterator`.
- `value_type` must behave like `std::pair<const key_type, mapped_type>`; the library accesses `.first` and `.second` on it.
- `iterator` must be default-constructible and satisfy [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator). The type returned by `cbegin()`/`cend()` must satisfy the same requirements.
- Constructors: default, copy, move, and from an iterator range `(first, last)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`, `find(key)`, `count(key)`, `emplace(key, value)`, `insert(value_type)`, `insert(first, last)`, `operator[](key)`, `erase(iterator)`, and `erase(first, last)`. `erase(iterator)` may return the following iterator or `void`; in the latter case the library computes the successor itself, before erasing.
- `erase(key)` is **optional**: if the container does not provide one, the library falls back to `find(key)` followed by `erase(iterator)`.
- `at(key)` is required only by [`to_ubjson`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) and [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md), but every container tried here provides it.
- `emplace` and `insert(value_type)` must return `std::pair<iterator, bool>` and must have **unique-key** semantics; multimaps cannot be used.
- The type must be swappable (via `std::swap` or an ADL `swap`).
- The comparison operators `==` and `<`; `!=`, `<=`, `>`, and `>=` are derived from them. Where the library uses three-way comparison (C++20), `==` and `<=>` are required **instead** -- the six two-way operators do not satisfy it. They implement [`basic_json`'s comparison operators](https://json.nlohmann.me/api/basic_json/operator_eq/index.md).

### Required for heterogeneous key lookup

The overloads of [`at`](https://json.nlohmann.me/api/basic_json/at/index.md), [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md), [`find`](https://json.nlohmann.me/api/basic_json/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md), [`count`](https://json.nlohmann.me/api/basic_json/count/index.md), [`erase`](https://json.nlohmann.me/api/basic_json/erase/index.md), and [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) that accept a key type other than `object_t::key_type` require

- a **transparent** comparator, i.e. [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md) has a member type `is_transparent` (this is why the default comparator is `std::less<>` since C++14), and
- corresponding heterogeneous `find`, `count`, `erase`, and `operator[]` overloads on the container.

### Notes

#### `std::unordered_map` needs an adapter

`std::unordered_map` cannot be passed directly: its third template parameter is a hash function, but `basic_json` passes a comparator in that position. An alias template or wrapper that restores the expected argument order makes it usable:

```
template<class Key, class T, class IgnoredCompare, class Allocator>
struct unordered_map_object
    : std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
};

using unordered_json = nlohmann::basic_json<unordered_map_object>;
```

Whether `std::unordered_map` can be instantiated at all depends on the standard library: `object_t` is formed while `basic_json` is still incomplete (see the warning above), and libstdc++ 9 needs the size of the mapped type to instantiate the hash map's node type, so the adapter does not compile there. Newer libstdc++ versions, and the hash maps listed below, do not have that problem.

The adapter above works verbatim for Abseil's, Boost's, `phmap`'s and `gtl`'s hash maps, which all place the hash function third and take a `std::pair<const Key, T>` allocator fifth. Two need a different adapter:

- `ankerl::unordered_dense` expects an allocator over `std::pair<Key, T>` (non-const key), so the allocator has to be rebound to that or dropped.
- `robin_hood`'s fifth parameter is the non-type `MaxLoadFactor100`, so its adapter must drop the allocator entirely.

None of these hash maps defines `key_compare`, so all of them additionally rely on `object_comparator_t` falling back to [`default_object_comparator_t`](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md); see [`object_comparator_t`](https://json.nlohmann.me/api/basic_json/object_comparator_t/index.md).

#### Abseil hash maps

`absl::flat_hash_map` and `absl::node_hash_map` tolerate an incomplete value type, but they take a hash function as their third template argument. The same adapter as for `std::unordered_map` makes them usable:

```
template<class Key, class T, class IgnoredCompare, class Allocator>
struct flat_hash_object
    : absl::flat_hash_map<Key, T, absl::Hash<Key>, std::equal_to<Key>, Allocator>
{
    using base_t = absl::flat_hash_map<Key, T, absl::Hash<Key>, std::equal_to<Key>, Allocator>;
    using base_t::base_t;
};

using flat_hash_json = nlohmann::basic_json<flat_hash_object>;
```

`absl::node_hash_map` keeps references to the mapped values valid across insertions; `absl::flat_hash_map` does not, which makes it behave like [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) with respect to [iterator invalidation](https://json.nlohmann.me/api/basic_json/#iterator-invalidation). Both expose a `capacity()` member function, so [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) treats them conservatively and keeps the parent pointers correct either way.

#### Iteration order

The library never relies on the container's iteration order for correctness; it does determine the order in which object keys are serialized by [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) and visited by [`items`](https://json.nlohmann.me/api/basic_json/items/index.md). See [Object Order](https://json.nlohmann.me/features/object_order/index.md).

#### `capacity()` marks a container as insertion-ordered

With [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) enabled, the library detects insertion-ordered maps by probing for a `capacity()` member function (`nlohmann::ordered_map` inherits it from `std::vector`) and refreshes all parent pointers after every insertion. An `ObjectType` that happens to have a `capacity()` member is therefore treated conservatively -- this is correct, but slower.

#### Key order and duplicate keys

The library does not sort or de-duplicate keys itself; the behavior described in [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md) is entirely the behavior of the chosen container.

Reference implementation

`docs/mkdocs/docs/examples/custom_object_type.hpp` wraps a private `std::map` and satisfies every requirement above. It does not define `key_compare`, so `object_comparator_t` falls back to [`default_object_comparator_t`](https://json.nlohmann.me/api/basic_json/default_object_comparator_t/index.md) -- a good starting point for a custom `ObjectType`.

```
#pragma once

#include <map>
#include <utility>

// A minimal, self-contained ObjectType built around a private std::map.
// key_compare is deliberately not exposed: when an ObjectType has no
// key_compare member, the library falls back to its own default comparator.
// See https://json.nlohmann.me/features/types/template_parameters/#objecttype
template<class Key, class T, class Compare, class Allocator>
class custom_object_type
{
    using map_t = std::map<Key, T, Compare, Allocator>;
    map_t data_;

  public:
    using key_type = typename map_t::key_type;
    using mapped_type = typename map_t::mapped_type;
    using value_type = typename map_t::value_type;
    using size_type = typename map_t::size_type;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;

    custom_object_type() = default;
    custom_object_type(const custom_object_type&) = default;
    custom_object_type(custom_object_type&&) = default;
    custom_object_type& operator=(const custom_object_type&) = default;
    custom_object_type& operator=(custom_object_type&&) = default;

    template<class InputIt>
    custom_object_type(InputIt first, InputIt last) : data_(first, last) {}

    iterator begin()
    {
        return data_.begin();
    }
    iterator end()
    {
        return data_.end();
    }
    const_iterator begin() const
    {
        return data_.begin();
    }
    const_iterator end() const
    {
        return data_.end();
    }
    const_iterator cbegin() const
    {
        return data_.cbegin();
    }
    const_iterator cend() const
    {
        return data_.cend();
    }

    bool empty() const
    {
        return data_.empty();
    }
    size_type size() const
    {
        return data_.size();
    }
    size_type max_size() const
    {
        return data_.max_size();
    }
    void clear()
    {
        data_.clear();
    }

    iterator find(const key_type& key)
    {
        return data_.find(key);
    }
    const_iterator find(const key_type& key) const
    {
        return data_.find(key);
    }
    size_type count(const key_type& key) const
    {
        return data_.count(key);
    }

    std::pair<iterator, bool> emplace(const key_type& key, const mapped_type& value)
    {
        return data_.emplace(key, value);
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        return data_.insert(value);
    }

    template<class InputIt>
    void insert(InputIt first, InputIt last)
    {
        data_.insert(first, last);
    }

    mapped_type& operator[](const key_type& key)
    {
        return data_[key];
    }

    mapped_type& at(const key_type& key)
    {
        return data_.at(key);
    }
    const mapped_type& at(const key_type& key) const
    {
        return data_.at(key);
    }

    iterator erase(iterator pos)
    {
        return data_.erase(pos);
    }
    iterator erase(iterator first, iterator last)
    {
        return data_.erase(first, last);
    }
    size_type erase(const key_type& key)
    {
        return data_.erase(key);
    }

    void swap(custom_object_type& other)
    {
        data_.swap(other.data_);
    }

    friend bool operator==(const custom_object_type& lhs, const custom_object_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_object_type& lhs, const custom_object_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
```

Compiling and using it

```
#include <iostream>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_object_type.hpp"

using custom_json = nlohmann::basic_json<custom_object_type, std::vector>;

int main()
{
    custom_json j;
    j["pi"] = 3.141;
    j["happy"] = true;
    j["list"] = {1, 2, 3};

    std::cout << j.dump(2) << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;

    // custom_object_type has no key_compare member, so object_comparator_t
    // falls back to its default
    std::cout << std::boolalpha
              << std::is_same<custom_json::object_comparator_t, custom_json::default_object_comparator_t>::value
              << std::endl;
}
```

Output:

```
{
  "happy": true,
  "list": [
    1,
    2,
    3
  ],
  "pi": 3.141
}
true
true
```

### Compatible containers

| Container                                                                        | Notes                                                                                               |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `std::map` (default)                                                             |                                                                                                     |
| [`nlohmann::ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md)     | used by [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md); keeps insertion order |
| [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map)                     | keeps insertion order; adapter puts `fifo_map_compare` in the comparator slot                       |
| `boost::container::map`, `boost::container::flat_map`                            | no adapter needed                                                                                   |
| `std::unordered_map`                                                             | through the adapter above; not with libstdc++ 9, see the note                                       |
| `boost::unordered_map`, `boost::unordered_flat_map`, `boost::unordered_node_map` | through the adapter above                                                                           |
| `absl::flat_hash_map`, `absl::node_hash_map`                                     | through the adapter above; `flat_hash_map` moves mapped values on rehash                            |
| `phmap::flat_hash_map`, `phmap::node_hash_map`, `gtl::flat_hash_map`             | through the adapter above                                                                           |
| `ankerl::unordered_dense::map` and `segmented_map`                               | adapter must rebind or drop the allocator                                                           |
| `robin_hood::unordered_flat_map`                                                 | adapter must drop the allocator                                                                     |
| `folly::F14NodeMap`                                                              | through the adapter above; requires C++20, see the note above                                       |
| `folly::sorted_vector_map`                                                       | alias must drop the allocator, whose value type it disagrees on                                     |

### Containers that cannot be used

| Container                                                                | Reason                                                                                                              |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `absl::btree_map`, `phmap::btree_map`, `gtl::btree_map`                  | require a complete mapped type                                                                                      |
| `robin_hood::unordered_node_map`, `folly::F14FastMap`, `eastl::hash_map` | require a complete mapped type                                                                                      |
| `eastl::map`                                                             | EASTL iterators do not work with `std::iterator_traits`                                                             |
| `tsl::ordered_map`                                                       | its iterators expose the mapped value as `const`                                                                    |
| `QMap`                                                                   | no `value_type` member type                                                                                         |
| `QHash`                                                                  | its `value_type` is the mapped type rather than a key/value pair, and its iterators dereference to the mapped value |
| `std::multimap`, `std::unordered_multimap`                               | `emplace` does not return `std::pair<iterator, bool>`                                                               |

## `ArrayType`

`ArrayType` is instantiated as

```
using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;
```

### Always required

- The template must be usable with **two** type arguments (value type and allocator).
- Member types `value_type` and `iterator`.
- Constructors: default, copy, and move; and from an iterator range `(first, last)`.
- Member functions `begin()`, `end()`, `cbegin()`, `cend()`, `empty()`, `size()`, `max_size()`, `clear()`, `operator[](size_type)`, `back()`, `push_back()`, `emplace_back()`, `pop_back()`, `resize()`, `insert()` (single element, count, and range), `erase(pos)`, and `erase(first, last)`. `basic_json::insert(pos, initializer_list)` goes through the range overload, so no initializer-list `insert` is needed. `at(size_type)` is **not** required: [`basic_json::at(size_type)`](https://json.nlohmann.me/api/basic_json/at/index.md) checks the index itself and then uses `operator[]`.
- `iterator` must be default-constructible, and it as well as the type returned by `cbegin()`/`cend()` must satisfy [LegacyRandomAccessIterator](https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator). A `static_assert` only checks for [LegacyBidirectionalIterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator), but [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) (`cend() - 1`), [`erase(idx)`](https://json.nlohmann.me/api/basic_json/erase/index.md) (`begin() + idx`), and the random-access operations of [`basic_json::iterator`](https://json.nlohmann.me/api/basic_json/begin/index.md) require random access.
- The comparison operators, as for [`ObjectType`](#objecttype): `==` and `<`, or `==` and `<=>` under C++20.

### Required for individual functions

- A member type `value_type`, for [`to_bson`](https://json.nlohmann.me/api/basic_json/to_bson/index.md) of an array.
- A constructor from `(count, value)`, for [`basic_json(size_type, const basic_json&)`](https://json.nlohmann.me/api/basic_json/basic_json/index.md).
- Swappability, via `std::swap` or an ADL `swap`, for [`swap(array_t&)`](https://json.nlohmann.me/api/basic_json/swap/index.md).

`capacity()` is optional

With [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) enabled, the library reads `array_t::capacity()` to find out whether adding an element reallocated the array and moved its elements, which would invalidate the parent pointers. An array type without a `capacity()` member function is handled conservatively: the parent pointers of all elements are refreshed after every insertion, which makes adding *n* elements cost O(\*n\*²). Only diagnostics builds pay this; without them `capacity()` is never called.

Reference implementation

`docs/mkdocs/docs/examples/custom_array_type.hpp` wraps a private `std::vector` and satisfies every requirement above -- a good starting point for a custom `ArrayType`.

```
#pragma once

#include <memory>
#include <utility>
#include <vector>

// A minimal, self-contained ArrayType built around a private std::vector.
// See https://json.nlohmann.me/features/types/template_parameters/#arraytype
template<class T, class Allocator = std::allocator<T>>
class custom_array_type
{
    using vector_t = std::vector<T, Allocator>;
    vector_t data_;

  public:
    using value_type = typename vector_t::value_type;
    using size_type = typename vector_t::size_type;
    using iterator = typename vector_t::iterator;
    using const_iterator = typename vector_t::const_iterator;

    custom_array_type() = default;
    custom_array_type(const custom_array_type&) = default;
    custom_array_type(custom_array_type&&) = default;
    custom_array_type& operator=(const custom_array_type&) = default;
    custom_array_type& operator=(custom_array_type&&) = default;

    template<class InputIt>
    custom_array_type(InputIt first, InputIt last) : data_(first, last) {}

    custom_array_type(size_type count, const T& value) : data_(count, value) {}

    iterator begin()
    {
        return data_.begin();
    }
    iterator end()
    {
        return data_.end();
    }
    const_iterator begin() const
    {
        return data_.begin();
    }
    const_iterator end() const
    {
        return data_.end();
    }
    const_iterator cbegin() const
    {
        return data_.cbegin();
    }
    const_iterator cend() const
    {
        return data_.cend();
    }

    bool empty() const
    {
        return data_.empty();
    }
    size_type size() const
    {
        return data_.size();
    }
    size_type max_size() const
    {
        return data_.max_size();
    }
    void clear()
    {
        data_.clear();
    }
    void resize(size_type n)
    {
        data_.resize(n);
    }

    T& operator[](size_type pos)
    {
        return data_[pos];
    }
    const T& operator[](size_type pos) const
    {
        return data_[pos];
    }

    T& back()
    {
        return data_.back();
    }
    const T& back() const
    {
        return data_.back();
    }

    void push_back(const T& value)
    {
        data_.push_back(value);
    }
    void push_back(T&& value)
    {
        data_.push_back(std::move(value));
    }

    template<class... Args>
    void emplace_back(Args&& ... args)
    {
        data_.emplace_back(std::forward<Args>(args)...);
    }

    void pop_back()
    {
        data_.pop_back();
    }

    iterator insert(const_iterator pos, const T& value)
    {
        return data_.insert(pos, value);
    }
    iterator insert(const_iterator pos, size_type count, const T& value)
    {
        return data_.insert(pos, count, value);
    }
    template<class InputIt>
    iterator insert(const_iterator pos, InputIt first, InputIt last)
    {
        return data_.insert(pos, first, last);
    }

    iterator erase(const_iterator pos)
    {
        return data_.erase(pos);
    }
    iterator erase(const_iterator first, const_iterator last)
    {
        return data_.erase(first, last);
    }

    void swap(custom_array_type& other)
    {
        data_.swap(other.data_);
    }

    friend bool operator==(const custom_array_type& lhs, const custom_array_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_array_type& lhs, const custom_array_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
```

Compiling and using it

```
#include <iostream>
#include <map>

#include <nlohmann/json.hpp>

#include "custom_array_type.hpp"

using custom_json = nlohmann::basic_json<std::map, custom_array_type>;

int main()
{
    custom_json j = custom_json::array();
    j.push_back(1);
    j.push_back(2);
    j.push_back(3);

    std::cout << j.dump() << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;
}
```

Output:

```
[1,2,3]
true
```

### Compatible containers

| Container                                               | Notes                                                                                     |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `std::vector` (default)                                 |                                                                                           |
| `std::deque`                                            | references survive appends, but not insertions elsewhere; see the `capacity()` note above |
| `std::pmr::vector`                                      | through an alias, as the allocator comes from `AllocatorType` instead                     |
| `boost::container::vector`, `deque`, `devector`         |                                                                                           |
| `boost::container::stable_vector`                       | the only one tried that keeps references valid across *every* insertion                   |
| `boost::container::small_vector`, `folly::small_vector` | through an alias that fixes the inline capacity                                           |
| `boost::container::static_vector`                       | through the same kind of alias, for arrays that stay within the fixed capacity            |
| `folly::fbvector`                                       | requires C++20, see the note above                                                        |

### Containers that cannot be used

| Container                           | Reason                                                                                        |
| ----------------------------------- | --------------------------------------------------------------------------------------------- |
| `std::list`                         | no `operator[]`, and no random-access iterators                                               |
| `eastl::vector`, `QList`, `QVector` | no `max_size()`; they handle the incomplete value type fine                                   |
| `absl::InlinedVector`               | requires a complete value type, see the note above                                            |
| `absl::FixedArray`                  | the size is fixed at construction, so `resize`, `push_back`, `insert` and `erase` are missing |

## `StringType`

`StringType` is used **both** for JSON string values and for the keys of JSON objects (`string_t` and `object_t::key_type`).

### Always required

- A member type `value_type` that is one byte wide and `char`-compatible. The library stores and processes UTF-8 encoded `char` data and hands `data()` to `std::strtoull`/`std::strtoll`. `std::wstring`, `std::u16string`, and `std::u32string` are **not** valid choices; see the FAQ on [wide string handling](https://json.nlohmann.me/home/faq/#wide-string-handling).
- Constructors: default, copy, move, from `const char*` (which must not be `explicit`), from `(const char*, size_type)`, and from `(size_type, char)`; and copy or move assignment.
- Member functions `size()`, `clear()`, `resize(n, c)`, `data()`, `push_back(char)`, and `operator[]` (const and non-const, returning references). `c_str()` and `back()` are **not** required.
- `data()` must return a pointer to a contiguous, **null-terminated** buffer -- the parser hands it to `std::strtoull`. A type whose `data()` is not null-terminated does not fail to compile; it silently misparses numbers.
- `append(const char*, size_type)`, used by [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), and `append(const StringType&)`, used by the CBOR reader for indefinite-length strings. The library's internal string concatenation additionally has to append a `char` and a `const char*`; for each it selects between `append(arg)`, `operator+=`, `append(first, last)`, and `append(data, size)`.
- The comparison operator `==` against another `StringType`, and `<` for use as a key of the chosen [`ObjectType`](#objecttype) (with the default comparator, `std::less<>` must be able to compare two `StringType` values, and a `StringType` with the key types used for lookup). `!=` is never applied to a `StringType`, and `==` against `const char*` is resolved by the implicit `const char*` constructor.

### Required for the binary formats

- `resize(n)`, used by the readers to make room for a block of bytes.
- Non-const `operator[]`, into which the readers `std::memcpy` those bytes. A non-`const` `data()` would serve just as well, but `std::string` has only had one since C++17, and the library still supports C++11.

### Required for JSON Pointer, `flatten`, and `diff`

- A static member `npos` and the member function `find_first_of(char, size_type)` -- together with `data()`, `reserve(n)`, and `append(const char*, size_type)` they implement the escaping and unescaping of reference tokens described in RFC 6901. Neither `find(const StringType&, size_type)`, nor `substr(pos, count)`, nor `replace(pos, count, const StringType&)` is required.
- `empty()`.
- `begin()` and `end()` -- used by [`operator[](const json_pointer&)`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md) to decide whether a reference token denotes an array index.

### Required for other functionality

| Functionality                                                                                                                                                                                                | Additional requirement                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`diff`](https://json.nlohmann.me/api/basic_json/diff/index.md), [`items`](https://json.nlohmann.me/api/basic_json/items/index.md), [`std::hash`](https://json.nlohmann.me/api/basic_json/std_hash/index.md) | conversion of a `std::size_t` to `StringType`: either assignability from the result of `std::to_string`, or an ADL overload `void int_to_string(StringType&, std::size_t)` |
| [`std::hash<basic_json>`](https://json.nlohmann.me/api/basic_json/std_hash/index.md)                                                                                                                         | additionally a specialization of `std::hash<StringType>`                                                                                                                   |
| [`to_bson`](https://json.nlohmann.me/api/basic_json/to_bson/index.md)                                                                                                                                        | `find(value_type)` and `npos`                                                                                                                                              |
| [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) from a `string_t`                                                                                                                          | the input adapters must accept it; otherwise pass a character range                                                                                                        |
| `operator<<(std::ostream&, const json_pointer&)`                                                                                                                                                             | streamability to `std::ostream`                                                                                                                                            |
| exception messages                                                                                                                                                                                           | `data()` and `size()`, or `begin()` and `end()`                                                                                                                            |

### Compatible types

| Type                                                      | Notes                                                                                                                                                                                                                                                |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `std::string` (default)                                   |                                                                                                                                                                                                                                                      |
| `std::basic_string` with a custom **stateless** allocator |                                                                                                                                                                                                                                                      |
| `std::pmr::string`                                        | see the warning below before relying on the memory resource                                                                                                                                                                                          |
| `boost::container::string`                                | needs a user-supplied `std::hash` specialization (Boost provides `boost::hash` instead)                                                                                                                                                              |
| `folly::fbstring`                                         | requires C++20, see the note above                                                                                                                                                                                                                   |
| `eastl::string`                                           | needs a user-supplied `std::hash` and an ADL `int_to_string` (it is not assignable from a `std::string`); [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) does not accept it directly -- pass a character range or a `std::string` |
| a custom string class in a user-defined namespace         | if the requirements above are met                                                                                                                                                                                                                    |

### Types that cannot be used

| Type                                               | Reason                                                                                                  |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `std::wstring`, `std::u16string`, `std::u32string` | the character type is not one byte wide                                                                 |
| `std::u8string`                                    | one byte wide, but `char8_t` is not `char`-compatible                                                   |
| `absl::Cord`                                       | no `value_type`, and the storage is not contiguous                                                      |
| `QString`                                          | no `append(const char*, size_type)`; its `QChar` is also two bytes wide, though that is never diagnosed |

A `std::pmr::string` mostly does not use the memory resource you choose

`basic_json` cannot be given an allocator or a memory resource. `AllocatorType` is default-constructed at every allocation and has to be stateless (see [`AllocatorType`](#allocatortype)), and string values the library creates are constructed with their own default allocator. So:

- Every string the library itself produces -- from [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), from [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), or by default construction -- allocates from `std::pmr::get_default_resource()`.
- **Copying** an arena-backed string into a value silently drops its memory resource: the copy lands on the default resource, because `std::pmr::polymorphic_allocator` does not propagate on copy construction. Nothing warns about this.
- **Moving** one in does keep it, and later growth still allocates from that arena -- but it does not survive a copy of the enclosing `basic_json`.
- Passing `std::pmr::polymorphic_allocator` as `AllocatorType` does not work around any of this; it does not compile.

Apart from moving a string in, the only way to redirect these allocations is the process-global `std::pmr::set_default_resource()`.

Reference implementation

`docs/mkdocs/docs/examples/custom_string_type.hpp` wraps a private `std::string` and satisfies every requirement above -- a good starting point for a custom `StringType`. The unit test `tests/src/unit-alt-string.cpp` contains a more thorough variant, `alt_string`, exercised against a larger part of the API.

```
#pragma once

#include <ostream>
#include <string>

// A minimal, self-contained StringType built around a private std::string.
// Wraps rather than inherits, so it exposes exactly what the library needs
// and nothing more of std::string's interface.
//
// Covers the "Always required" members, the extras needed for the binary
// formats, and the extras needed for JSON Pointer / flatten / unflatten /
// diff. Extending it further (e.g. for std::hash<basic_json> or to_bson) is
// a matter of adding the extra members listed in the "Required for other
// functionality" table.
//
// See https://json.nlohmann.me/features/types/template_parameters/#stringtype
class custom_string_type
{
    std::string data_;

  public:
    using value_type = char;
    using size_type = std::string::size_type;
    using iterator = std::string::iterator;
    using const_iterator = std::string::const_iterator;

    static constexpr size_type npos = std::string::npos;

    custom_string_type() = default;
    custom_string_type(const custom_string_type&) = default;
    custom_string_type(custom_string_type&&) = default;
    custom_string_type& operator=(const custom_string_type&) = default;
    custom_string_type& operator=(custom_string_type&&) = default;

    // not explicit: the library relies on being able to hand it a string literal
    custom_string_type(const char* s) : data_(s) {}
    custom_string_type(const char* s, size_type count) : data_(s, count) {}
    custom_string_type(size_type count, char ch) : data_(count, ch) {}

    size_type size() const
    {
        return data_.size();
    }
    bool empty() const
    {
        return data_.empty();
    }
    void clear()
    {
        data_.clear();
    }
    void resize(size_type n)
    {
        data_.resize(n);
    }
    void resize(size_type n, char c)
    {
        data_.resize(n, c);
    }
    void reserve(size_type n)
    {
        data_.reserve(n);
    }

    // must stay null-terminated -- the parser hands this to std::strtoull &
    // friends; std::string::data() has guaranteed that since C++11
    const char* data() const
    {
        return data_.data();
    }

    void push_back(char c)
    {
        data_.push_back(c);
    }

    char& operator[](size_type pos)
    {
        return data_[pos];
    }
    char operator[](size_type pos) const
    {
        return data_[pos];
    }

    custom_string_type& append(const char* s, size_type count)
    {
        data_.append(s, count);
        return *this;
    }
    custom_string_type& append(const custom_string_type& other)
    {
        data_.append(other.data_);
        return *this;
    }

    size_type find_first_of(char c, size_type pos = 0) const
    {
        return data_.find_first_of(c, pos);
    }

    iterator begin()
    {
        return data_.begin();
    }
    iterator end()
    {
        return data_.end();
    }
    const_iterator begin() const
    {
        return data_.begin();
    }
    const_iterator end() const
    {
        return data_.end();
    }

    friend bool operator==(const custom_string_type& lhs, const custom_string_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_string_type& lhs, const custom_string_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }

    // not required by the library itself, but dump() returns a custom_string_type
    // and this makes `std::cout << j.dump()` work as expected
    friend std::ostream& operator<<(std::ostream& os, const custom_string_type& s)
    {
        return os << s.data_;
    }
};
```

Compiling and using it

```
#include <iostream>
#include <map>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_string_type.hpp"

using custom_json = nlohmann::basic_json<std::map, std::vector, custom_string_type>;

int main()
{
    custom_json j;
    j["pi"] = 3.141;
    j["happy"] = true;
    j["list"] = {1, 2, 3};

    std::cout << j.dump(2) << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;
}
```

Output:

```
{
  "happy": true,
  "list": [
    1,
    2,
    3
  ],
  "pi": 3.141
}
true
```

## `BooleanType`

`boolean_t` is stored **directly** inside `basic_json`, as a member of an anonymous union.

### Always required

- A literal type that is trivially default-constructible, trivially copyable, and trivially destructible; otherwise the union's special member functions are deleted.
- **Implicitly** convertible from `bool` -- an `explicit` constructor is not enough, because the `to_json` overload for a custom `BooleanType` is constrained on `std::is_convertible` -- and contextually convertible to `bool` (here an `explicit operator bool` is fine).
- Comparison operators `==`, `!=`, `<`, `<=`, `>`, `>=` (or `<=>`).
- Convertible from and to `bool` through the serializer, because [`get<bool>()`](https://json.nlohmann.me/api/basic_json/get/index.md) is used internally.

There is little reason to use anything other than `bool` here.

### Compatible types

`bool` is the only usable choice. Another trivially copyable type that is implicitly convertible to and from `bool` -- `std::uint8_t`, say -- does compile, and JSON booleans still round-trip, but the type then serves as both `boolean_t` and an ordinary integer: `basic_json` can no longer be constructed or assigned from a `std::uint8_t` at all (the boolean and unsigned-integer `to_json` overloads become ambiguous), and [`get<std::uint8_t>()`](https://json.nlohmann.me/api/basic_json/get/index.md) on a number throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) instead of returning the value.

## `NumberIntegerType` and `NumberUnsignedType`

Both types are stored **directly** inside `basic_json`'s union.

### Always required

- `std::is_integral` must be satisfied: `NumberIntegerType` must be a **signed** integer type, `NumberUnsignedType` an **unsigned** integer type. Class types are not supported -- among others, the constructors taking integer values are constrained on `std::is_integral`.
- Trivially default-constructible, trivially copyable, and trivially destructible (union member).
- `std::numeric_limits` must be specialized for both types.
- `NumberUnsignedType` must be able to represent the absolute value of every `NumberIntegerType` value; serialization of negative numbers converts the value to `NumberUnsignedType`. A `static_assert` requires it to be at least as wide as `NumberIntegerType`, which is what that amounts to for the standard integer types.
- Both types must fit into the internal 64-character number buffer used by [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), which is the case for all standard integer types.
- [`std::hash<basic_json>`](https://json.nlohmann.me/api/basic_json/std_hash/index.md) additionally requires `std::hash` specializations.

### Notes

The number types influence what the parser accepts: an integer literal that does not round-trip through the chosen type is stored as [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md) instead. Choosing types narrower than 64 bits therefore silently changes parse results rather than raising an error. See [Number Handling](https://json.nlohmann.me/features/types/number_handling/index.md) for details.

### Compatible types

| Type pair                                                            | Support                                                                                                                                                                              |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `std::int64_t` / `std::uint64_t` (default)                           | full                                                                                                                                                                                 |
| `std::int32_t` / `std::uint32_t`, `long long` / `unsigned long long` | full; narrower types change which literals the parser can represent                                                                                                                  |
| any other pair of standard signed/unsigned integer types             | full                                                                                                                                                                                 |
| class types, enumerations                                            | not usable; `std::is_integral` must hold                                                                                                                                             |
| `bool`, or a type already used for another member of the union       | not usable; `std::is_integral<bool>` is in fact `true`, but the `get_impl_ptr` overloads for `boolean_t`, `number_integer_t`, `number_unsigned_t` and `number_float_t` would collide |

## `NumberFloatType`

`number_float_t` is stored **directly** inside `basic_json`'s union.

### Always required

- Trivially default-constructible, trivially copyable, and trivially destructible (union member).
- `std::numeric_limits` must be specialized; `max_digits10` is used to size the conversion.
- `std::isfinite` must be applicable to the type.

### Required for parsing and serialization

`NumberFloatType` must be one of `float`, `double`, or `long double`:

- The [parser](https://json.nlohmann.me/features/parsing/index.md) converts number literals with `std::strtof`, `std::strtod`, or `std::strtold`; the library provides overloads for exactly these three types.
- [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) falls back to `std::snprintf` with the `%g` and `%Lg` conversion specifiers, for which the library likewise provides only `double` and `long double` overloads (`float` is promoted to `double`).

If `std::numeric_limits<NumberFloatType>` describes an IEEE 754 binary32 or binary64 number, `dump` uses the Grisu2 algorithm, which produces the shortest representation that round-trips. Otherwise the `snprintf` fallback with `max_digits10` digits is used.

### Required for the binary formats

`NumberFloatType` must be `float` or `double`. The writers for [CBOR, MessagePack, UBJSON, BJData, and BSON](https://json.nlohmann.me/features/binary_formats/index.md) map a floating-point value onto an IEEE 754 binary32 or binary64 field and have no encoding for `long double`.

### Compatible types

| Type               | Support                                                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `double` (default) | full; short round-trip output through Grisu2                                                                          |
| `float`            | full; short round-trip output through Grisu2                                                                          |
| `long double`      | `dump` and `parse` only; the binary format writers do not compile, as they only handle IEEE 754 binary32 and binary64 |
| any other type     | not usable                                                                                                            |

## `AllocatorType`

`AllocatorType` is instantiated with **one** argument, for each of `object_t`, `array_t`, `string_t`, `binary_t`, `basic_json`, `std::pair<const StringType, basic_json>`, and `std::pair<StringType, basic_json>`.

`AllocatorType` is not the only allocator a `basic_json` uses. It allocates the JSON values themselves, but most temporary storage is allocated with `std::allocator`. This includes the parser's stacks and the stacks that process deeply nested values without recursion.

### Always required

- The template must be usable with exactly one type argument. The library instantiates `AllocatorType<T>` directly and never uses `std::allocator_traits<...>::rebind_alloc`.
- It must satisfy the [Allocator](https://en.cppreference.com/w/cpp/named_req/Allocator) named requirement so that `std::allocator_traits` can be used with it.
- It must be **default-constructible and stateless**. Objects are allocated with a default-constructed allocator and deallocated with a *different* default-constructed allocator, and [`get_allocator()`](https://json.nlohmann.me/api/basic_json/get_allocator/index.md) returns a default-constructed instance. Allocators carrying state are not supported, so there is no way to tell a `basic_json` where to allocate from; see the note under [`StringType`](#stringtype) for what that means in practice. A stateful allocator is **not diagnosed**: it compiles and silently ignores the state.
- It must support **incomplete types**: `AllocatorType<basic_json>` is instantiated inside the definition of `basic_json` itself.
- `std::allocator_traits<AllocatorType<basic_json>>::pointer` becomes [`basic_json::pointer`](https://json.nlohmann.me/api/basic_json/#container-types), and iterators are constructed from raw `basic_json*` values. The `pointer` type must therefore be a plain pointer; fancy pointers are not supported.

### Compatible types

| Type                                                        | Support                                |
| ----------------------------------------------------------- | -------------------------------------- |
| `std::allocator` (default)                                  | full                                   |
| a custom stateless allocator template                       | full                                   |
| stateful allocators, e.g. `std::pmr::polymorphic_allocator` | not usable; see the requirements above |

## `JSONSerializer`

`JSONSerializer` is instantiated as `JSONSerializer<T, void>` and defaults to [`adl_serializer`](https://json.nlohmann.me/api/adl_serializer/index.md).

### Always required

- The template must accept **two** type arguments. It does not have to give the second one a default -- `basic_json` declares the parameter as `template<typename T, typename SFINAE = void> class JSONSerializer`, so uses such as `JSONSerializer<T>` inside the library supply `void` themselves. The second parameter exists so that partial specializations can be constrained by SFINAE.
- For every type `T` that is converted **to** a JSON value, a static member function `static void to_json(basic_json&, T)` must exist.
- For every type `T` that is converted **from** a JSON value, either `static void from_json(const basic_json&, T&)` or `static T from_json(const basic_json&)` must exist. The latter form is required for types that are not default-constructible; see [Arbitrary Types Conversions](https://json.nlohmann.me/features/arbitrary_types/index.md).
- To support the [converting constructor](https://json.nlohmann.me/api/basic_json/basic_json/index.md) between different `basic_json` specializations, `to_json` must be available for `boolean_t`, `number_integer_t`, `number_unsigned_t`, `number_float_t`, `string_t`, `object_t`, `array_t`, and `binary_t` of the *source* specialization.

### Compatible types

| Type                                                                                         | Support                                                           |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| [`nlohmann::adl_serializer`](https://json.nlohmann.me/api/adl_serializer/index.md) (default) | full                                                              |
| a class template deriving from `adl_serializer`                                              | full; the usual way to change behavior while keeping the defaults |
| an unrelated template with the same interface                                                | full, but it has to handle every type the library converts        |

## `BinaryType`

`BinaryType` is not a JSON type; it is used for the byte strings of the [binary formats](https://json.nlohmann.me/features/binary_formats/index.md). It is wrapped as

```
using binary_t = nlohmann::byte_container_with_subtype<BinaryType>;
```

### Always required

- A non-`final` class type -- [`byte_container_with_subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/index.md) derives from it publicly.
- A member type `value_type` that is **exactly one byte** wide (e.g., `std::uint8_t`, `char`, or `std::byte`). Readers and writers reinterpret the container's storage as raw bytes, so a wider `value_type` is rejected with a `static_assert`.
- Contiguous storage: the binary readers `std::memcpy` into `&binary[n]`, the writers `reinterpret_cast` `data()`. `data() + n` would do for the readers too, but they share one helper with [`StringType`](#stringtype), whose non-`const` `data()` is C++17 and later only.
- Default-constructible, copy-constructible, and move-constructible.
- Member functions `size()`, `empty()`, `data()`, `resize()`, `operator[]`, `back()`, `begin()`, `end()`, `cbegin()`, and `cend()` with random-access iterators, and `insert(pos, first, last)`, which the CBOR reader uses to join the chunks of an indefinite-length byte string. `push_back()` is **not** required.
- Comparison operators: `==` is used by [`byte_container_with_subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/index.md), the relational operators by [`basic_json`'s comparison operators](https://json.nlohmann.me/api/basic_json/operator_le/index.md).

### Required for individual functions

- `clear()`, for [`basic_json::clear()`](https://json.nlohmann.me/api/basic_json/clear/index.md).

`max_size()`, `at()`, `reserve()`, `erase()`, `pop_back()`, and `emplace_back()` are **not** used at all.

See [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md) for how a non-default `BinaryType` changes the meaning of assigning such a container to a `basic_json` value.

Reference implementation

`docs/mkdocs/docs/examples/custom_binary_type.hpp` wraps a private `std::vector<std::uint8_t>` and satisfies every requirement above -- a good starting point for a custom `BinaryType`.

```
#pragma once

#include <cstdint>
#include <initializer_list>
#include <vector>

// A minimal, self-contained BinaryType built around a private std::vector.
// See https://json.nlohmann.me/features/types/template_parameters/#binarytype
class custom_binary_type
{
    using vector_t = std::vector<std::uint8_t>;
    vector_t data_;

  public:
    using value_type = vector_t::value_type;
    using size_type = vector_t::size_type;
    using iterator = vector_t::iterator;
    using const_iterator = vector_t::const_iterator;

    custom_binary_type() = default;
    custom_binary_type(const custom_binary_type&) = default;
    custom_binary_type(custom_binary_type&&) = default;
    custom_binary_type& operator=(const custom_binary_type&) = default;
    custom_binary_type& operator=(custom_binary_type&&) = default;

    template<class InputIt>
    custom_binary_type(InputIt first, InputIt last) : data_(first, last) {}

    // so basic_json::binary({0x01, 0x02}) can build one directly
    custom_binary_type(std::initializer_list<std::uint8_t> init) : data_(init) {}

    size_type size() const
    {
        return data_.size();
    }
    bool empty() const
    {
        return data_.empty();
    }
    void clear()
    {
        data_.clear();
    }
    void resize(size_type n)
    {
        data_.resize(n);
    }

    // read-only is enough: the writers only ever read from a binary value
    const std::uint8_t* data() const
    {
        return data_.data();
    }

    std::uint8_t& operator[](size_type pos)
    {
        return data_[pos];
    }
    std::uint8_t operator[](size_type pos) const
    {
        return data_[pos];
    }

    std::uint8_t& back()
    {
        return data_.back();
    }
    std::uint8_t back() const
    {
        return data_.back();
    }

    iterator begin()
    {
        return data_.begin();
    }
    iterator end()
    {
        return data_.end();
    }
    const_iterator begin() const
    {
        return data_.begin();
    }
    const_iterator end() const
    {
        return data_.end();
    }
    const_iterator cbegin() const
    {
        return data_.cbegin();
    }
    const_iterator cend() const
    {
        return data_.cend();
    }

    template<class InputIt>
    iterator insert(const_iterator pos, InputIt first, InputIt last)
    {
        return data_.insert(pos, first, last);
    }

    friend bool operator==(const custom_binary_type& lhs, const custom_binary_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_binary_type& lhs, const custom_binary_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
```

Compiling and using it

```
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_binary_type.hpp"

using custom_json = nlohmann::basic_json<std::map, std::vector, std::string, bool,
      std::int64_t, std::uint64_t, double, std::allocator,
      nlohmann::adl_serializer, custom_binary_type>;

int main()
{
    const auto j = custom_json::binary({0x01, 0x02, 0x03});

    std::cout << j.dump() << std::endl;
    std::cout << std::boolalpha << (custom_json::from_cbor(custom_json::to_cbor(j)) == j) << std::endl;
}
```

Output:

```
{"bytes":[1,2,3],"subtype":null}
true
```

### Compatible containers

| Container                                                                                   | Notes                                                                     |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `std::vector<std::uint8_t>` (default)                                                       |                                                                           |
| `std::vector<char>`, `std::vector<std::byte>`                                               | `dump()` writes the bytes as 0..255 whichever is used                     |
| `boost::container::vector<std::uint8_t>`, `boost::container::small_vector<std::uint8_t, N>` |                                                                           |
| `absl::InlinedVector<std::uint8_t, N>`                                                      | usable here, unlike as an `ArrayType`, because the value type is complete |
| `eastl::vector<std::uint8_t>`                                                               | usable here, unlike as an `ArrayType`, because `max_size()` is not needed |
| `folly::fbvector<std::uint8_t>`                                                             | requires C++20, see the note above                                        |

### Containers that cannot be used

| Container                                            | Reason                                                                                                                                                                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `QByteArray`                                         | no `empty()` (it spells that `isEmpty()`); its `insert` takes an index rather than an iterator; and it converts to `string_t`, which makes `to_json` ambiguous between a string and a binary value            |
| `std::string`                                        | `binary_t::container_type` and `string_t` would be the same type, so the two [`swap`](https://json.nlohmann.me/api/basic_json/swap/index.md) overloads collide and `basic_json` cannot be instantiated at all |
| `std::deque<std::uint8_t>`                           | storage is not contiguous, so there is no `data()`                                                                                                                                                            |
| containers whose `value_type` is wider than one byte | see above -- accepted by the compiler, wrong at runtime                                                                                                                                                       |

## `CustomBaseClass`

`CustomBaseClass` is an extension point: unless it is `void` (the default, which selects the empty `nlohmann::json_default_base`), `basic_json` publicly derives from it.

### Always required

- A non-`final`, default-constructible class type.
- `basic_json` is copy-/move-constructible and copy-/move-assignable only if `CustomBaseClass` is.

### Notes

`basic_json` is documented to be a [StandardLayoutType](https://en.cppreference.com/w/cpp/named_req/StandardLayoutType). Because `basic_json` has non-static data members of its own, a `CustomBaseClass` with non-static data members forfeits this guarantee.

Note the namespace of `CustomBaseClass` becomes an associated namespace of `basic_json` for the purpose of argument-dependent lookup.

See [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) for an example.

### Compatible types

| Type                                         | Support                                                                                             |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `void` (default)                             | an empty base class is used; no effect on `basic_json`                                              |
| any default-constructible, non-`final` class | full; see [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) |

## Cross-specialization conversions

Converting a value from one `basic_json` specialization into another (see the [converting constructor](https://json.nlohmann.me/api/basic_json/basic_json/index.md)) imposes two additional requirements that are not diagnosed at compile time. With assertions enabled they abort on the `JSON_ASSERT` at the end of the converting constructor; under `NDEBUG` they fail **silently** at runtime:

- The target `string_t` must be directly constructible from the source `string_t`. Otherwise the string is converted to an array of character codes.
- The target `object_t::key_type` must be directly constructible from the source object's key type. Otherwise the object is converted to an array of key/value pairs.

See [issue #3425](https://github.com/nlohmann/json/issues/3425), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), and [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md).

## See also

- [Types](https://json.nlohmann.me/features/types/index.md) -- overview of how JSON values are stored
- [Number Handling](https://json.nlohmann.me/features/types/number_handling/index.md) -- how the number types affect parsing and serialization
- [Object Order](https://json.nlohmann.me/features/object_order/index.md) -- using an insertion-ordered `ObjectType`
- [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) -- API documentation of the class template
