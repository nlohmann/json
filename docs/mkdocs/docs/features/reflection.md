# Reflection

This library has experimental support for [reflection](https://en.wikipedia.org/wiki/Reflection_(C%2B%2B)), introduced
in C++26.

!!! warning "Experimental"

    This feature relies on very recent compiler support. Treat it as experimental.

Using reflection lets the library serialize and deserialize a struct's fields directly, avoiding the
[`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](../api/macros/nlohmann_define_type_intrusive.md) and
[`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](../api/macros/nlohmann_define_type_non_intrusive.md) macros entirely. Two
functions drive it:

- [`serialize`](../api/basic_json/serialize.md) — a static function that maps an object to a JSON value.
- [`deserialize`](../api/basic_json/deserialize.md) — a member function that maps a JSON value back into an object.

## Requirements

Reflection-based serde is only available when [`JSON_HAS_REFLECTION`](../api/macros/json_has_reflection.md) evaluates to
`1`. The library sets it automatically based on the `#!cpp __cpp_impl_reflection` feature-test macro.

As of this writing, GCC 16 is the only compiler that supports reflection, and it must be invoked with the
`-std=c++26 -freflection` flags. On every other toolchain the macro is `0`, the functions and annotations below are not 
declared, and the macros remain the way to convert user types.

## Basic usage

A plain struct with public data members needs no macros and no annotations:

```cpp
import std;
import nlohmann.json;

using nlohmann::json;

struct Person
{
    std::string name;
    std::string address;
    int age;
};

Person ned = {
    .name = "Ned Flanders",
    .address = "744 Evergreen Terrace",
    .age = 60,
};

// object -> JSON
json j = json::serialize(ned);
// {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}

// JSON -> object
Person p = j.deserialize<Person>();
```

Each non-static data member becomes a key in a JSON object, named after the member. Members are mapped through the
library's normal conversion machinery, so nested structs, containers, optionals, and any type with a custom
`to_json`/`from_json` are handled recursively.

!!! info "Relationship to the macros and hand-written conversions"

    `serialize`/`deserialize` only step in for a type that has **no** `to_json`/`from_json` reachable via
    [ADL](arbitrary_types.md) and no `NLOHMANN_DEFINE_TYPE_*` expansion. A type that defines either keeps its
    hand-written behavior, so reflection never silently overrides an explicit conversion. You can mix both freely: a
    reflected struct may contain a member whose type uses the macros, and vice versa.

## Missing and null values

A member whose key is absent from the JSON object, or present but `#!json null`, is left at its default value on
`deserialize`. This makes defaulted members and optionals behave naturally:

```cpp
struct Config
{
    std::string host = "localhost";
    int port = 8080;
};

Config c = json::parse(R"({"host": "example.com"})").deserialize<Config>();
// c.host == "example.com", c.port == 8080 (default kept)
```

## Enumerations

An enum member is serialized as the **name** of its enumerator (a string), not its underlying integer, and read back
from that name:

```cpp
enum class Element { FIRE, WATER, WIND };

struct Spell
{
    std::string name;
    Element element = Element::fire;
};

json j = json::serialize(Spell {.name = "Gust", .element = Element::WIND});
// {"element":"WIND","name":"Gust"}
```

A value formed by a cast that matches no enumerator falls back to its integer representation on the way out. On the way
in, a string that matches no enumerator throws
[`deserialization_error.602`](../home/exceptions.md#jsonexceptiondeserialization_error602).

## Annotations

Field-level behavior is controlled with the annotations (`#!cpp [[=nlohmann::...]]`), applied to a data member
(or, for `reflectable`, to the type):

| Annotation                           | Applies to | Effect                                                                   |
|--------------------------------------|------------|--------------------------------------------------------------------------|
| `#!cpp [[=nlohmann::transient]]`     | member     | the member is skipped entirely                                           |
| `#!cpp [[=nlohmann::rename("key")]]` | member     | the member uses `key` as its JSON key instead of its name                |
| `#!cpp [[=nlohmann::flatten]]`       | member     | a nested struct's keys are written at the parent level instead of nested |
| `#!cpp [[=nlohmann::reflectable]]`   | type       | grants the serializer access to the type's private and protected members |

### `transient` — skip a field

```cpp
struct Session
{
    std::string user;
    [[=nlohmann::transient]] std::string password;   // never serialized or read
};
```

### `rename` — use a different key

```cpp
struct Player
{
    [[=nlohmann::rename("full_name")]] std::string name;   // keyed as "full_name"
};
```

Note that if `nlohmann::rename` is imported with a using-declaration, it may clash with POSIX
`#!cpp ::rename(const char*, const char*)` from `<cstdio>`; if that header is included,
`#!cpp using nlohmann::rename;` should be avoided.

### `flatten` — inline a nested struct

Instead of nesting a struct member under its own key, `flatten` writes its members at the parent level on serialize and
reads them from the parent level on deserialize:

```cpp
struct Metadata
{
    std::string author;
    int version = 1;
};

struct Document
{
    std::string title;
    [[=nlohmann::flatten]] Metadata info;
};

json j = json::serialize(Document {
        .title = "Spec",
        .info = Metadata {.author = "Alice", .version = 3},
    }
);
// {"author":"Alice","title":"Spec","version":3}   (no "info" key)
```

Because a flattened struct's keys are pulled up to the parent level, they share one namespace with the parent's own
keys and with any other flattened struct at that level. If two of them resolve to the same JSON key, the value cannot
round-trip, so the library rejects the type at compile time. Give one of the members a distinct
[`rename`](#rename-use-a-different-key) to resolve the clash:

```cpp
struct Metadata
{
    std::string title; // would collide with Document::title once flattened
    int version = 1;
};

struct Document
{
    std::string title;
    [[=nlohmann::flatten]] Metadata info; // error: two members map to the key "title"
};
```

## Private members

By default the serializer only reaches **public** data members. A class with private or protected state opts in by
annotating the type `reflectable`:

```cpp
class [[=nlohmann::reflectable]] Account
{
  private:
    std::string owner;
    long balance = 0;

  public:
    Account() = default;
    Account(std::string owner, long balance):
        owner{std::move(owner)}, balance{balance} {}
};

json j = json::serialize(Account("Alice", 100));
// {"balance":100,"owner":"Alice"}
```

To lift this requirement for every type at once, define
[`JSON_SERDE_ALLOW_PRIVATE`](../api/macros/json_has_reflection.md#notes) to `1` before including the library. This
defeats the encapsulation of every serialized type, so prefer the per-type annotation unless you deliberately want the
global behavior.

### `allow_private` — opt in at the call site

The `reflectable` annotation can only be attached to a type at its definition, so it is no help for a third-party type
you cannot edit. For that case, pass the tag `nlohmann::allow_private` as the second argument to `serialize`, or to any
`deserialize` overload, to reach the private and protected members for that one call:

```cpp
// Stranger is a third-party type: private members, a public default constructor,
// and no annotation we are able to add.
json j = json::serialize(stranger, nlohmann::allow_private);
Stranger back = j.deserialize<Stranger>(nlohmann::allow_private);
```

This grants the same access as the `reflectable` annotation, but scoped to the call rather than the type, and without
the global reach of `JSON_SERDE_ALLOW_PRIVATE`. Without the tag, an unannotated type exposes only its public members.

## Other `basic_json` types

The functions and annotations work with every `basic_json` specialization the library provides, not only
[`json`](../api/json.md). For example, [`ordered_json`](../api/ordered_json.md) serializes the same way while preserving
object key insertion order.

## Error handling

A failed `deserialize` throws a [`deserialization_error`](../api/basic_json/deserialization_error.md) (ids 6xx):

- [`deserialization_error.601`](../home/exceptions.md#jsonexceptiondeserialization_error601) — a member that is itself a struct was expected
  to be a JSON object, but the key holds another type.
- [`deserialization_error.602`](../home/exceptions.md#jsonexceptiondeserialization_error602) — an enum member holds a string that matches no
  enumerator name.

A member whose own `from_json` conversion fails propagates that conversion's exception (for example,
[`type_error.302`](../home/exceptions.md#jsonexceptiontype_error302) for a scalar of the wrong type). When exceptions are
switched off (see [Working without exceptions](no_exceptions.md)), the failure follows the library's usual no-exception
behavior.

## See also

- [`serialize`](../api/basic_json/serialize.md) — map an object to a JSON value via reflection
- [`deserialize`](../api/basic_json/deserialize.md) — map a JSON value into an object via reflection
- [`deserialization_error`](../api/basic_json/deserialization_error.md) — the exception thrown on a failed reflection-based conversion
- [`JSON_HAS_REFLECTION`](../api/macros/json_has_reflection.md) — whether reflection-based serde is available, and the
  `JSON_SERDE_ALLOW_PRIVATE` knob
- [Arbitrary Type Conversions](arbitrary_types.md) — the `to_json`/`from_json` approach that works without reflection
- [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](../api/macros/nlohmann_define_type_intrusive.md) /
  [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE`](../api/macros/nlohmann_define_type_non_intrusive.md) — the macro-based
  alternatives
