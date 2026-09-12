# <small>nlohmann::</small>eval_value, eval_array, eval_object

```cpp
#include <nlohmann/eval.hpp>

namespace nlohmann
{

// (1) -- access a JSON object element by key with a default fallback
template <class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::object_t::key_type& key,
                     const ValueType& default_value) noexcept;

// (2) -- access a JSON value by JSON Pointer with a default fallback
template <class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::json_pointer& ptr,
                     const ValueType& default_value) noexcept;

// (3) -- access a JSON array stored at @a key
template <class BasicJsonType>
const BasicJsonType& eval_array(const BasicJsonType& j,
                                const typename BasicJsonType::object_t::key_type& key) noexcept;

// (4) -- access a JSON array resolved by @a ptr
template <class BasicJsonType>
const BasicJsonType& eval_array(const BasicJsonType& j,
                                const typename BasicJsonType::json_pointer& ptr) noexcept;

// (5) -- access a JSON object stored at @a key
template <class BasicJsonType>
const BasicJsonType& eval_object(const BasicJsonType& j,
                                 const typename BasicJsonType::object_t::key_type& key) noexcept;

// (6) -- access a JSON object resolved by @a ptr
template <class BasicJsonType>
const BasicJsonType& eval_object(const BasicJsonType& j,
                                 const typename BasicJsonType::json_pointer& ptr) noexcept;

}
```

Null-safe, `noexcept` accessors for retrieving values from a JSON object,
where "null" refers to the JSON value [`null`](../features/types/index.md)
(or any non-matching JSON shape) rather than to a null C++ object.

These free functions are an opt-in alternative to
[`basic_json::value`](basic_json/value.md). Unlike `value()`, they **never
throw** -- on any non-matching condition (the receiver is not a JSON
object, the key/pointer is missing, the resolved JSON value is `null`, or
has a type that is not convertible to `ValueType`) they silently fall back
to the supplied default value (overloads 1-2) or to a static empty JSON
array/object (overloads 3-6).

This brings the developer experience of accessing untrusted server-side JSON
closer to JavaScript's optional chaining (`?.`) and nullish coalescing (`??`).

1. Returns the value stored at @a key converted to `ValueType`. Returns
   @a default_value if @a j is not a JSON object, @a key does not exist
   in @a j, the value at @a key is JSON `null`, or the conversion fails.
2. As (1), but the position is identified by a
   [JSON Pointer](json_pointer/index.md). Any failure to resolve @a ptr
   (missing intermediate node, wrong type along the way, etc.) yields
   @a default_value.
3. Returns a const reference to the JSON array stored at @a key. Returns
   a reference to a static empty array if @a j is not a JSON object,
   @a key does not exist, or the value at @a key is not a JSON array.
4. As (3), but the position is identified by a
   [JSON Pointer](json_pointer/index.md).
5. Returns a const reference to the JSON object stored at @a key. Returns
   a reference to a static empty object if @a j is not a JSON object,
   @a key does not exist, or the value at @a key is not a JSON object.
6. As (5), but the position is identified by a
   [JSON Pointer](json_pointer/index.md).

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](basic_json/index.md).

`ValueType`
:   a type compatible with JSON values. For overloads (1) and (2), it is
    deduced from @a default_value, so the common case never requires
    explicit template arguments.

## Parameters

`j` (in)
:   the JSON value to query.

`key` (in)
:   the object key to look up (overloads (1), (3), (5)).

`ptr` (in)
:   a [JSON Pointer](json_pointer/index.md) identifying the position to
    look up (overloads (2), (4), (6)).

`default_value` (in)
:   the value to return when no matching value can be retrieved
    (overloads (1) and (2)).

## Return value

1. The value stored at @a key converted to `ValueType`, or @a default_value
   on any non-matching condition.
2. The JSON value resolved by @a ptr converted to `ValueType`, or
   @a default_value on any non-matching condition.
3. A const reference to the JSON array stored at @a key, or a const
   reference to a static empty array on any non-matching condition.
4. A const reference to the JSON array resolved by @a ptr, or a const
   reference to a static empty array on any non-matching condition.
5. A const reference to the JSON object stored at @a key, or a const
   reference to a static empty object on any non-matching condition.
6. A const reference to the JSON object resolved by @a ptr, or a const
   reference to a static empty object on any non-matching condition.

## Exception safety

All overloads are declared `noexcept` and never throw.

## Complexity

1. Logarithmic in the size of @a j (one object lookup).
2. Linear in the length of @a ptr.
3. Logarithmic in the size of @a j.
4. Linear in the length of @a ptr.
5. Logarithmic in the size of @a j.
6. Linear in the length of @a ptr.

## Notes

!!! note "Comparison with `value()`"

    | Condition                                    | `j.value(...)`               | `eval_value(j, ...)` |
    | -------------------------------------------- | ---------------------------- | -------------------- |
    | `j` is object, key exists, correct type      | returns value                | returns value        |
    | `j` is object, key missing                   | returns default              | returns default      |
    | `j` is JSON `null`                           | **throws `type_error`**      | returns default      |
    | `j` is array, string, number, bool, ...      | **throws `type_error`**      | returns default      |
    | resolved value is JSON `null`                | returns null-converted value | returns default      |

!!! note "Implementation strategy"

    These helpers rely only on the public API of
    [`basic_json`](basic_json/index.md): `is_object`, `is_array`,
    `is_null`, `find`, `end`, `get`, `contains(json_pointer)`, and
    `at(json_pointer)`. They are intentionally provided as non-member
    functions in an opt-in header (`<nlohmann/eval.hpp>`). They are not
    pulled in by `<nlohmann/json.hpp>` and are not bundled into the
    amalgamated `single_include/nlohmann/json.hpp`.

    The empty fallback array/object returned by reference is a
    process-lifetime singleton constructed once into properly-aligned
    uninitialized storage via placement-new. Its destructor is
    intentionally never invoked at process exit, which avoids both
    Clang's `-Wexit-time-destructors` and any
    static-destruction-order concerns.

!!! warning "Limitation under `JSON_NOEXCEPTION`"

    The `noexcept` guarantee is best-effort under
    [`JSON_NOEXCEPTION`](macros/json_noexception.md):

    - `eval_array` and `eval_object` (both key and JSON Pointer overloads)
      and the JSON Pointer overload of `eval_value` remain fully
      noexcept-correct, because they only rely on `is_*` predicates,
      `find`, `contains`, and `at` paths that are guarded by a successful
      `contains` check.
    - `eval_value(j, key, default)` calls `it->get<ValueType>()` for type
      conversion. Under `JSON_NOEXCEPTION`, a conversion failure inside
      `from_json` calls `std::abort()` instead of throwing, so passing a
      receiver where the value at @a key is not convertible to `ValueType`
      may abort the process. Use the JSON Pointer overload, or perform an
      explicit `is_*` check at the call site, when running with exceptions
      disabled.

## Examples

??? example "Example: safe access on a possibly-null payload"

    The example below demonstrates safe defensive access to a JSON value
    received from an untrusted source.

    ```cpp
    #include <nlohmann/json.hpp>
    #include <nlohmann/eval.hpp>

    using nlohmann::json;

    // a payload received from a remote source -- could be JSON null,
    // partial, of the wrong type, or fully populated
    json received = nullptr;

    int  a = nlohmann::eval_value(received, "a", 0);
    auto d = nlohmann::eval_value(received,
                                  json::json_pointer("/c/d"),
                                  std::string{});

    // safe range-based for: returns an empty array when "items" is missing
    // or has the wrong shape
    for (const auto& item : nlohmann::eval_array(received, "items"))
    {
        // process each item
        (void) item;
    }

    // safe iteration over a nested object
    for (const auto& kv : nlohmann::eval_object(received, "metadata").items())
    {
        // process each key/value pair
        (void) kv;
    }
    ```

??? example "Example: ADL allows omitting the namespace qualifier"

    Because the helpers live in `namespace nlohmann`, they are found by
    argument-dependent lookup, so the explicit qualifier is optional in
    user code:

    ```cpp
    const json j = {{"a", 7}};
    auto a = eval_value(j, "a", 0);   // ADL finds nlohmann::eval_value
    ```

## See also

- [`basic_json::value`](basic_json/value.md) -- exception-throwing
  counterpart with different semantics on non-object receivers.
- [JSON Pointer](json_pointer/index.md) -- the address syntax accepted
  by the pointer overloads.
- Discussion [#5129](https://github.com/nlohmann/json/discussions/5129) --
  motivation and design rationale.

## Version history

- Added in version 3.12.1.
