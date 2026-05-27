# <small>nlohmann::</small>eval_value, eval_array, eval_object

```cpp
#include <nlohmann/eval.hpp>
```

Null-safe, `noexcept` accessors for retrieving values from a JSON object.

These free functions are an opt-in alternative to
[`basic_json::value`](basic_json/value.md). Unlike `value()`, they **never
throw** -- on any non-matching condition (the receiver is not an object, the
key/pointer is missing, the resolved value is null, or has the wrong type)
they silently fall back to the supplied default value (for `eval_value`) or
to a static empty array/object (for `eval_array` / `eval_object`).

This brings the developer experience of accessing untrusted server-side JSON
closer to JavaScript's optional chaining (`?.`) and nullish coalescing (`??`).

## API

```cpp
// (1) -- access by key
template <class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::object_t::key_type& key,
                     const ValueType& default_value) noexcept;

// (2) -- access by JSON Pointer
template <class BasicJsonType, class ValueType>
ValueType eval_value(const BasicJsonType& j,
                     const typename BasicJsonType::json_pointer& ptr,
                     const ValueType& default_value) noexcept;

// (3) -- array access by key
template <class BasicJsonType>
const BasicJsonType& eval_array(
    const BasicJsonType& j,
    const typename BasicJsonType::object_t::key_type& key) noexcept;

// (4) -- array access by JSON Pointer
template <class BasicJsonType>
const BasicJsonType& eval_array(
    const BasicJsonType& j,
    const typename BasicJsonType::json_pointer& ptr) noexcept;

// (5) -- object access by key
template <class BasicJsonType>
const BasicJsonType& eval_object(
    const BasicJsonType& j,
    const typename BasicJsonType::object_t::key_type& key) noexcept;

// (6) -- object access by JSON Pointer
template <class BasicJsonType>
const BasicJsonType& eval_object(
    const BasicJsonType& j,
    const typename BasicJsonType::json_pointer& ptr) noexcept;
```

## Semantics

| Function                      | On non-object receiver | On missing key/path | On null resolved value | On wrong resolved type |
| ----------------------------- | ---------------------- | ------------------- | ---------------------- | ---------------------- |
| `eval_value(j, key, default)` | returns `default`      | returns `default`   | returns `default`      | returns `default`      |
| `eval_value(j, ptr, default)` | returns `default`      | returns `default`   | returns `default`      | returns `default`      |
| `eval_array(j, key)`          | returns empty `[]`     | returns empty `[]`  | returns empty `[]`     | returns empty `[]`     |
| `eval_array(j, ptr)`          | returns empty `[]`     | returns empty `[]`  | returns empty `[]`     | returns empty `[]`     |
| `eval_object(j, key)`         | returns empty `{}`     | returns empty `{}`  | returns empty `{}`     | returns empty `{}`     |
| `eval_object(j, ptr)`         | returns empty `{}`     | returns empty `{}`  | returns empty `{}`     | returns empty `{}`     |

All overloads are `noexcept`. They never throw regardless of the receiver's
type or the structure of the JSON value.

## Comparison with `value()`

| Condition                                    | `j.value(...)`               | `eval_value(j, ...)` |
| -------------------------------------------- | ---------------------------- | -------------------- |
| `j` is object, key exists, correct type      | returns value                | returns value        |
| `j` is object, key missing                   | returns default              | returns default      |
| `j` is `null`                                | **throws `type_error`**      | returns default      |
| `j` is array, string, number, bool, ...      | **throws `type_error`**      | returns default      |
| Resolved value is `null`                     | returns null-converted value | returns default      |

## Examples

### Safe access on a possibly-null payload

```cpp
#include <nlohmann/json.hpp>
#include <nlohmann/eval.hpp>

using nlohmann::json;

auto received = from_server();   // might be null, partial, or wrong type

int  a = nlohmann::eval_value(received, "a", 0);
auto d = nlohmann::eval_value(received,
                              json::json_pointer("/c/d"),
                              std::string{});

for (const auto& item : nlohmann::eval_array(received, "items"))
{
    // safe, no need to check is_object() / contains() / is_array()
}

for (const auto& [k, v] : nlohmann::eval_object(received, "metadata").items())
{
    // safe, no exceptions
}
```

### ADL

Because `eval_*` lives in `namespace nlohmann`, it is found by
argument-dependent lookup -- you can omit the namespace qualifier:

```cpp
const json j = {{"a", 7}};
auto a = eval_value(j, "a", 0);   // ADL finds nlohmann::eval_value
```

## Design notes

- These helpers rely only on the **public** API of `basic_json`
  (`is_object`, `is_array`, `is_null`, `find`, `end`, `get`,
  `contains(json_pointer)`, `at(json_pointer)`).
- They are intentionally provided as **non-member** functions in an
  **opt-in** header (`<nlohmann/eval.hpp>`). They are not pulled in by
  `<nlohmann/json.hpp>` and are not bundled into
  `single_include/nlohmann/json.hpp`.
- The empty fallback array/object returned by reference is a process-lifetime
  singleton constructed once into properly-aligned uninitialized storage via
  placement-new. Its destructor is intentionally never invoked at process
  exit, which avoids both Clang's `-Wexit-time-destructors` warning and any
  static-destruction-order concerns.
- `ValueType` for `eval_value` is **deduced** from `default_value`, so
  the common case never requires explicit template arguments.

## Limitation under `JSON_NOEXCEPTION`

The helpers' `noexcept` guarantee is best-effort under
[`JSON_NOEXCEPTION`](macros/json_noexception.md):

- `eval_array` / `eval_object` (both key and JSON Pointer overloads) and
  the JSON Pointer overload of `eval_value` remain fully noexcept-correct,
  because they only rely on `is_*` predicates, `find`, `contains`, and
  `at` paths that are guarded by a successful `contains` check.
- `eval_value(j, key, default)` calls `it->get<ValueType>()` for type
  conversion. Under `JSON_NOEXCEPTION`, a conversion failure inside
  `from_json` calls `std::abort()` instead of throwing, so passing a
  receiver where `j[key]` is convertibility-incompatible with `ValueType`
  may abort the process. Use the JSON Pointer overload, or perform an
  explicit `is_*` check at the call site, when running with exceptions
  disabled.

## See also

- [`basic_json::value`](basic_json/value.md) -- exception-throwing
  counterpart with different semantics on non-object receivers.
- Discussion [#5129](https://github.com/nlohmann/json/discussions/5129) --
  motivation and design rationale.

## Version history

- Added in version 3.12.1.
