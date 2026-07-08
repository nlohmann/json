# Migration Guide

This page collects some guidelines on how to future-proof your code for future versions of this library.

## Replace deprecated functions

The following functions have been deprecated and will be removed in the next major version (i.e., 4.0.0). All deprecations are annotated with [`HEDLEY_DEPRECATED_FOR`](https://nemequ.github.io/hedley/api-reference.html#HEDLEY_DEPRECATED_FOR) to report which function to use instead.

#### Parsing

- Function `friend std::istream& operator<<(basic_json&, std::istream&)` is deprecated since 3.0.0. Please use [`friend std::istream& operator>>(std::istream&, basic_json&)`](https://json.nlohmann.me/api/operator_gtgt/index.md) instead.

  ```
  nlohmann::json j;
  std::stringstream ss("[1,2,3]");
  j << ss;
  ```

  ```
  nlohmann::json j;
  std::stringstream ss("[1,2,3]");
  ss >> j;
  ```

- Passing iterator pairs or pointer/length pairs to parsing functions ([`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md), [`accept`](https://json.nlohmann.me/api/basic_json/accept/index.md), [`sax_parse`](https://json.nlohmann.me/api/basic_json/sax_parse/index.md), [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), and [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md) via initializer lists is deprecated since 3.8.0. Instead, pass two iterators; for instance, call `from_cbor(ptr, ptr+len)` instead of `from_cbor({ptr, len})`.

  ```
  const char* s = "[1,2,3]";
  bool ok = nlohmann::json::accept({s, s + std::strlen(s)});
  ```

  ```
  const char* s = "[1,2,3]";
  bool ok = nlohmann::json::accept(s, s + std::strlen(s));
  ```

#### JSON Pointers

- Comparing JSON Pointers with strings via [`operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md) and [`operator!=`](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md) is deprecated since 3.11.2. To compare a [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) `p` with a string `s`, convert `s` to a `json_pointer` first and use [`json_pointer::operator==`](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md) or [`json_pointer::operator!=`](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md).

  ```
  nlohmann::json::json_pointer lhs("/foo/bar/1");
  assert(lhs == "/foo/bar/1");
  ```

  ```
  nlohmann::json::json_pointer lhs("/foo/bar/1");
  assert(lhs == nlohmann::json::json_pointer("/foo/bar/1"));
  ```

- The implicit conversion from JSON Pointers to string ([`json_pointer::operator string_t`](https://json.nlohmann.me/api/json_pointer/operator_string_t/index.md)) is deprecated since 3.11.0. Use [`json_pointer::to_string`](https://json.nlohmann.me/api/json_pointer/to_string/index.md) instead.

  ```
  nlohmann::json::json_pointer ptr("/foo/bar/1");
  std::string s = ptr;
  ```

  ```
  nlohmann::json::json_pointer ptr("/foo/bar/1");
  std::string s = ptr.to_string();
  ```

- Passing a `basic_json` specialization as template parameter `RefStringType` to [`json_pointer`](https://json.nlohmann.me/api/json_pointer/index.md) is deprecated since 3.11.0. The string type can now be directly provided.

  ```
  using my_json = nlohmann::basic_json<std::map, std::vector, my_string_type>;
  nlohmann::json_pointer<my_json> ptr("/foo/bar/1");
  ```

  ```
  nlohmann::json_pointer<my_string_type> ptr("/foo/bar/1");
  ```

  Thereby, `nlohmann::my_json::json_pointer` is an alias for `nlohmann::json_pointer<my_string_type>` and is always an alias to the `json_pointer` with the appropriate string type for all specializations of `basic_json`.

#### Miscellaneous functions

- The function `iterator_wrapper` is deprecated since 3.1.0. Please use the member function [`items`](https://json.nlohmann.me/api/basic_json/items/index.md) instead.

  ```
  for (auto &x : nlohmann::json::iterator_wrapper(j))
  {
      std::cout << x.key() << ":" << x.value() << std::endl;
  }
  ```

  ```
  for (auto &x : j.items())
  {
      std::cout << x.key() << ":" << x.value() << std::endl;
  }
  ```

- Function `friend std::ostream& operator>>(const basic_json&, std::ostream&)` is deprecated since 3.0.0. Please use [`friend operator<<(std::ostream&, const basic_json&)`](https://json.nlohmann.me/api/operator_ltlt/index.md) instead.

  ```
  j >> std::cout;
  ```

  ```
  std::cout << j;
  ```

- The legacy comparison behavior for discarded values is deprecated since 3.11.0. It is already disabled by default and can still be enabled by defining [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md) to `1`.

  ```
  #define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 1
  #include <nlohmann/json.hpp>
  ```

  ```
  #include <nlohmann/json.hpp>
  ```

## Replace implicit conversions

Implicit conversions via [`operator ValueType`](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) will be switched off by default in the next major release of the library.

You can prepare existing code by already defining [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) to `0` and replace any implicit conversions with calls to [`get`](https://json.nlohmann.me/api/basic_json/get/index.md), [`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md), [`get_ref`](https://json.nlohmann.me/api/basic_json/get_ref/index.md), or [`get_ptr`](https://json.nlohmann.me/api/basic_json/get_ptr/index.md).

```
nlohmann::json j = "Hello, world!";
std::string s = j;
```

```
nlohmann::json j = "Hello, world!";
auto s = j.get<std::string>();
```

```
nlohmann::json j = "Hello, world!";
std::string s;
j.get_to(s);
```

## Import namespace `literals` for UDLs

The user-defined string literals [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md) and [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md) will be removed from the global namespace in the next major release of the library.

```
nlohmann::json j = "[1,2,3]"_json;
```

```
using namespace nlohmann::literals;
nlohmann::json j = "[1,2,3]"_json;
```

To prepare existing code, define [`JSON_USE_GLOBAL_UDLS`](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md) to `0` and bring the string literals into scope where needed.

## Do not hard-code the complete library namespace

The [`nlohmann` namespace](https://json.nlohmann.me/features/namespace/index.md) contains a sub-namespace to avoid problems when different versions or configurations of the library are used in the same project. Always use `nlohmann` as namespace or, when the exact version and configuration is relevant, use macro [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md) to denote the namespace.

```
void to_json(nlohmann::json_abi_v3_11_2::json& j, const person& p)
{
    j["age"] = p.age;
}
```

```
void to_json(nlohmann::json& j, const person& p)
{
    j["age"] = p.age;
}
```

```
void to_json(NLOHMANN_JSON_NAMESPACE::json& j, const person& p)
{
    j["age"] = p.age;
}
```

## Do not use the `details` namespace

The `details` namespace is not part of the public API of the library and can change in any version without an announcement. Do not rely on any function or type in the `details` namespace.
