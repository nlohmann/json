# Migration Guide

This page collects some guidelines on how to future-proof your code for future versions of this library.

## Replace deprecated functions

The following functions have been deprecated and will be removed in the next major version (i.e., 4.0.0). All
deprecations are annotated with
[`HEDLEY_DEPRECATED_FOR`](https://nemequ.github.io/hedley/api-reference.html#HEDLEY_DEPRECATED_FOR) to report which
function to use instead.

#### Parsing

- Function `friend std::istream& operator<<(basic_json&, std::istream&)` is deprecated since 3.0.0. Please use
  [`friend std::istream&  operator>>(std::istream&, basic_json&)`](../api/operator_gtgt.md) instead.
  
    === "Deprecated"
    
        ```cpp
        nlohmann::json j;
        std::stringstream ss("[1,2,3]");
        j << ss;
        ```
    
    === "Future-proof"

        ```cpp
        nlohmann::json j;
        std::stringstream ss("[1,2,3]");
        ss >> j;
        ```

- Passing iterator pairs or pointer/length pairs to parsing functions ([`parse`](../api/basic_json/parse.md),
  [`accept`](../api/basic_json/accept.md), [`sax_parse`](../api/basic_json/sax_parse.md),
  [`from_cbor`](../api/basic_json/from_cbor.md), [`from_msgpack`](../api/basic_json/from_msgpack.md),
  [`from_ubjson`](../api/basic_json/from_ubjson.md), and [`from_bson`](../api/basic_json/from_bson.md) via initializer
  lists is deprecated since 3.8.0. Instead, pass two iterators; for instance, call `from_cbor(ptr, ptr+len)` instead of
  `from_cbor({ptr, len})`.

    === "Deprecated"
  
          ```cpp
          const char* s = "[1,2,3]";
          bool ok = nlohmann::json::accept({s, s + std::strlen(s)});
          ```
  
    === "Future-proof"
  
          ```cpp
          const char* s = "[1,2,3]";
          bool ok = nlohmann::json::accept(s, s + std::strlen(s));
          ```

#### JSON Pointers

- Comparing JSON Pointers with strings via [`operator==`](../api/json_pointer/operator_eq.md) and
  [`operator!=`](../api/json_pointer/operator_ne.md) is deprecated since 3.11.2. To compare a
  [`json_pointer`](../api/json_pointer/index.md) `p` with a string `s`, convert `s` to a `json_pointer` first and use
  [`json_pointer::operator==`](../api/json_pointer/operator_eq.md) or
  [`json_pointer::operator!=`](../api/json_pointer/operator_ne.md).
    
    === "Deprecated"
  
        ```cpp
        nlohmann::json::json_pointer lhs("/foo/bar/1");
        assert(lhs == "/foo/bar/1");
        ```
  
    === "Future-proof"

        ```cpp
        nlohmann::json::json_pointer lhs("/foo/bar/1");
        assert(lhs == nlohmann::json::json_pointer("/foo/bar/1"));
        ```

- The implicit conversion from JSON Pointers to string
  ([`json_pointer::operator string_t`](../api/json_pointer/operator_string_t.md)) is deprecated since 3.11.0. Use
  [`json_pointer::to_string`](../api/json_pointer/to_string.md) instead.
  
    === "Deprecated"
  
          ```cpp
          nlohmann::json::json_pointer ptr("/foo/bar/1");
          std::string s = ptr;
          ```
  
    === "Future-proof"
  
          ```cpp
          nlohmann::json::json_pointer ptr("/foo/bar/1");
          std::string s = ptr.to_string();
          ```

- Passing a `basic_json` specialization as template parameter `RefStringType` to
  [`json_pointer`](../api/json_pointer/index.md) is deprecated since 3.11.0. The string type can now be directly
  provided.
  
    === "Deprecated"
  
          ```cpp
          using my_json = nlohmann::basic_json<std::map, std::vector, my_string_type>;
          nlohmann::json_pointer<my_json> ptr("/foo/bar/1");
          ```
  
    === "Future-proof"
  
          ```cpp
          nlohmann::json_pointer<my_string_type> ptr("/foo/bar/1");
          ```
  
    Thereby, `nlohmann::my_json::json_pointer` is an alias for `nlohmann::json_pointer<my_string_type>` and is always an 
    alias to the `json_pointer` with the appropriate string type for all specializations of `basic_json`.

#### Miscellaneous functions

- The function `iterator_wrapper` is deprecated since 3.1.0. Please use the member function
  [`items`](../api/basic_json/items.md) instead.
  
    === "Deprecated"

          ```cpp
          for (auto &x : nlohmann::json::iterator_wrapper(j))
          {
              std::cout << x.key() << ":" << x.value() << std::endl;
          }
          ```

    === "Future-proof"

          ```cpp
          for (auto &x : j.items())
          {
              std::cout << x.key() << ":" << x.value() << std::endl;
          }
          ```

- Function `friend std::ostream& operator>>(const basic_json&, std::ostream&)` is deprecated since 3.0.0. Please use
  [`friend operator<<(std::ostream&, const basic_json&)`](../api/operator_ltlt.md) instead.
  
    === "Deprecated"

          ```cpp
          j >> std::cout;
          ```

    === "Future-proof"

          ```cpp
          std::cout << j;
          ```

- The legacy comparison behavior for discarded values is deprecated since 3.11.0. It is already disabled by default and
  can still be enabled by defining
  [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../api/macros/json_use_legacy_discarded_value_comparison.md) to `1`.
  
    === "Deprecated"

          ```cpp
          #define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 1
          #include <nlohmann/json.hpp>
          ```

    === "Future-proof"

          ```cpp
          #include <nlohmann/json.hpp>
          ```

## Replace implicit conversions

Implicit conversions via [`operator ValueType`](../api/basic_json/operator_ValueType.md) will be switched off by default
in the next major release of the library.

You can prepare existing code by already defining
[`JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md) to `0` and replace any implicit
conversions with calls to [`get`](../api/basic_json/get.md), [`get_to`](../api/basic_json/get_to.md),
[`get_ref`](../api/basic_json/get_ref.md), or [`get_ptr`](../api/basic_json/get_ptr.md).

=== "Deprecated"

      ```cpp
      nlohmann::json j = "Hello, world!";
      std::string s = j;
      ```

=== "Future-proof"

      ```cpp
      nlohmann::json j = "Hello, world!";
      auto s = j.template get<std::string>();
      ```

=== "Future-proof (alternative)"

      ```cpp
      nlohmann::json j = "Hello, world!";
      std::string s;
      j.get_to(s);
      ```

You can prepare existing code by already defining
[`JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md) to `0` and replace any implicit
conversions with calls to [`get`](../api/basic_json/get.md).

## Import namespace `literals` for UDLs

The user-defined string literals [`operator""_json`](../api/operator_literal_json.md) and
[`operator""_json_pointer`](../api/operator_literal_json_pointer.md) will be removed from the global namespace in the
next major release of the library.

=== "Deprecated"

      ```cpp
      nlohmann::json j = "[1,2,3]"_json;
      ```

=== "Future-proof"

      ```cpp
      using namespace nlohmann::literals;
      nlohmann::json j = "[1,2,3]"_json;
      ```

To prepare existing code, define [`JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md) to `0` and bring the
string literals into scope where needed.

## Do not hard-code the complete library namespace

The [`nlohmann` namespace](../features/namespace.md) contains a sub-namespace to avoid problems when different
versions or configurations of the library are used in the same project. Always use `nlohmann` as namespace or, when the
exact version and configuration is relevant, use macro
[`NLOHMANN_JSON_NAMESPACE`](../api/macros/nlohmann_json_namespace.md) to denote the namespace.

=== "Dangerous"

      ```cpp
      void to_json(nlohmann::json_abi_v3_11_2::json& j, const person& p)
      {
          j["age"] = p.age;
      }
      ```

=== "Future-proof"

      ```cpp
      void to_json(nlohmann::json& j, const person& p)
      {
          j["age"] = p.age;
      }
      ```

=== "Future-proof (alternative)"

      ```cpp
      void to_json(NLOHMANN_JSON_NAMESPACE::json& j, const person& p)
      {
          j["age"] = p.age;
      }
      ```

## Do not use the `details` namespace

The `details` namespace is not part of the public API of the library and can change in any version without announcement.
Do not rely on any function or type in the `details` namespace.
