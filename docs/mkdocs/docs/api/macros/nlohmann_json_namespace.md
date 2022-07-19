# NLOHMANN_JSON_NAMESPACE

```cpp
#define NLOHMANN_JSON_NAMESPACE
```

This macro evaluates to the full name of the `nlohmann` namespace, including
the name of a versioned and ABI-tagged inline namespace. Use this macro to
unambiguously refer to the `nlohmann` namespace.

## Default definition

The default value consists of a prefix, a version string, and optional ABI tags
depending on whether ABI-affecting macros are defined (e.g.,
[`JSON_DIAGNOSTICS`](json_diagnostics.md), and
[`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](json_use_legacy_discarded_value_comparison.md)).

When the macro is not defined, the library will define it to its default value.

## See also

- [`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](nlohmann_json_namespace_begin.md)

## Version history

- Added in version 3.11.0.
