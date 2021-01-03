# `nlohmann` Namespace

The 3.11.0 release introduced an
[inline namespace](https://en.cppreference.com/w/cpp/language/namespace#Inline_namespaces) to allow different parts of
a codebase to safely use different versions of the JSON library as long as they never exchange instances of library
types.

## Structure

The complete default namespace name is derived as follows:

- The root namespace is always `nlohmann`.
- The inline namespace starts with `json_abi` and is followed by serveral optional ABI tags according to the value of
  these ABI-affecting macros, in order:
    - [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) defined non-zero appends `_diag`.
    - [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../api/macros/json_use_legacy_discarded_value_comparison.md)
      defined non-zero appends `_ldvcmp`.
- The inline namespace ends with the suffix `_v` followed by the 3 components of the version number separated by
  underscores. To omit the version component, see [Disabling the version component](#disabling-the-version-component)
  below.

For example, the namespace name for version 3.11.2 with `JSON_DIAGNOSTICS` defined to `1` is:

```cpp
nlohmann::json_abi_diag_v3_11_2
```

## Purpose

Several incompatibilities have been observed. Amongst the most common ones is linking code compiled with different
definitions of [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md). This is illustrated in the diagram below.

```plantuml
[**nlohmann_json (v3.10.5)**\nJSON_DIAGNOSTICS=0] as [json]
[**nlohmann_json (v3.10.5)**\nJSON_DIAGNOSTICS=1] as [json_diag]
[**some_library**] as [library]
[**application**] as [app]

[library] ..|> [json]
[app] ..|> [json_diag]
[app] ..|>[library]
```

In releases prior to 3.11.0, mixing any version of the JSON library with different `JSON_DIAGNOSTICS` settings would
result in a crashing application. If `some_library` never passes instances of JSON library types to the application,
this scenario became safe in version 3.11.0 and above due to the inline namespace yielding distinct symbol names.

## Limitations

Neither the compiler nor the linker will issue as much as a warning when translation units – intended to be linked
together and that include different versions and/or configurations of the JSON library – exchange and use library
types.

There is an exception when forward declarations are used (i.e., when including `json_fwd.hpp`) in which case the linker
may complain about undefined references.

## Disabling the version component

Different versions are not necessarily ABI-incompatible, but the project does not actively track changes in the ABI and
recommends that all parts of a codebase exchanging library types be built with the same version. Users can, **at their
own risk**, disable the version component of the linline namespace, allowing different versions – but not
configurations – to be used in cases where the linker would otherwise output undefined reference errors.

To do so, define [`NLOHMANN_JSON_NAMESPACE_NO_VERSION`](../api/macros/nlohmann_json_namespace_no_version.md) to `1`.

This applies to version 3.11.2 and above only, versions 3.11.0 and 3.11.1 can apply the technique described in the next
section to emulate the effect of the `NLOHMANN_JSON_NAMESPACE_NO_VERSION` macro.

!!! danger "Use at your own risk"

    Disabling the namespace version component and mixing ABI-incompatible versions will result in crashes or incorrect
    behavior. You have been warned!
## Disabling the inline namespace completely

When interoperability with code using a pre-3.11.0 version of the library is required, users can, **at their own risk**
restore the old namespace layout by redefining
[`NLOHMANN_JSON_NAMESPACE_BEGIN, NLOHMANN_JSON_NAMESPACE_END`](../api/macros/nlohmann_json_namespace_begin.md) as
follows:

```cpp
#define NLOHMANN_JSON_NAMESPACE_BEGIN  namespace nlohmann {
#define NLOHMANN_JSON_NAMESPACE_END    }
```

!!! danger "Use at your own risk"

    Overriding the namespace and mixing ABI-incompatible versions will result in crashes or incorrect behavior. You
    have been warned!

## Version history

- Introduced inline namespace (`json_v3_11_0[_abi-tag]*`) in version 3.11.0.
- Changed structure of inline namespace in version 3.11.2.
