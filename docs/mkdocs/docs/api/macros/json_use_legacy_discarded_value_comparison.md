# JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON

```cpp
#define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON /* value */
```

This macro enables the (incorrect) legacy comparison behavior of discarded JSON values.
Possible values are `1` to enable or `0` to disable (default).

When enabled, comparisons involving at least one discarded JSON value yield results as follows:

| **Operator** | **Result**    |
|--------------|---------------|
| `==`         | `#!cpp false` |
| `!=`         | `#!cpp true`  |
| `<`          | `#!cpp false` |
| `<=`         | `#!cpp true`  |
| `>=`         | `#!cpp true`  |
| `>`          | `#!cpp false` |

Otherwise, comparisons involving at least one discarded JSON value always yield `#!cpp false`.

## Default definition

The default value is `0`.

```cpp
#define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 0
```

When the macro is not defined, the library will define it to its default value.

## Notes

!!! warning "Inconsistent behavior in C++20 and beyond"

    When targeting C++20 or above, enabling the legacy comparison behavior is _strongly_
    discouraged.

      - The 3-way comparison operator (`<=>`) will always give the correct result
        (`#!cpp std::partial_ordering::unordered`) regardless of the value of
        `JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`.
      - Overloads for the equality and relational operators emulate the legacy behavior.

    Code outside your control may use either 3-way comparison or the equality and
    relational operators, resulting in inconsistent and unpredictable behavior.

    See [`operator<=>`](../basic_json/operator_spaceship.md) for more information on 3-way
    comparison.

!!! warning "Deprecation"

    The legacy comparison behavior is deprecated and may be removed in a future major
    version release.

    New code should not depend on it and existing code should try to remove or rewrite
    expressions relying on it.

## Version history

- Added in version 3.11.0.
