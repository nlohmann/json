# Compile times

The library is header-only and makes heavy use of templates, so every translation unit that includes
`<nlohmann/json.hpp>` pays for parsing the header and instantiating what it uses. This page lists the options to reduce
that cost, ordered by how much they typically save.

!!! info "Measurements"

    The numbers below are medians of nine runs compiling a single translation unit with `-std=c++17 -c` against the
    single-header version, with Apple clang and GCC 16 on macOS (Apple silicon). They show the order of magnitude to
    expect; measure your own code before and after a change.

## Include `json_fwd.hpp` in headers

Header files that only need to *name* the `json` type — for function declarations, members held by pointer or
reference, or friend declarations — can include `<nlohmann/json_fwd.hpp>` instead of `<nlohmann/json.hpp>`. It only
forward-declares `basic_json`, `json`, `ordered_json`, `json_pointer`, and `adl_serializer`. The translation units that
actually use the values then include `<nlohmann/json.hpp>`.

```cpp title="person.hpp"
#pragma once
#include <nlohmann/json_fwd.hpp>

struct person;
void to_json(nlohmann::json& j, const person& p);
void from_json(const nlohmann::json& j, person& p);
```

```cpp title="person.cpp"
#include "person.hpp"
#include <nlohmann/json.hpp>

void to_json(nlohmann::json& j, const person& p) { /* ... */ }
void from_json(const nlohmann::json& j, person& p) { /* ... */ }
```

| Compiler    | `json.hpp` (`-O0`) | `json_fwd.hpp` (`-O0`) | Change |
|-------------|-------------------:|-----------------------:|-------:|
| Apple clang |             704 ms |                 329 ms |   −53% |
| GCC 16      |             779 ms |                 242 ms |   −69% |

This is the most effective option, because it avoids the full header in every translation unit that includes
*your* headers.

## Opt out of the automatic user-defined string literals

The user-defined string literals [`operator""_json`](../api/operator_literal_json.md) and
[`operator""_json_pointer`](../api/operator_literal_json_pointer.md) are ordinary inline functions whose bodies call the
parser. As `<nlohmann/json.hpp>` includes them by default, every translation unit instantiates the parser, even if it
never parses anything itself.

Define [`JSON_NO_AUTOMATIC_UDLS`](../api/macros/json_no_automatic_udls.md) for the whole project and include
`<nlohmann/json_literals.hpp>` instead of `<nlohmann/json.hpp>` in the files that use the literals (it includes
`<nlohmann/json.hpp>` itself):

```cmake
target_compile_definitions(my_target PRIVATE JSON_NO_AUTOMATIC_UDLS)
```

```cpp
#include <nlohmann/json_literals.hpp> // only where "..."_json is used; includes <nlohmann/json.hpp>
```

The saving applies to translation units that do not parse JSON, for example ones that define types and their
conversions or only pass `json` values around:

| Compiler    | Translation unit | Default (`-O0` / `-O2`) | `JSON_NO_AUTOMATIC_UDLS` (`-O0` / `-O2`) | Change      |
|-------------|------------------|------------------------:|-----------------------------------------:|------------:|
| Apple clang | model            |         776 ms / 846 ms |                          629 ms / 692 ms | −19% / −18% |
| GCC 16      | model            |       1022 ms / 1120 ms |                          882 ms / 965 ms | −14% / −14% |
| Apple clang | parsing          |       992 ms / 1815 ms |                        1006 ms / 1823 ms |   +1% / 0% |
| GCC 16      | parsing          |      2018 ms / 3420 ms |                        1990 ms / 3454 ms |   −1% / +1% |

Translation units that include only the header save up to a third. Translation units that parse anyway instantiate
the parser regardless and see no difference.

## Instantiate `basic_json` once

Each translation unit instantiates the member functions of `nlohmann::json` it uses. An explicit instantiation
declaration tells the compiler that the non-template members are instantiated elsewhere, so it can skip them:

```cpp title="json_instance.hpp"
#pragma once
#include <nlohmann/json.hpp>

extern template class nlohmann::basic_json<>;
```

```cpp title="json_instance.cpp"
#include "json_instance.hpp"

template class nlohmann::basic_json<>;
```

Include `json_instance.hpp` instead of `<nlohmann/json.hpp>` and compile and link `json_instance.cpp` once.

| Compiler    | Translation unit    | Default (`-O0` / `-O2`) | `extern template` (`-O0` / `-O2`) | Change      |
|-------------|---------------------|------------------------:|----------------------------------:|------------:|
| Apple clang | parsing             |        992 ms / 1815 ms |                  953 ms / 1625 ms |  −4% / −10% |
| GCC 16      | parsing             |       2018 ms / 3420 ms |                 1522 ms / 2728 ms | −25% / −20% |
| Apple clang | `json_instance.cpp` |                       — |                 2166 ms / 4660 ms |           — |
| GCC 16      | `json_instance.cpp` |                       — |                5085 ms / 10616 ms |           — |

Notes:

- The saving grows with the number of translation units that use `json`, while the instantiation translation unit is
  compiled only once (and is rarely recompiled, as it does not depend on your code).
- Member function templates (such as `get<T>()`, `parse(InputType&&)`, or `value(key, default)`) are not covered by
  the explicit instantiation and are still instantiated where they are used.
- The declaration covers exactly `nlohmann::json`. Add the same lines for `nlohmann::ordered_json`
  (`nlohmann::basic_json<nlohmann::ordered_map>`) or your own `basic_json` specializations if you use them.

## Use C++20 modules

With a toolchain that supports named modules, `import nlohmann.json;` compiles the library once into a module and
avoids parsing the header in every translation unit. See [Modules](../features/modules.md) for requirements and known
issues. Module support is experimental and currently depends heavily on the compiler version.

## Use precompiled headers

Build systems can precompile `<nlohmann/json.hpp>` together with other stable headers, for example with CMake's
[`target_precompile_headers`](https://cmake.org/cmake/help/latest/command/target_precompile_headers.html):

```cmake
target_precompile_headers(my_target PRIVATE <nlohmann/json.hpp>)
```

This removes the cost of parsing the header, but not of instantiating templates in each translation unit, so it
combines well with the options above.

## Options without effect on compile times

Some configuration macros change what the library declares, but do not measurably change compile times:

| Macro                                                                  | Apple clang, model (`-O0` / `-O2`) | GCC 16, model (`-O0` / `-O2`) |
|------------------------------------------------------------------------|-----------------------------------:|------------------------------:|
| default                                                                |                    776 ms / 846 ms |             1022 ms / 1120 ms |
| [`JSON_NO_IO`](../api/macros/json_no_io.md)                            |                    764 ms / 836 ms |             1022 ms / 1117 ms |
| [`JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md)`=0`    |                    763 ms / 852 ms |             1019 ms / 1106 ms |

`JSON_USE_GLOBAL_UDLS` only controls *where* the literals are declared; to avoid their cost, use
`JSON_NO_AUTOMATIC_UDLS` instead.

## See also

- [`JSON_NO_AUTOMATIC_UDLS`](../api/macros/json_no_automatic_udls.md) - do not include the user-defined string
  literals automatically
- [Modules](../features/modules.md) - C++20 module support
- [Header only](index.md) - including the library
