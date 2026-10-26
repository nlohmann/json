# Compile times

The library is header-only and makes heavy use of templates, so every translation unit that includes
`<nlohmann/json.hpp>` pays for parsing the header and instantiating what it uses. This page lists the options to reduce
that cost, ordered by how much they typically save.

!!! info "Measurements"

    The numbers below are medians of the wall-clock time of nine runs compiling a single translation unit with
    `-std=c++17 -c` against the single-header version, with Apple clang 21.0.0 (clang-2100.3.34.2) and Homebrew GCC
    16.2.0 on macOS (Apple M1 Max). All configurations were run interleaved, in alternating order. They show the order
    of magnitude to expect; measure your own code before and after a change.

    The translation units are listed below. They replace the ones used for earlier versions of this page, whose
    sources were not published, so the numbers differ from earlier versions.

??? example "Measured translation units"

    The *model* and *parsing* translation units start with `#include <string>`, `#include <vector>`, and
    `#include <nlohmann/json.hpp>`; the *header-only* translation unit includes only the library header.

    ```cpp title="model translation unit"
    struct person
    {
        std::string name;
        int age = 0;
        std::vector<std::string> tags;
    };

    void to_json(nlohmann::json& j, const person& p)
    {
        j = nlohmann::json{{"name", p.name}, {"age", p.age}, {"tags", p.tags}};
    }

    void from_json(const nlohmann::json& j, person& p)
    {
        j.at("name").get_to(p.name);
        j.at("age").get_to(p.age);
        j.at("tags").get_to(p.tags);
    }

    nlohmann::json roundtrip(const person& p)
    {
        nlohmann::json j = p;
        return nlohmann::json(j.get<person>());
    }
    ```

    ```cpp title="parsing translation unit"
    std::size_t parse_and_dump(const std::string& s)
    {
        const nlohmann::json j = nlohmann::json::parse(s);
        return j.dump(2).size();
    }
    ```

    ```cpp title="header-only translation unit"
    #include <nlohmann/json.hpp> // or <nlohmann/json_fwd.hpp>

    struct person;
    void to_json(nlohmann::json& j, const person& p);
    void from_json(const nlohmann::json& j, person& p);
    ```

<div class="nj-fig-wrap" markdown>
--8<-- "images/compile_times.svg"
</div>
<p class="nj-charts-caption" markdown>Change in compile time at `-O0` against the default configuration of the same
translation unit, taken from the tables below (medians of nine runs, see above). * computed from the milliseconds in
[Options without effect on compile times](#options-without-effect-on-compile-times).</p>

## Include `json_fwd.hpp` in headers

Header files that only need to *name* the `json` type — for function declarations, members held by pointer or
reference, or friend declarations — can include `<nlohmann/json_fwd.hpp>` instead of `<nlohmann/json.hpp>`. It only
forward-declares `basic_json`, `json_pointer`, `adl_serializer`, and `ordered_map`, and defines the aliases `json` and
`ordered_json`. The translation units that
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
| Apple clang |             868 ms |                 332 ms |   −62% |
| GCC 16      |            1164 ms |                 210 ms |   −82% |

<p class="nj-table-caption" markdown>Compile time of the header-only translation unit at `-O0` with each header, as the median wall-clock time of nine runs (see "Measurements" above). A negative change means a faster build.</p>

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
| Apple clang | model            |       1051 ms / 1300 ms |                         935 ms / 1170 ms | −11% / −10% |
| GCC 16      | model            |       1801 ms / 2106 ms |                        1598 ms / 1983 ms |  −11% / −6% |
| Apple clang | parsing          |       1157 ms / 2016 ms |                        1146 ms / 2006 ms |    −1% / 0% |
| GCC 16      | parsing          |       2529 ms / 4087 ms |                        2484 ms / 4059 ms |   −2% / −1% |

<p class="nj-table-caption" markdown>Compile time of the model and parsing translation units without and with `JSON_NO_AUTOMATIC_UDLS`, at `-O0` and `-O2`.</p>

The model translation unit saves about a tenth. Translation units that parse anyway instantiate the parser regardless
and see no difference.

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
| Apple clang | parsing             |       1157 ms / 2016 ms |                 1071 ms / 1844 ms |   −7% / −9% |
| GCC 16      | parsing             |       2529 ms / 4087 ms |                 1994 ms / 3190 ms | −21% / −22% |
| Apple clang | `json_instance.cpp` |                       — |                 2573 ms / 6221 ms |           — |
| GCC 16      | `json_instance.cpp` |                       — |                6489 ms / 13759 ms |           — |

<p class="nj-table-caption" markdown>Compile time of the parsing translation unit without and with the `extern template` declaration, at `-O0` and `-O2`. The `json_instance.cpp` rows are the one-off cost of the translation unit that holds the instantiation.</p>

Notes:

- The saving grows with the number of translation units that use `json`, while the instantiation translation unit is
  compiled only once (and is rarely recompiled, as it does not depend on your code).
- Member function templates (such as `get<T>()`, `parse(InputType&&)`, or `value(key, default)`) are not covered by
  the explicit instantiation and are still instantiated where they are used.
- The declaration covers exactly `nlohmann::json`. Add the same lines for `nlohmann::ordered_json`
  (`nlohmann::basic_json<nlohmann::ordered_map>`) or your own `basic_json` specializations if you use them.

## Switch off filesystem support

With C++17, the library includes `<filesystem>` to provide conversions from and to `std::filesystem::path`
(see [`JSON_HAS_FILESYSTEM`](../api/macros/json_has_filesystem.md)). Parsing `<filesystem>` is a fixed cost in every
translation unit, and it also pulls in `<iomanip>`, `<istream>`, and `<ostream>` (and, with GCC's libstdc++,
`<sstream>`). If you do not convert paths, switch the detection off for the whole project:

```cmake
target_compile_definitions(my_target PRIVATE JSON_HAS_FILESYSTEM=0 JSON_HAS_EXPERIMENTAL_FILESYSTEM=0)
```

| Compiler    | Translation unit | Default (`-O0` / `-O2`) | Filesystem off (`-O0` / `-O2`) | Change     |
|-------------|------------------|------------------------:|-------------------------------:|-----------:|
| Apple clang | model            |       1051 ms / 1300 ms |               998 ms / 1257 ms | −5% / −3%  |
| GCC 16      | model            |       1801 ms / 2106 ms |              1636 ms / 2008 ms | −9% / −5%  |
| Apple clang | parsing          |       1157 ms / 2016 ms |              1107 ms / 1971 ms | −4% / −2%  |
| GCC 16      | parsing          |       2529 ms / 4087 ms |              2405 ms / 4029 ms | −5% / −1%  |

<p class="nj-table-caption" markdown>Compile time with `JSON_HAS_FILESYSTEM=0` and `JSON_HAS_EXPERIMENTAL_FILESYSTEM=0` against the default configuration, at `-O0` and `-O2`.</p>

Only with filesystem support switched off does [`JSON_NO_IO`](../api/macros/json_no_io.md) remove the stream headers
from the translation unit, so the two macros save most together:

| Compiler    | Translation unit | Default (`-O0` / `-O2`) | Filesystem off and `JSON_NO_IO` (`-O0` / `-O2`) | Change     |
|-------------|------------------|------------------------:|------------------------------------------------:|-----------:|
| Apple clang | model            |       1051 ms / 1300 ms |                                 969 ms / 1219 ms | −8% / −6%  |
| GCC 16      | model            |       1801 ms / 2106 ms |                                1605 ms / 1982 ms | −11% / −6% |
| Apple clang | parsing          |       1157 ms / 2016 ms |                                1083 ms / 1947 ms | −6% / −3%  |
| GCC 16      | parsing          |       2529 ms / 4087 ms |                                2384 ms / 3972 ms | −6% / −3%  |

<p class="nj-table-caption" markdown>Compile time with filesystem support switched off and `JSON_NO_IO` defined, against the default configuration, at `-O0` and `-O2`.</p>

The trade-off: the library's own `to_json`/`from_json` overloads for `std::filesystem::path` (which store the path as
UTF-8) are removed. In a test with both compilers on macOS, paths still converted through their implicit conversion
from and to `std::string`; whether that fallback exists depends on the platform's native path string type
(`std::wstring` on Windows), so check code that converts paths. `JSON_NO_IO` additionally removes all stream
functions (see [Options without effect](#options-without-effect-on-compile-times)).

## Use C++20 modules

With a toolchain that supports named modules, `import nlohmann.json;` compiles the library once into a module and
avoids parsing the header in every translation unit. See [Modules](../features/modules.md) for requirements and known
issues. Module support is experimental and currently depends heavily on the compiler version.

<div class="nj-fig-wrap" markdown>
--8<-- "images/compile_times_modules.svg"
</div>
<p class="nj-caption" markdown>Change in compile time per translation unit at `-O0` when `#include <nlohmann/json.hpp>` is
replaced by `import nlohmann.json;`, both with `-std=c++20`, and the one-off cost of building the module, taken from
the table below.</p>

| Compiler    | Translation unit          | `#include` (`-O0` / `-O2`) | `import nlohmann.json;` (`-O0` / `-O2`) | Change      |
|-------------|---------------------------|---------------------------:|----------------------------------------:|------------:|
| Apple clang | model                     |          1311 ms / 1597 ms |                          680 ms / 914 ms | −48% / −43% |
| GCC 16      | model                     |          2156 ms / 2588 ms |                        1153 ms / 1580 ms | −47% / −39% |
| Apple clang | parsing                   |          1387 ms / 2319 ms |                         800 ms / 1676 ms | −42% / −28% |
| GCC 16      | parsing                   |          2838 ms / 4520 ms |                        1810 ms / 3476 ms | −36% / −23% |
| Apple clang | `json.cppm` (module)      |                          — |                        1630 ms / 1642 ms |           — |
| GCC 16      | `json.cppm` (module)      |                          — |                        2538 ms / 2547 ms |           — |

<p class="nj-table-caption" markdown>Compile time with `#include <nlohmann/json.hpp>` and with `import nlohmann.json;`, both with `-std=c++20`, at `-O0` and `-O2`. The `json.cppm` rows are the one-off cost of building the module.</p>

Both columns use `-std=c++20`; with `-std=c++17`, the `#include` baseline is 17% to 20% faster (see the next
section). The module is built once per set of compiler flags and pays for itself from about the third translation
unit that imports it. Notes from the measurement:

- Apple clang only accepts the module declarations with `-fcxx-modules`; without it, `module;` is a syntax error.
- GCC 16 warns with `-Wexpose-global-module-tu-local` about internal constants of the library when building the
  module. With GCC 16.2, including `<string>` and `<vector>` before `import nlohmann.json;` works, but including
  them after it fails with redefinition errors ([#5103](https://github.com/nlohmann/json/issues/5103)).

??? example "How these numbers were measured"

    The model and parsing translation units are the ones listed at the top of this page, with `import nlohmann.json;`
    in place of `#include <nlohmann/json.hpp>` (after `#include <string>` and `#include <vector>`). Same method as
    for the other tables, with `-std=c++20`.

    ```sh
    # Apple clang: build the module once, then import it
    clang++ -std=c++20 -fcxx-modules -O0 -I single_include -c -x c++-module src/modules/json.cppm \
        -fmodule-output=nlohmann.json.pcm -o json_mod.o
    clang++ -std=c++20 -fcxx-modules -O0 -fmodule-file=nlohmann.json=nlohmann.json.pcm -c model.cpp

    # GCC 16 (Homebrew on macOS): writes gcm.cache/nlohmann.json.gcm, found by the importing translation unit
    g++-16 --sysroot=$(xcrun --show-sdk-path) -std=c++20 -fmodules -O0 -I single_include -c src/modules/json.cppm \
        -o json_mod.o
    g++-16 --sysroot=$(xcrun --show-sdk-path) -std=c++20 -fmodules -O0 -c model.cpp
    ```

    Link `json_mod.o` into the program.

## Use precompiled headers

Build systems can precompile `<nlohmann/json.hpp>` together with other stable headers, for example with CMake's
[`target_precompile_headers`](https://cmake.org/cmake/help/latest/command/target_precompile_headers.html):

```cmake
target_precompile_headers(my_target PRIVATE <nlohmann/json.hpp>)
```

This removes the cost of parsing the header, but not of instantiating templates in each translation unit, so it
combines well with the options above.

<div class="nj-fig-wrap" markdown>
--8<-- "images/compile_times_pch.svg"
</div>
<p class="nj-caption" markdown>Change in compile time per translation unit at `-O0` with a precompiled
`<nlohmann/json.hpp>` (`-std=c++17`), and the one-off cost of building the precompiled header, taken from the table
below.</p>

| Compiler    | Translation unit     | Default (`-O0` / `-O2`) | With PCH (`-O0` / `-O2`) | Change      |
|-------------|----------------------|------------------------:|-------------------------:|------------:|
| Apple clang | model                |       1045 ms / 1295 ms |          594 ms / 842 ms | −43% / −35% |
| GCC 16      | model                |       1789 ms / 2101 ms |        1060 ms / 1376 ms | −41% / −35% |
| Apple clang | parsing              |       1148 ms / 2008 ms |         714 ms / 1584 ms | −38% / −21% |
| GCC 16      | parsing              |       2498 ms / 4075 ms |        1884 ms / 3452 ms | −25% / −15% |
| Apple clang | building the PCH     |                       — |          771 ms / 760 ms |           — |
| GCC 16      | building the PCH     |                       — |        2254 ms / 2218 ms |           — |

<p class="nj-table-caption" markdown>Compile time without and with a precompiled `<nlohmann/json.hpp>`, at `-O0` and `-O2`. The last two rows are the one-off cost of building the precompiled header.</p>

The saving is largest in translation units that instantiate little, and the PCH pays for itself from the second
(Apple clang) or fourth (GCC) translation unit. A precompiled header only works with the flags it was built with:
GCC silently ignores a mismatching `.gch` file (for example one built with another `-O` level) unless `-Winvalid-pch`
is given.

??? example "How these numbers were measured"

    `pch.hpp` contains only `#include <nlohmann/json.hpp>`; the translation units are the ones
    listed at the top of this page.

    ```sh
    # Apple clang
    clang++ -std=c++17 -O0 -I single_include -x c++-header pch.hpp -o pch.hpp.pch
    clang++ -std=c++17 -O0 -I single_include -include-pch pch.hpp.pch -include pch.hpp -c model.cpp

    # GCC 16 (Homebrew on macOS): pch.hpp.gch next to pch.hpp is picked up by -include pch.hpp
    g++-16 --sysroot=$(xcrun --show-sdk-path) -std=c++17 -O0 -I single_include -x c++-header pch.hpp -o pch.hpp.gch
    g++-16 --sysroot=$(xcrun --show-sdk-path) -std=c++17 -O0 -I single_include -include pch.hpp -Winvalid-pch -c model.cpp
    ```

## Options without effect on compile times

Some configuration macros change what the library declares, but do not measurably change compile times:

| Macro                                                                  | Apple clang, model (`-O0` / `-O2`) | GCC 16, model (`-O0` / `-O2`) |
|------------------------------------------------------------------------|-----------------------------------:|------------------------------:|
| default                                                                |                  1051 ms / 1300 ms |             1801 ms / 2106 ms |
| [`JSON_NO_IO`](../api/macros/json_no_io.md)                            |                  1034 ms / 1288 ms |             1756 ms / 2087 ms |
| [`JSON_USE_GLOBAL_UDLS`](../api/macros/json_use_global_udls.md)`=0`    |                  1055 ms / 1298 ms |             1783 ms / 2109 ms |

<p class="nj-table-caption" markdown>Compile time of the model translation unit with each macro defined; the first row is the default configuration for comparison.</p>

`JSON_NO_IO` removes the library's stream functions and its `#include`s of `<istream>` and `<ostream>`, but with the
default C++17 settings `<filesystem>` includes these headers anyway (and with libc++, `<vector>` already includes
`<streambuf>` via `<locale>`), so only a few hundred lines of the library's own stream code go away. It also does not
change what the translation unit instantiates. On the parsing translation unit, the change is 0% / 0% (Apple clang)
and −2% / 0% (GCC). To get a saving, combine it with
[switching off filesystem support](#switch-off-filesystem-support).

`JSON_USE_GLOBAL_UDLS` only controls *where* the literals are declared; to avoid their cost, use
`JSON_NO_AUTOMATIC_UDLS` instead.

## See also

- [`JSON_HAS_FILESYSTEM`](../api/macros/json_has_filesystem.md) - control the conversions from and to
  `std::filesystem::path`
- [`JSON_NO_AUTOMATIC_UDLS`](../api/macros/json_no_automatic_udls.md) - do not include the user-defined string
  literals automatically
- [Modules](../features/modules.md) - C++20 module support
- [Header only](index.md) - including the library
