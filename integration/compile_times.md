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
<svg class="nj-fig nj-charts nj-charts--compile" viewBox="0 0 470 516" role="img" aria-labelledby="nj-charts-ct nj-charts-ct-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-ct">Change in compile time against the default configuration at -O0, Apple clang and G&#8203;CC 16</title>
<desc id="nj-charts-ct-d">Grouped horizontal bars, negative is faster. json_fwd.hpp instead of json.hpp on a header-only translation unit: Apple clang -62 %, G&#8203;CC 16 -82 %; extern template on a parsing translation unit: Apple clang -7 %, G&#8203;CC 16 -21 %; JSON_NO_AUTOMATIC_UDLS on a model translation unit: Apple clang -11 %, G&#8203;CC 16 -11 %; JSON_NO_AUTOMATIC_UDLS on a parsing translation unit: Apple clang -1 %, G&#8203;CC 16 -2 %; JSON_HAS_FILESYSTEM=0 + JSON_NO_IO on a model translation unit: Apple clang -8 %, G&#8203;CC 16 -11 %; JSON_HAS_FILESYSTEM=0 on a model translation unit: Apple clang -5 %, G&#8203;CC 16 -9 %; JSON_NO_IO on a model translation unit: Apple clang -2 %, G&#8203;CC 16 -2 %; JSON_USE_GLOBAL_UDLS=0 on a model translation unit: Apple clang 0 %, G&#8203;CC 16 -1 %.</desc>
<rect class="nj-charts-clang" x="8" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="26" y="20.5">Apple clang</text>
<rect class="nj-charts-gcc" x="126" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="144" y="20.5">G&#8203;CC 16</text>
<line class="nj-charts-grid" x1="47.4" y1="58" x2="47.4" y2="472"/>
<text class="nj-charts-tick" x="47.4" y="488">&#8722;80 %</text>
<line class="nj-charts-grid" x1="126.2" y1="58" x2="126.2" y2="472"/>
<text class="nj-charts-tick" x="126.2" y="488">&#8722;60 %</text>
<line class="nj-charts-grid" x1="205" y1="58" x2="205" y2="472"/>
<text class="nj-charts-tick" x="205" y="488">&#8722;40 %</text>
<line class="nj-charts-grid" x1="283.8" y1="58" x2="283.8" y2="472"/>
<text class="nj-charts-tick" x="283.8" y="488">&#8722;20 %</text>
<text class="nj-charts-tick" x="362.6" y="488">0 %</text>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="506">&#8592; faster</text>
<text class="nj-charts-tick nj-charts-tick--r" x="462" y="506">slower &#8594;</text>
<text class="nj-charts-rowlabel" x="8" y="62"><tspan class="nj-charts-code">json_fwd.hpp instead of json.hpp</tspan><tspan class="nj-charts-sub"> &#183; header-only TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 70 H122.32 Q118.32 70 118.32 74 V78 Q118.32 82 122.32 82 H362.6 Z"><title>json_fwd.hpp instead of json.hpp, header-only TU (Apple clang): &#8722;62 %</title></path>
<text class="nj-charts-val" x="367.6" y="80.5">&#8722;62 %</text>
<path class="nj-charts-gcc" d="M362.6 84 H43.52 Q39.52 84 39.52 88 V92 Q39.52 96 43.52 96 H362.6 Z"><title>json_fwd.hpp instead of json.hpp, header-only TU (G&#8203;CC 16): &#8722;82 %</title></path>
<text class="nj-charts-val" x="367.6" y="94.5">&#8722;82 %</text>
<text class="nj-charts-rowlabel" x="8" y="114"><tspan class="nj-charts-code">extern template</tspan><tspan class="nj-charts-sub"> &#183; parsing TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 122 H339.02 Q335.02 122 335.02 126 V130 Q335.02 134 339.02 134 H362.6 Z"><title>extern template, parsing TU (Apple clang): &#8722;7 %</title></path>
<text class="nj-charts-val" x="367.6" y="132.5">&#8722;7 %</text>
<path class="nj-charts-gcc" d="M362.6 136 H283.86 Q279.86 136 279.86 140 V144 Q279.86 148 283.86 148 H362.6 Z"><title>extern template, parsing TU (G&#8203;CC 16): &#8722;21 %</title></path>
<text class="nj-charts-val" x="367.6" y="146.5">&#8722;21 %</text>
<text class="nj-charts-rowlabel" x="8" y="166"><tspan class="nj-charts-code">JSON_NO_AUTOMATIC_UDLS</tspan><tspan class="nj-charts-sub"> &#183; model TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 174 H323.26 Q319.26 174 319.26 178 V182 Q319.26 186 323.26 186 H362.6 Z"><title>JSON_NO_AUTOMATIC_UDLS, model TU (Apple clang): &#8722;11 %</title></path>
<text class="nj-charts-val" x="367.6" y="184.5">&#8722;11 %</text>
<path class="nj-charts-gcc" d="M362.6 188 H323.26 Q319.26 188 319.26 192 V196 Q319.26 200 323.26 200 H362.6 Z"><title>JSON_NO_AUTOMATIC_UDLS, model TU (G&#8203;CC 16): &#8722;11 %</title></path>
<text class="nj-charts-val" x="367.6" y="198.5">&#8722;11 %</text>
<text class="nj-charts-rowlabel" x="8" y="218"><tspan class="nj-charts-code">JSON_NO_AUTOMATIC_UDLS</tspan><tspan class="nj-charts-sub"> &#183; parsing TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 226 H362.6 Q358.66 226 358.66 229.94 V234.06 Q358.66 238 362.6 238 H362.6 Z"><title>JSON_NO_AUTOMATIC_UDLS, parsing TU (Apple clang): &#8722;1 %</title></path>
<text class="nj-charts-val" x="367.6" y="236.5">&#8722;1 %</text>
<path class="nj-charts-gcc" d="M362.6 240 H358.72 Q354.72 240 354.72 244 V248 Q354.72 252 358.72 252 H362.6 Z"><title>JSON_NO_AUTOMATIC_UDLS, parsing TU (G&#8203;CC 16): &#8722;2 %</title></path>
<text class="nj-charts-val" x="367.6" y="250.5">&#8722;2 %</text>
<text class="nj-charts-rowlabel" x="8" y="270"><tspan class="nj-charts-code">JSON_HAS_FILESYSTEM=0 + JSON_NO_IO</tspan><tspan class="nj-charts-sub"> &#183; model TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 278 H335.08 Q331.08 278 331.08 282 V286 Q331.08 290 335.08 290 H362.6 Z"><title>JSON_HAS_FILESYSTEM=0 + JSON_NO_IO, model TU (Apple clang): &#8722;8 %</title></path>
<text class="nj-charts-val" x="367.6" y="288.5">&#8722;8 %</text>
<path class="nj-charts-gcc" d="M362.6 292 H323.26 Q319.26 292 319.26 296 V300 Q319.26 304 323.26 304 H362.6 Z"><title>JSON_HAS_FILESYSTEM=0 + JSON_NO_IO, model TU (G&#8203;CC 16): &#8722;11 %</title></path>
<text class="nj-charts-val" x="367.6" y="302.5">&#8722;11 %</text>
<text class="nj-charts-rowlabel" x="8" y="322"><tspan class="nj-charts-code">JSON_HAS_FILESYSTEM=0</tspan><tspan class="nj-charts-sub"> &#183; model TU</tspan></text>
<path class="nj-charts-clang" d="M362.6 330 H346.9 Q342.9 330 342.9 334 V338 Q342.9 342 346.9 342 H362.6 Z"><title>JSON_HAS_FILESYSTEM=0, model TU (Apple clang): &#8722;5 %</title></path>
<text class="nj-charts-val" x="367.6" y="340.5">&#8722;5 %</text>
<path class="nj-charts-gcc" d="M362.6 344 H331.14 Q327.14 344 327.14 348 V352 Q327.14 356 331.14 356 H362.6 Z"><title>JSON_HAS_FILESYSTEM=0, model TU (G&#8203;CC 16): &#8722;9 %</title></path>
<text class="nj-charts-val" x="367.6" y="354.5">&#8722;9 %</text>
<text class="nj-charts-rowlabel" x="8" y="374"><tspan class="nj-charts-code">JSON_NO_IO</tspan><tspan class="nj-charts-sub"> &#183; model TU*</tspan></text>
<path class="nj-charts-clang" d="M362.6 382 H358.72 Q354.72 382 354.72 386 V390 Q354.72 394 358.72 394 H362.6 Z"><title>JSON_NO_IO, model TU (Apple clang): &#8722;2 %</title></path>
<text class="nj-charts-val" x="367.6" y="392.5">&#8722;2 %</text>
<path class="nj-charts-gcc" d="M362.6 396 H358.72 Q354.72 396 354.72 400 V404 Q354.72 408 358.72 408 H362.6 Z"><title>JSON_NO_IO, model TU (G&#8203;CC 16): &#8722;2 %</title></path>
<text class="nj-charts-val" x="367.6" y="406.5">&#8722;2 %</text>
<text class="nj-charts-rowlabel" x="8" y="426"><tspan class="nj-charts-code">JSON_USE_GLOBAL_UDLS=0</tspan><tspan class="nj-charts-sub"> &#183; model TU*</tspan></text>
<path class="nj-charts-clang" d="M362.6 434 h0.5 v12 h-0.5 Z"><title>JSON_USE_GLOBAL_UDLS=0, model TU (Apple clang): 0 %</title></path>
<text class="nj-charts-val" x="367.6" y="444.5">0 %</text>
<path class="nj-charts-gcc" d="M362.6 448 H362.6 Q358.66 448 358.66 451.94 V456.06 Q358.66 460 362.6 460 H362.6 Z"><title>JSON_USE_GLOBAL_UDLS=0, model TU (G&#8203;CC 16): &#8722;1 %</title></path>
<text class="nj-charts-val" x="367.6" y="458.5">&#8722;1 %</text>
<line class="nj-charts-zero" x1="362.6" y1="58" x2="362.6" y2="472"/>
</svg>

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
<svg class="nj-fig nj-charts nj-charts--compile" viewBox="0 0 440 282" role="img" aria-labelledby="nj-charts-mod nj-charts-mod-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-mod">Compile time per translation unit with import nlohmann.json at -O0, and the one-off cost of the module</title>
<desc id="nj-charts-mod-d">Horizontal bars, negative is faster, medians of nine runs, -std=c++20 for both. model TU, Apple clang: -48 % (1311 ms to 680 ms); model TU, G&#8203;CC 16: -47 % (2156 ms to 1153 ms); parsing TU, Apple clang: -42 % (1387 ms to 800 ms); parsing TU, G&#8203;CC 16: -36 % (2838 ms to 1810 ms); one-off build, Apple clang: 1630 ms; one-off build, G&#8203;CC 16: 2538 ms.</desc>
<rect class="nj-charts-clang" x="8" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="26" y="20.5">Apple clang</text>
<rect class="nj-charts-gcc" x="126" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="144" y="20.5">G&#8203;CC 16</text>
<line class="nj-charts-grid" x1="68.6667" y1="58" x2="68.6667" y2="160"/>
<text class="nj-charts-tick" x="68.6667" y="176">&#8722;50 %</text>
<line class="nj-charts-grid" x1="220.333" y1="58" x2="220.333" y2="160"/>
<text class="nj-charts-tick" x="220.333" y="176">&#8722;25 %</text>
<text class="nj-charts-tick" x="372" y="176">0 %</text>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="194">&#8592; faster per TU</text>
<text class="nj-charts-rowlabel" x="8" y="62">model TU<tspan class="nj-charts-sub"> &#183; import nlohmann.json</tspan></text>
<path class="nj-charts-clang" d="M372 70 H84.8 Q80.8 70 80.8 74 V78 Q80.8 82 84.8 82 H372 Z"><title>model TU, Apple clang: 1311 ms by default, 680 ms import nlohmann.json (&#8722;48 %)</title></path>
<text class="nj-charts-val" x="377" y="80.5">&#8722;48 %</text>
<path class="nj-charts-gcc" d="M372 84 H90.8667 Q86.8667 84 86.8667 88 V92 Q86.8667 96 90.8667 96 H372 Z"><title>model TU, G&#8203;CC 16: 2156 ms by default, 1153 ms import nlohmann.json (&#8722;47 %)</title></path>
<text class="nj-charts-val" x="377" y="94.5">&#8722;47 %</text>
<text class="nj-charts-rowlabel" x="8" y="114">parsing TU<tspan class="nj-charts-sub"> &#183; import nlohmann.json</tspan></text>
<path class="nj-charts-clang" d="M372 122 H121.2 Q117.2 122 117.2 126 V130 Q117.2 134 121.2 134 H372 Z"><title>parsing TU, Apple clang: 1387 ms by default, 800 ms import nlohmann.json (&#8722;42 %)</title></path>
<text class="nj-charts-val" x="377" y="132.5">&#8722;42 %</text>
<path class="nj-charts-gcc" d="M372 136 H157.6 Q153.6 136 153.6 140 V144 Q153.6 148 157.6 148 H372 Z"><title>parsing TU, G&#8203;CC 16: 2838 ms by default, 1810 ms import nlohmann.json (&#8722;36 %)</title></path>
<text class="nj-charts-val" x="377" y="146.5">&#8722;36 %</text>
<line class="nj-charts-zero" x1="372" y1="58" x2="372" y2="160"/>
<text class="nj-charts-rowlabel" x="8" y="222">One-off cost<tspan class="nj-charts-sub"> &#183; built once, reused by every TU</tspan></text>
<rect class="nj-charts-clang" x="8" y="232.5" width="10" height="10" rx="2.5"/>
<text class="nj-charts-val" x="24" y="242">Apple clang: 1630 ms once, saves 587 to 631 ms per TU</text>
<rect class="nj-charts-gcc" x="8" y="252.5" width="10" height="10" rx="2.5"/>
<text class="nj-charts-val" x="24" y="262">G&#8203;CC 16: 2538 ms once, saves 1003 to 1028 ms per TU</text>
</svg>

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
<svg class="nj-fig nj-charts nj-charts--compile" viewBox="0 0 440 282" role="img" aria-labelledby="nj-charts-pch nj-charts-pch-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-pch">Compile time per translation unit with a precompiled json.hpp at -O0, and the one-off cost of the PCH</title>
<desc id="nj-charts-pch-d">Horizontal bars, negative is faster, medians of nine runs, -std=c++17. model TU, Apple clang: -43 % (1045 ms to 594 ms); model TU, G&#8203;CC 16: -41 % (1789 ms to 1060 ms); parsing TU, Apple clang: -38 % (1148 ms to 714 ms); parsing TU, G&#8203;CC 16: -25 % (2498 ms to 1884 ms); one-off build, Apple clang: 771 ms; one-off build, G&#8203;CC 16: 2254 ms.</desc>
<rect class="nj-charts-clang" x="8" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="26" y="20.5">Apple clang</text>
<rect class="nj-charts-gcc" x="126" y="10" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="144" y="20.5">G&#8203;CC 16</text>
<line class="nj-charts-grid" x1="68.6667" y1="58" x2="68.6667" y2="160"/>
<text class="nj-charts-tick" x="68.6667" y="176">&#8722;50 %</text>
<line class="nj-charts-grid" x1="220.333" y1="58" x2="220.333" y2="160"/>
<text class="nj-charts-tick" x="220.333" y="176">&#8722;25 %</text>
<text class="nj-charts-tick" x="372" y="176">0 %</text>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="194">&#8592; faster per TU</text>
<text class="nj-charts-rowlabel" x="8" y="62">model TU<tspan class="nj-charts-sub"> &#183; with PCH</tspan></text>
<path class="nj-charts-clang" d="M372 70 H115.133 Q111.133 70 111.133 74 V78 Q111.133 82 115.133 82 H372 Z"><title>model TU, Apple clang: 1045 ms by default, 594 ms with PCH (&#8722;43 %)</title></path>
<text class="nj-charts-val" x="377" y="80.5">&#8722;43 %</text>
<path class="nj-charts-gcc" d="M372 84 H127.267 Q123.267 84 123.267 88 V92 Q123.267 96 127.267 96 H372 Z"><title>model TU, G&#8203;CC 16: 1789 ms by default, 1060 ms with PCH (&#8722;41 %)</title></path>
<text class="nj-charts-val" x="377" y="94.5">&#8722;41 %</text>
<text class="nj-charts-rowlabel" x="8" y="114">parsing TU<tspan class="nj-charts-sub"> &#183; with PCH</tspan></text>
<path class="nj-charts-clang" d="M372 122 H145.467 Q141.467 122 141.467 126 V130 Q141.467 134 145.467 134 H372 Z"><title>parsing TU, Apple clang: 1148 ms by default, 714 ms with PCH (&#8722;38 %)</title></path>
<text class="nj-charts-val" x="377" y="132.5">&#8722;38 %</text>
<path class="nj-charts-gcc" d="M372 136 H224.333 Q220.333 136 220.333 140 V144 Q220.333 148 224.333 148 H372 Z"><title>parsing TU, G&#8203;CC 16: 2498 ms by default, 1884 ms with PCH (&#8722;25 %)</title></path>
<text class="nj-charts-val" x="377" y="146.5">&#8722;25 %</text>
<line class="nj-charts-zero" x1="372" y1="58" x2="372" y2="160"/>
<text class="nj-charts-rowlabel" x="8" y="222">One-off cost<tspan class="nj-charts-sub"> &#183; built once, reused by every TU</tspan></text>
<rect class="nj-charts-clang" x="8" y="232.5" width="10" height="10" rx="2.5"/>
<text class="nj-charts-val" x="24" y="242">Apple clang: 771 ms once, saves 434 to 451 ms per TU</text>
<rect class="nj-charts-gcc" x="8" y="252.5" width="10" height="10" rx="2.5"/>
<text class="nj-charts-val" x="24" y="262">G&#8203;CC 16: 2254 ms once, saves 614 to 729 ms per TU</text>
</svg>

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
- [Macros](../api/macros/index.md) - reference of all macros
- [Supported Macros](../features/macros.md) - overview of all configuration macros
- [Performance](../features/performance.md) - run-time performance
- [`JSON_NO_IO`](../api/macros/json_no_io.md) - remove all stream and file I/O
