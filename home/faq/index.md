# Frequently Asked Questions (FAQ)

## Known bugs

### Brace initialization yields arrays

Question

Why does

```
json j{true};
```

and

```
json j(true);
```

yield different results (`[true]` vs. `true`)?

This is a known issue, and -- even worse -- the behavior differs between GCC and Clang. The "culprit" for this is the library's constructor overloads for initializer lists to allow syntax like

```
json array = {1, 2, 3, 4};
```

for arrays and

```
json object = {{"one", 1}, {"two", 2}};
```

for objects.

Tip

To avoid any confusion and ensure portable code, **do not** use brace initialization with the types `basic_json`, `json`, or `ordered_json` unless you want to create an object or array as shown in the examples above.

To explicitly create a single-element array, use `json::array({value})`:

```
json j = json::array({true});  // [true]
```

**Opt-in copy semantics (since version 3.13.0 unreleased)**

If you define [`JSON_BRACE_INIT_COPY_SEMANTICS`](https://json.nlohmann.me/api/macros/json_brace_init_copy_semantics/index.md) to `1` before including the library, single-element brace initialization is treated as copy/move instead of creating a single-element array:

```
#define JSON_BRACE_INIT_COPY_SEMANTICS 1
#include <nlohmann/json.hpp>

json obj = {{"key", "value"}};
json j{obj};   // -> {"key":"value"}  (copy, not array)
```

Without the macro (default behavior), `json j{obj}` creates `[{"key":"value"}]`. This opt-in macro fixes issue #5074 while preserving backwards compatibility for existing code.

## Getting started

### Which file do I need?

Question

Do I have to clone the repository or build the library?

No. The library is header-only: the single file [`json.hpp`](https://github.com/nlohmann/json/releases) from the releases page is all you need, including the `_json` literals. Put it in a directory `nlohmann` on your include path. Companion headers (`json_fwd.hpp`, `json_view.hpp`, `json_literals.hpp`) are only needed if you use them. See [Integration](https://json.nlohmann.me/integration/#header-only).

### Using CMake or a package manager

Question

How do I add the library with CMake, Conan, vcpkg, Homebrew, or another tool?

See [CMake](https://json.nlohmann.me/integration/cmake/index.md) for `find_package`, `add_subdirectory`, and `FetchContent`, and [Package managers](https://json.nlohmann.me/integration/package_managers/index.md) for the list of supported package managers.

### The IDE cannot open the header

Question

The compiler finds `nlohmann/json.hpp`, but my IDE reports "cannot open source file". Why?

The compiler's include path is set correctly, but the IDE's is not. Add the same directory to the include paths of the IDE (or of its language server); the build itself is not affected.

### Compile times

Question

Including the library slows down my build. What can I do?

Include [`json_fwd.hpp`](https://json.nlohmann.me/integration/compile_times/#include-json_fwdhpp-in-headers) in headers and `json.hpp` only in the source files that need it, instantiate `basic_json` once, and consider precompiled headers or [C++20 modules](https://json.nlohmann.me/features/modules/index.md). See [Compile times](https://json.nlohmann.me/integration/compile_times/index.md).

## Parsing

### Parsing a file fails with "unexpected end of input"

Question

`json::parse(file)` throws `parse_error.101` at line 1, column 1 for a file that is valid JSON. Why?

The parser did not see any character: the file was most likely not opened. A relative path is resolved against the working directory of the running program, which is often the build directory of your IDE, not the source directory. Check `is_open()` and try an absolute path. Other causes are an empty file and a stream that was already read. See [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101).

### Input that arrives in chunks

Question

My data comes from a socket in pieces. How do I parse it?

The parser cannot be resumed. Frame the messages (one value per line, a length prefix) and parse each complete frame, or buffer the chunks until the value is complete; a `parse_error` at the end of the buffer means the input ended prematurely. See [Large, streamed, and partial input](https://json.nlohmann.me/features/parsing/large_and_partial_input/#input-arriving-in-chunks).

### Several values in one stream

Question

How do I read concatenated JSON values or one value per line?

Read newline-delimited input line by line ([JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md)). For concatenated values, use `operator>>` and check for the end of the stream before each read, as shown in [Several values in one stream](https://json.nlohmann.me/features/parsing/large_and_partial_input/#several-values-in-one-stream).

### Files that are too large for memory

Question

How do I process a huge JSON file?

Handle and discard the records of a large array with a [parser callback](https://json.nlohmann.me/features/parsing/parser_callbacks/index.md), stop early with the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md), or read parts of the text through a [`json_document`](https://json.nlohmann.me/features/json_view/index.md) (added in version 3.13.0 unreleased). See [Input too large for memory](https://json.nlohmann.me/features/parsing/large_and_partial_input/#input-too-large-for-memory).

### Position of a parse error

Question

How do I get the line and column of a parse error?

The message contains them. The exception stores the byte index in `byte`, from which you can compute both; see [Where did the error occur?](https://json.nlohmann.me/features/parsing/parse_exceptions/#where-did-the-error-occur). To locate a value that causes a *later* error, such as a `type_error`, use [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/features/parsing/parse_exceptions/#where-is-the-value-that-caused-a-later-error).

### Comments and trailing commas

Question

Can the parser read JSON with comments or trailing commas?

Yes, when asked to: see [Comments](https://json.nlohmann.me/features/comments/index.md) and [Trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md). Both are rejected by default.

## Accessing and creating values

### Reading a value into a variable

Question

How do I get a C++ value out of a `json` value?

Use [`get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md), for example `int age = j["age"].get<int>();`, or an implicit conversion. `auto x = j["age"];` is **not** a conversion: it copies the `json` value. See [Converting values](https://json.nlohmann.me/features/conversions/index.md).

### Strings are printed with quotes

Question

`std::cout << j["name"]` prints `"Mary"` with quotes. How do I get the string?

The value is a `json`, and printing it produces JSON text. Convert it first: `j["name"].get<std::string>()`. See [Getting a string without quotes](https://json.nlohmann.me/features/conversions/#getting-values-out).

### Testing whether a key exists

Question

How do I check if a key exists, without changing the object?

Use `contains` or `find`. Do not test with the non-const `operator[]`: like `std::map::operator[]`, it inserts a `null` value for a missing key. See [Does this key exist?](https://json.nlohmann.me/features/element_access/#does-this-key-exist).

### Reading a value with a fallback

Question

How do I read a value that may be missing?

Use [`value`](https://json.nlohmann.me/features/element_access/default_value/index.md), which returns a default for a missing key. It still throws if the key exists with a different type; see [Working without exceptions](https://json.nlohmann.me/features/no_exceptions/index.md).

### Iterating and nested values

Question

How do I loop over an array or object, or reach a nested value?

See [Iterators](https://json.nlohmann.me/features/iterators/index.md) and [`items()`](https://json.nlohmann.me/api/basic_json/items/index.md) for loops, and [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) to address or test a nested value by path.

### Unexpected arrays when creating values

Question

Why does `json j{x}` or `{{"a", 1}, {"b"}}` produce an array instead of what I expected?

Braces create arrays and objects based on their content, and single-element braces create a one-element array. See [Brace initialization yields arrays](#brace-initialization-yields-arrays) and the table in [Creating values](https://json.nlohmann.me/features/creating_values/#what-does-this-produce).

### Keeping the order of object keys

Question

The keys of my object come out sorted. How do I keep the insertion order?

Use `ordered_json`, and call `ordered_json::parse` when reading. See [Object order](https://json.nlohmann.me/features/object_order/index.md).

## Converting your own types

### Structs, enums, and optional fields

Question

How do I convert my own types to and from JSON?

Write `to_json`/`from_json` functions or use the `NLOHMANN_DEFINE_TYPE_*` macros; see [Arbitrary type conversions](https://json.nlohmann.me/features/arbitrary_types/index.md). Enums can be mapped to strings ([Enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md)), and an empty `std::optional` can be omitted ([Omitting a field](https://json.nlohmann.me/features/conversions/#omitting-a-field-when-serializing-stdoptional)).

### Smart pointers, variants, chrono, and class hierarchies

Question

Why can't I convert `std::shared_ptr`, `std::variant`, `std::chrono` types, or a pointer to a base class?

There is more than one sensible JSON representation for them, so the library leaves the choice to you. [Recipes for common types](https://json.nlohmann.me/features/type_recipes/index.md) shows one for each.

### My `to_json` is not found

Question

I wrote `to_json`/`from_json`, but the compiler does not find them. Why?

Typical causes are a type alias of a standard type, a function in the wrong namespace, or a declaration that comes too late. See [Why isn't my `to_json` found?](https://json.nlohmann.me/features/arbitrary_types/#why-isnt-my-to_json-or-from_json-found).

## Limitations

### Relaxed parsing

Question

Can you add an option to ignore trailing commas?

Yes, trailing commas in arrays and objects can be allowed by setting parameter `ignore_trailing_commas` of [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) to `true`; see [trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md). They are rejected by default, and the library never adds them when serializing.

### Parse errors reading non-ASCII characters

Questions

- Why is the parser complaining about a Chinese character?
- Does the library support Unicode?
- I get an exception `[json.exception.parse_error.101] parse error at line 1, column 53: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '"Testé$')"`

The library supports **Unicode input** as follows:

- **UTF-8** encoded input is supported, which is the default encoding for JSON, according to [RFC 8259](https://tools.ietf.org/html/rfc8259.html#section-8.1).
- `std::u16string` and `std::u32string` can be parsed, assuming UTF-16 and UTF-32 encoding, respectively; `std::wstring` works as well and is interpreted as UTF-16 or UTF-32, depending on the width of the platform's `wchar_t`. These encodings cannot be read from a `FILE*` or a `std::istream`, which carry bytes only.
- Ill-formed UTF-16 or UTF-32 input is rejected: a lone surrogate, a high surrogate that is not followed by its low surrogate, and a code point above `U+10FFFF` all yield a parse error. The same holds for iterators over 2- or 4-byte characters.
- Other encodings such as Latin-1 or ISO 8859-1 are **not** supported and will yield parse or serialization errors.
- The library will not replace [Unicode noncharacters](http://www.unicode.org/faq/private_use.html#nonchar1).
- Invalid surrogates (e.g., incomplete pairs such as `\uDEAD`) will yield parse errors.
- The strings stored in the library are UTF-8 encoded. When using the default string type (`std::string`), note that its length/size functions return the number of stored bytes rather than the number of characters or glyphs.
- When you store strings with different encodings in the library, calling [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) may throw an exception unless `json::error_handler_t::replace`, `json::error_handler_t::ignore`, or `json::error_handler_t::keep` are used as error handlers.

In most cases, the parser is right to complain, because the input is not UTF-8 encoded. This is especially true for Microsoft Windows, where Latin-1 or ISO 8859-1 is often the standard encoding.

### NUL bytes in the input

Questions

- Why does [`json::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) silently ignore part of my input?
- Why does a `std::string`/buffer with extra data after the JSON text parse without error, while a similar-looking string with extra text does not?

A `'\0'` (NUL) byte anywhere in the input is treated the same as the real end of the input, rather than as an ordinary (and, outside of a string, invalid) byte. Everything from that byte onward is silently ignored, without a parse error — including further, otherwise well-formed JSON:

```
json::parse(std::string("123") + '\0');          // == 123, no error
json::parse(std::string("123") + '\0' + "true"); // == 123, the "true" is silently ignored too
```

This is different from any other unexpected trailing byte, which *does* raise [`parse_error.101`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error101):

```
json::parse("123x"); // throws parse_error.101: unexpected additional data
```

This falls out of the same convention used when no explicit input length is given at all: `json::parse(const char*)` already stops at the first NUL byte via `strlen()`, since a bare pointer has no length of its own. The library applies that same NUL-terminated-C-string convention uniformly, rather than only when a length is genuinely unavailable — so a `std::string`, iterator range, or container whose content happens to include a NUL byte is affected the same way a raw `const char*` would be.

If your input may contain a trailing or embedded NUL that is **not** meant to signal the end of the JSON text — for instance, a fixed-size, zero-padded buffer — trim it yourself before calling `parse()`, since the library will otherwise silently stop there instead of raising an error:

```
s.resize(s.find('\0')); // drop everything from the first NUL onward, if any
json::parse(s);
```

**Opt-in strict handling (since version 3.13.0 unreleased)**

Manually trimming every input is easy to forget. If you define [`JSON_STRICT_NUL_HANDLING`](https://json.nlohmann.me/api/macros/json_strict_nul_handling/index.md) to `1` before including the library, a `'\0'` byte is instead rejected like any other unexpected byte and raises `parse_error.101`, instead of being treated as end of input:

```
#define JSON_STRICT_NUL_HANDLING 1
#include <nlohmann/json.hpp>

json::parse(std::string("123") + '\0'); // throws parse_error.101 instead of silently returning 123
```

This macro defaults to `0` (disabled, preserving the behavior described above) to avoid breaking existing code that may depend on it, even unknowingly; it is planned to become the default in version 4.0.0. See [its documentation](https://json.nlohmann.me/api/macros/json_strict_nul_handling/index.md) for details, including how it also affects `char` arrays such as string literals.

Note that this is unrelated to an *unescaped* NUL byte occurring **inside** a quoted JSON string, which is a different, already-invalid case and is correctly rejected either way:

```
json::parse(std::string("\"") + '\0' + "\""); // throws parse_error.101: control character U+0000 (NUL) must be escaped to \u0000
```

### Wide string handling

Question

Why are wide strings (e.g., `std::wstring`) dumped as arrays of numbers?

As described [above](#parse-errors-reading-non-ascii-characters), the library stores its strings as UTF-8. To store a wide string as a string, convert it to a UTF-8 encoded `std::string` first, as in the example below.

Example

```
#include <codecvt> // codecvt_utf8
#include <locale>  // wstring_convert

// encoding function
std::string to_utf8(std::wstring& wide_string)
{
    static std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;
    return utf8_conv.to_bytes(wide_string);
}

json j;
std::wstring ws = L"車B1234 こんにちは";

j["original"] = ws;
j["encoded"] = to_utf8(ws);

std::cout << j << std::endl;
```

The result is:

```
{
  "encoded": "車B1234 こんにちは",
  "original": [36554, 66, 49, 50, 51, 52, 32, 12371, 12435, 12395, 12385, 12399]
}
```

## Usage

### Thread safety

Question

Is `basic_json` thread-safe?

No. `basic_json` provides no built-in synchronization, the same as `std::map` or `std::vector`. Concurrent reads of the same value from multiple threads are safe, as are concurrent (non-overlapping) accesses to independent `json` objects. However, any concurrent write to a `json` object -- or a concurrent read while another thread writes to the same object -- is a data race and requires external synchronization (e.g., a `std::mutex`) by the caller.

### Schema validation

Question

Does this library support JSON Schema validation?

Not directly, but the companion project [json-schema-validator](https://github.com/pboettch/json-schema-validator) builds JSON Schema (draft 7; draft 4 in its older, now-superseded 1.x releases) validation on top of this library and is a common recommendation for this use case.

### Memory use

Question

Does the library leak memory? My process stays large after I free a `json` value.

Destroying a value frees everything it owns. Freed memory is returned to the allocator, which does not necessarily give it back to the operating system, so a high resident size alone is not a leak. Copies are deep, and `clear()` keeps the capacity of an array. See [Memory](https://json.nlohmann.me/features/performance/#memory), and use Valgrind or the sanitizers to tell a leak from retained memory.

### Reproducible builds

Question

The header path ends up in my binary. How do I get path-independent builds?

The runtime assertions embed `__FILE__`. Define `NDEBUG` (the default for release builds) or map the path prefix; see [Notes for builds and distribution](https://json.nlohmann.me/integration/#notes-for-builds-and-distribution).

### Slow debug builds

Question

Parsing a large file is very slow in my debug build. Can I compile the library with optimizations?

The library is header-only, so there is no separate source file. Keep the code that uses `json` in its own source file and compile that file with optimizations; see [Notes for builds and distribution](https://json.nlohmann.me/integration/#notes-for-builds-and-distribution).

## Exceptions

### Parsing without exceptions

Question

Is it possible to indicate a parse error without throwing an exception?

Yes, see [Parsing and exceptions](https://json.nlohmann.me/features/parsing/parse_exceptions/index.md) and [Working without exceptions](https://json.nlohmann.me/features/no_exceptions/index.md).

### Key name in exceptions

Question

Can I get the key of the object item that caused an exception?

Yes, you can. Please define the symbol [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) to get [extended diagnostics messages](https://json.nlohmann.me/home/exceptions/#extended-diagnostic-messages).

## Serialization issues

### Number precision

Question

- It seems that precision is lost when serializing a double.
- Can I change the precision for floating-point serialization?

The library serializes floating-point numbers with the shortest representation that parses back to the same value, using at most `std::numeric_limits<number_float_t>::max_digits10` (17 for IEEE `double`s) significant digits. This guarantees that value -> string -> value round-trips. The reverse direction, string -> value -> string, is only guaranteed for numbers with at most `std::numeric_limits<number_float_t>::digits10` (15 for IEEE `double`s) significant digits; a number with more digits may not be representable exactly and is then serialized as the closest `double`.

[cppreference.com](https://en.cppreference.com/w/cpp/types/numeric_limits/max_digits10)

The value of `std::numeric_limits<T>::max_digits10` is the number of base-10 digits that are necessary to uniquely represent all distinct values of the type T, such as necessary for serialization/deserialization to text.

Tip

The website <https://float.exposed> gives a good insight into the internal storage of floating-point numbers.

See [this section](https://json.nlohmann.me/features/types/number_handling/#number-serialization) on the library's number handling for more information.

### Serializing untrusted or invalid UTF-8

Questions

- Why does `dump()` throw when I serialize data that came from the network?
- Is CVE-2024-34363 a vulnerability in this library?

Crashes reported against this library that stem from an uncaught [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) while serializing unvalidated input (e.g., CVE-2024-34363) are a usage issue, not a library vulnerability: [`dump()`](https://json.nlohmann.me/api/basic_json/dump/index.md) throws in its default `strict` mode because [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259#section-8.1) requires JSON text to be valid UTF-8.

The recommended pattern is to pass a non-strict [`error_handler`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md) or to handle the exception:

```
// replace invalid sequences with U+FFFD instead of throwing
const auto s = j.dump(-1, ' ', false, json::error_handler_t::replace);
```

### Using JSON values with `std::format` or `fmt`

Question

- Can I use `std::format("{}", j)` on a JSON value?
- Can I use `fmt::format("{}", j)` or `fmt::print("{}", j)` (the [{fmt}](https://github.com/fmtlib/fmt) library) on a JSON value?

`std::format` works out of the box since version 3.13.0 unreleased, as long as the standard library provides `<format>` (see [`JSON_HAS_STD_FORMAT`](https://json.nlohmann.me/api/macros/json_has_std_format/index.md)); see [`std::formatter<basic_json>`](https://json.nlohmann.me/api/basic_json/std_formatter/index.md) for details, including the `"{:#}"` pretty-print spec, indent widths (`"{:2}"`), and custom indent characters (`"{:.>#}"`).

For `fmt`, the library ships [`format_as`](https://json.nlohmann.me/api/basic_json/format_as/index.md), a small customization point `fmt` looks for via argument-dependent lookup. It only has an effect on fmt 10.0.0 through 11.0.2 — from fmt 11.1.0 onwards, `fmt` no longer picks up a `format_as` overload that returns a `std::string`. On such versions (or any version, if you also want the same `"{:#}"`/width/fill-and-align spec support that `std::formatter<basic_json>` has), define your own `fmt::formatter` specialization; see [`format_as`](https://json.nlohmann.me/api/basic_json/format_as/index.md) for a recipe that mirrors it.

If you get ambiguous-overload errors when passing a JSON value to `fmt::format`/`fmt::print` without any `fmt::formatter<json>` specialization in scope, that's `fmt` picking up `basic_json`'s implicit `operator ValueType()` conversion operator (see [#964](https://github.com/nlohmann/json/issues/964) and [#958](https://github.com/nlohmann/json/issues/958)); disabling it via [`JSON_USE_IMPLICIT_CONVERSIONS 0`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) avoids the ambiguity.

## Compilation issues

### Android SDK

Question

Why does the code not compile with Android SDK?

Since [NDK r18](https://github.com/android/ndk/wiki/Changelog-r18) (2018), GCC and the `gnustl`/`stlport` C++ libraries have been removed from the Android NDK; Clang and `libc++` are now the only compiler and C++ library, and they support C++11 and later out of the box. With a current NDK, no special configuration is needed to use this library.

Only very old NDKs (before r18), which defaulted to GCC and `gnustl`, lacked C++11 library features such as `std::to_string`. If you run into this, update to a current NDK.

### Incomplete `detector` type with GCC < 11

Question

Why does GCC 10 or older fail with `invalid use of incomplete type 'struct nlohmann::detail::detector<..., to_json_function, ...>'` for a type that holds an `optional` member?

This happens with GCC 10 and older in C++11/C++14 mode when all of these hold:

- a class `Holder` has an `optional<Dummy>` member (e.g., `boost::optional`),
- `Dummy` has a constructor taking a `json` value, and
- `to_json` for `Holder` is a free function in the namespace of `Dummy`.

```
class Dummy {
  public:
    explicit Dummy(const nlohmann::json& j);
};

class Holder {
    boost::optional<Dummy> d;
};

void to_json(nlohmann::json& j, const Holder& h);  // triggers the error
```

To decide whether `Dummy` is copyable, the compiler checks whether a `Dummy` can be converted to `json`. That check looks up `to_json` via argument-dependent lookup, finds the unrelated `to_json` for `Holder`, and eventually asks again whether `Dummy` is copyable. GCC before version 11 turns this cycle into a hard error; GCC 11 and later, Clang, and C++17 mode compile the code. The same error shows up without this library whenever a constrained converting constructor is involved, so the library can't avoid it.

To work around this, define `to_json` (and `from_json`) as a *hidden friend* inside the class. That way, argument-dependent lookup only finds it for `Holder`:

```
class Holder {
    boost::optional<Dummy> d;

    friend void to_json(nlohmann::json& j, const Holder& h) { /* ... */ }
};
```

The [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) macros define hidden friends as well. See [#3669](https://github.com/nlohmann/json/issues/3669) for details.

### Missing STL function

Questions

- Why do I get a compilation error `'to_string' is not a member of 'std'` (or similarly, for `strtod` or `strtof`)?
- Why does the code not compile with MinGW or Android SDK?

This is not an issue with the code, but rather with the compiler itself. On Android, use a current NDK (see above). For MinGW, please refer to [this site](http://tehsausage.com/mingw-to-string) and [this discussion](https://github.com/nlohmann/json/issues/136) for information on how to fix this bug.
