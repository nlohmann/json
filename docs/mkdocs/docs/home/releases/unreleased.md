# Unreleased

These changes are part of the `develop` branch, but not of a release yet.

- Converting an rvalue container to JSON (`json j = std::move(vec);`, `json j = std::map<std::string, std::string>{...};`)
  now **moves** the elements instead of copying them (e.g., `std::vector<std::string>` with 100,000 strings: 4.7 ms to
  2.3 ms). Two consequences: the source container is left in a valid but unspecified (moved-from) state, and if an
  exception is thrown during the conversion, the source may be partially moved-from, so the strong exception guarantee
  no longer holds for the source of an rvalue conversion (the JSON value itself is unaffected). Lvalues and `const`
  objects are still copied. See [`basic_json`](../../api/basic_json/basic_json.md).
- In C++20 (library support for `char8_t`, `__cpp_lib_char8_t`), a `#!cpp std::u8string` is a JSON **string**:
  `json j = std::u8string(u8"abc");` stores `"abc"`, and `#!cpp j.get<std::u8string>()` reads it back. Version 3.12.0
  stored a `#!cpp std::u8string` as an array of code units (`[97,98,99]`); on the 3.13.0 development branch it was
  already stored as a string if `std::filesystem` is available, but could not be read back. Now the result no longer
  depends on whether `std::filesystem::path` is supported, and `#!cpp get<std::u8string>()` accepts both a JSON string
  and the array of numbers written by 3.12.0. **Consequence:** JSON documents produced from a `#!cpp std::u8string` by
  3.12.0 (arrays) are still read, but code that checks `is_array()` on such a value, or that reads it as
  `#!cpp std::vector<char8_t>` / `#!cpp std::vector<std::uint8_t>`, now sees a string; to keep the array form, convert
  explicitly, e.g., `#!cpp json(std::vector<char8_t>(s.begin(), s.end()))`. `#!cpp std::u8string_view` and
  `#!cpp char8_t` arrays are unchanged (arrays of code units). See [`basic_json`](../../api/basic_json/basic_json.md).

## API changes

<!-- api-changes -->
