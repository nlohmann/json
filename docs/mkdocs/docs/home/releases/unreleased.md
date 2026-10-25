# Unreleased

These changes are part of the `develop` branch, but not of a release yet.

- Converting an rvalue container to JSON (`json j = std::move(vec);`, `json j = std::map<std::string, std::string>{...};`)
  now **moves** the elements instead of copying them (e.g., `std::vector<std::string>` with 100,000 strings: 4.7 ms to
  2.3 ms). Two consequences: the source container is left in a valid but unspecified (moved-from) state, and if an
  exception is thrown during the conversion, the source may be partially moved-from, so the strong exception guarantee
  no longer holds for the source of an rvalue conversion (the JSON value itself is unaffected). Lvalues and `const`
  objects are still copied. See [`basic_json`](../../api/basic_json/basic_json.md).

## API changes

<!-- api-changes -->
