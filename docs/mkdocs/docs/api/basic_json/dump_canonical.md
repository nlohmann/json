# <small>nlohmann::basic_json::</small>dump_canonical

```cpp
// (1)
string_t dump_canonical() const;

// (2)
static void dump_canonical(const basic_json& j, detail::output_adapter<char> o);
```

Serialization function for JSON values according to the
**JSON Canonicalization Scheme (JCS, [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785))**.

Canonical JSON serialization produces a deterministic, byte-for-byte identical
representation of a JSON document across implementations. This is crucial for
digital signatures, hashing, blockchain protocols, and cryptographic checksums.

1. Member function: Returns a string containing the canonical serialization
   of the JSON value.
2. Static function: Writes the canonical serialization of JSON value `j` directly
   into the given output adapter `o` (e.g. `std::string`, `std::ostream`, or
   custom output adapter).

## Parameters

`j` (in)
:   The JSON value to serialize (for overload 2).

`o` (out)
:   The output adapter to write into (for overload 2).

## Return value

(1) `string_t` containing the canonical serialization of the JSON value.
(2) none.

## Exceptions

- Throws [`out_of_range.406`](../../home/exceptions.md#jsonexceptionout_of_range406)
  if a floating-point number is not finite (`NaN` or `Infinity`).
- Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316)
  if a string is not valid UTF-8.
- Throws [`type_error.317`](../../home/exceptions.md#jsonexceptiontype_error317)
  if called on unsupported types (such as binary or discarded).

## Complexity

Linear in the size of the JSON document ($O(N \log K)$ where $K$ is the number of
keys in each object due to key sorting).

## Notes

The canonical serialization strictly adheres to [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785):

- **Whitespace**: No whitespace is added around separators (`:`, `,`).
- **Object Keys**: Object keys are sorted lexicographically by their UTF-16 code units
  (RFC 8785 Section 3.2.3).
- **Strings**: Only characters `\"`, `\\`, and control characters `\u0000` through `\u001F`
  (`\b`, `\f`, `\n`, `\r`, `\t`, or `\u00XX`) are escaped. Characters U+0020 and above
  (including Unicode characters and `/`) are emitted as raw UTF-8 without escaping.
- **Numbers**: Numbers are formatted according to ECMAScript 2019 `Number::toString`
  (RFC 8785 Section 3.2.2.3):
    - Negative zero (`-0.0`) is formatted as `"0"`.
    - No trailing `.0` is emitted for integer values.
    - Exponents have no leading zeros (e.g. `1e+21` or `1e-7`).
    - Values in range $10^{-6} \le |x| < 10^{21}$ are formatted in plain decimal notation.
- **Unsupported Types**: Non-finite numbers (`NaN`, `Infinity`, `-Infinity`), binary
  values, and discarded values cannot be serialized in canonical JSON.

## Examples

??? example

    The following example shows the usage of `dump_canonical()`.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        // Object keys are automatically sorted deterministically
        json j = {{"banana", 2}, {"apple", 1}, {"cherry", 3}};
        std::cout << j.dump_canonical() << '\n';
        // Output: {"apple":1,"banana":2,"cherry":3}

        // Float without trailing .0
        json j_num = {{"value", 42.0}};
        std::cout << j_num.dump_canonical() << '\n';
        // Output: {"value":42}
    }
    ```

## See also

- [dump](dump.md) - standard configurable JSON serialization
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) - JSON Canonicalization Scheme (JCS) specification

## Version history

- Added in version 3.13.0.
