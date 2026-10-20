# JSON_DISABLE_UNLOCKED_FILE_IO

```cpp
#define JSON_DISABLE_UNLOCKED_FILE_IO /* value */
```

When defined to `1`, parsing from a `#!cpp FILE*` reads every character with `std::fgetc`, as in version 3.12.0 and
earlier, instead of locking the file once and reading it with the unlocked stdio functions.

It does not change any result: values, exceptions, and the position of the file after parsing are the same either way.
Only the speed and the locking of the file differ (see the notes on locking below).

## Default definition

The default value is `0`: the file is locked once and read with the unlocked stdio functions where they are available.

```cpp
#define JSON_DISABLE_UNLOCKED_FILE_IO 0
```

## Notes

!!! note "Background"

    The C standard library makes every `std::fgetc` call thread-safe by locking and unlocking the `FILE` object. When
    parsing from a `FILE*`, the parser reads one character at a time, so this happens for every character of the input.

    Instead, the parser locks the file once when parsing starts and unlocks it when parsing ends - also when an
    exception is thrown - and reads the characters in between without locking:

    | C library                                                  | functions                                          |
    |------------------------------------------------------------|----------------------------------------------------|
    | glibc (Linux), Apple (macOS, iOS), Android, FreeBSD, NetBSD, OpenBSD, DragonFly BSD | `flockfile`, `getc_unlocked`, `funlockfile` (POSIX) |
    | Microsoft (MSVC, clang-cl)                                 | `_lock_file`, `_fgetc_nolock`, `_unlock_file`       |
    | others (e.g., musl, MinGW, newlib)                         | `std::fgetc`, as before                             |

    This makes parsing from a `FILE*` 3 to 4 times as fast with the Apple C library and 1.1 to 1.3 times as fast with
    glibc, whose locking is cheaper. The binary formats ([`from_cbor`](../basic_json/from_cbor.md),
    [`from_msgpack`](../basic_json/from_msgpack.md), ...) read from a `FILE*` the same way.

!!! note "Locking"

    While a value is parsed from a `FILE*`, the parsing thread holds the file's lock. The lock is recursive, so the
    parsing thread itself - for instance, a [SAX](../json_sax/index.md) handler or a
    [parser callback](../basic_json/parser_callback_t.md) - can keep using the file with stdio functions such as
    `std::ftell`. Other threads that use the same `FILE` object wait until the parser is done. Before, they could
    interleave their reads with the parser's, which made the parsed input unpredictable anyway.

    A program in which a SAX handler or parser callback waits for **another** thread that uses the **same** `FILE`
    object would deadlock. Define the macro to `1` for such programs.

!!! note "ABI compatibility"

    The value of this macro is encoded in the [namespace](../../features/namespace.md) (tag `_dufio`), resulting in
    distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program
    without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

!!! note "Other inputs"

    Reading from a `#!cpp std::istream` is not affected by this macro; see
    [`JSON_DISABLE_STREAM_BULK_SCAN`](json_disable_stream_bulk_scan.md) for that input.

## Examples

??? example "Example: parsing from a `FILE*` (default)"

    The file is locked once while it is parsed:

    ```cpp
    #include <cstdio>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        std::FILE* f = std::fopen("example.json", "rb");
        json j = json::parse(f);  // f is locked until parse() returns
        std::fclose(f);
    }
    ```

??? example "Example: locking for every character (macro defined to 1)"

    With the macro, every character is read with `std::fgetc`, with the same result:

    ```cpp
    #define JSON_DISABLE_UNLOCKED_FILE_IO 1
    #include <cstdio>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        std::FILE* f = std::fopen("example.json", "rb");
        json j = json::parse(f);  // std::fgetc for every character
        std::fclose(f);
    }
    ```

## See also

- [**parse**](../basic_json/parse.md) - deserialize from a compatible input
- [**sax_parse**](../basic_json/sax_parse.md) - generate SAX events
- [**JSON_DISABLE_STREAM_BULK_SCAN**](json_disable_stream_bulk_scan.md) - read a `std::istream` one character at a
  time
- [Parsing: input sources and performance](../../features/parsing/index.md#input-sources-and-performance)

## Version history

- Added in version 3.13.0.
