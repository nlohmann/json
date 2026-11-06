# Reading and writing files

The library has no functions that take a file name. It reads from and writes to streams, so files are handled with
`#!cpp std::ifstream` and `#!cpp std::ofstream` (or a `#!cpp FILE*` when reading). This page collects the recipes for
the common cases and the mistakes that show up again and again.

## Reading a JSON file

Pass the stream to [`parse`](../api/basic_json/parse.md) directly, and check that the file was opened:

```cpp
#include <fstream>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

json read_json_file(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
    {
        throw std::runtime_error("cannot open " + path);
    }
    return json::parse(f);
}
```

- **Check that the file is open.** A stream that failed to open looks like an empty input, so `parse` reports
  [`parse_error.101`](../home/exceptions.md#jsonexceptionparse_error101) ("unexpected end of input") at line 1,
  column 1 instead of saying that the file is missing. A relative path is resolved against the working directory of the
  running program, which is often not the directory of the source file (see the
  [FAQ](../home/faq.md#parsing-a-file-fails-with-unexpected-end-of-input)).
- **Don't read the file into a string first.** Parsing from a `#!cpp std::ifstream` is only about 10 to 20 % slower
  than reading the whole file into a string with one `read()` and parsing that, and it needs no memory for the copy (see
  [input sources and performance](parsing/index.md#input-sources-and-performance)). The common way to read a file with
  `#!cpp std::istreambuf_iterator<char>` is so slow that it takes about twice as long as parsing from the stream. Read
  the file into a string only if you need the text itself, for example for an error message. This advice is for
  `#!cpp json::parse`. [`json_document`](json_view/index.md) reads a stream into a buffer that it owns anyway, so there is no
  copy to save: reading the file into a `#!cpp std::string` yourself and passing that as an lvalue, which the document
  borrows, was about 6 to 12 % faster than parsing from the stream, with the same single buffer.
- `parse` requires the file to hold exactly one JSON value. Files with one value per line are read with
  [JSON Lines](parsing/json_lines.md); files too large for memory are covered in
  [Large, streamed, and partial input](parsing/large_and_partial_input.md).

## Writing a JSON file

[`dump`](../api/basic_json/dump.md) the value into a string first, then write the string:

```cpp
void write_json_file(const std::string& path, const json& j)
{
    const std::string text = j.dump(4) + '\n';  // may throw: nothing is written yet

    std::ofstream f(path, std::ios::binary);
    if (!f.is_open())
    {
        throw std::runtime_error("cannot open " + path);
    }
    f << text;
    f.close();
    if (f.fail())
    {
        throw std::runtime_error("cannot write " + path);
    }
}
```

- **Serialize before opening the file.** Opening a `#!cpp std::ofstream` truncates the file. `dump` and
  [`operator<<`](../api/operator_ltlt.md) throw [`type_error.316`](../home/exceptions.md#jsonexceptiontype_error316)
  when a string is not valid UTF-8 (see [handling invalid UTF-8](serialization.md#handling-invalid-utf-8)), and
  `#!cpp f << std::setw(4) << j` may already have written part of the value when it throws. Serializing into a string
  first leaves the old file untouched in that case.
- **Check the stream after closing it.** A full disk or a missing permission sets the stream's error state; it does not
  throw unless you enabled exceptions on the stream with `exceptions()`.
- `std::ios::binary` writes the text as it is. Without it, Windows writes `\r\n` for every newline of a pretty-printed
  value.

## Replacing a file without corrupting it

The library never writes a file itself, so this section is not about the library. It is general C++ advice for a
problem users of the library keep running into.

A program that crashes or is killed while it writes leaves a truncated file behind. To make sure readers see either the
old or the new contents, write to a temporary file in the same directory and rename it over the original
(C++17, `#!cpp <filesystem>`):

```cpp
#include <filesystem>

void replace_json_file(const std::filesystem::path& path, const json& j)
{
    std::filesystem::path tmp = path;
    tmp += ".tmp";  // use a unique name if several processes may write the file

    write_json_file(tmp.string(), j);
    std::filesystem::rename(tmp, path);  // replaces path
}
```

The temporary file must be in the same directory (more precisely, on the same file system) as the target: a rename
across file systems does not fall back to a copy, it fails and throws `#!cpp std::filesystem::filesystem_error`. On
POSIX systems, the rename atomically replaces the file. Standard C++ has no way to flush a file to the disk (`fsync`),
so this protects against a crashed program, but not necessarily against a power loss.

## Binary formats

The [binary formats](binary_formats/index.md) work the same way, with the streams opened in binary mode:

```cpp
// read
std::ifstream in("data.cbor", std::ios::binary);
json j = json::from_cbor(in);

// write
const std::vector<std::uint8_t> bytes = json::to_cbor(j);
std::ofstream out("data.cbor", std::ios::binary);
out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
```

Without `std::ios::binary`, Windows turns the bytes `0x0D 0x0A` into `0x0A` and may stop at a byte `0x1A` while reading,
and turns `0x0A` into `0x0D 0x0A` while writing, which corrupts the data.

## See also

- [Parsing](parsing/index.md) - the inputs `parse` accepts
- [Serialization](serialization.md) - the options of `dump`
- [`parse`](../api/basic_json/parse.md), [`dump`](../api/basic_json/dump.md)
- [`operator>>`](../api/operator_gtgt.md), [`operator<<`](../api/operator_ltlt.md)
