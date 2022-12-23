# <small>nlohmann::</small>position_t

```cpp
struct position_t;
```

This type represents the parsers position when parsing a json string using.
This position can be retrieved when using a [sax parser](../json_sax/index.md) with the format `nlohmann::json::input_format_t::json`
and implementing [next_token_start](../json_sax/next_token_start.md) or [next_token_end](../json_sax/next_token_end.md).

## Member functions

- [**operator size_t**](operator_size_t.md) - return the value of [chars_read_total](chars_read_total.md).

## Member variables

- [**chars_read_total**](chars_read_total.md) - The total number of characters read.
- [**lines_read**](lines_read.md) - The number of lines read.
- [**chars_read_current_line**](chars_read_current_line.md) - The number of characters read in the current line.

## Version history

- Moved from namespace `nlohmann::detail` to `nlohmann` in version ???.???.???.
