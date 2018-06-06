# Styled Pretty Printing

The library provides a pretty printer supporting flexible customization of the layout. There are two concepts used by the library:

* A _style_ defines how printed objects are formatted.
* A _stylizer_ determines what style to use, based on the current context being printed.

At some level, this functionality is analogous to a mix between a source code formatter (like clang-format or astyle) and CSS.

## Styles -- Uniform Formatting

If you want the entire document to be formatted the same, all you need to do is provide a single `nlohmann::print_style` instance to the `nlohmann::styled_dump` function. There are three “presets” you can use, `print_style::preset_compact()`, `print_style::preset_one_line()`, and `print_style::multiline()`. When creating a new `print_style` object, the default matches `preset_compact`.

Here is how to use the presets along with `styled_dump`:

    using nlohmann::json;
    using nlohmann::print_style;
    using nlohmann::styled_dump;
    
    json j = {"foo", 1, 2, 3, false, {{"one", 1}}}
        
    styled_dump(std::cout, j, print_style::preset_compact());
    // Result: ["foo",1,2,3,false,{"one":1}]
    
    styled_dump(std::cout, j, print_style::preset_one_line());
    // Result: ["foo", 1, 2, 3, false, {"one": 1}]

    styled_dump(std::cout, j, print_style::multiline());
    // Result (no comment symbols, of course):
    //[
    //    "foo",
    //    1,
    //    2,
    //    3,
    //    false,
    //    {
    //        "one": 1
    //    }
    //]

Styles can, of course, be customized. The following fields are provided:

### `print_style::indent_step` and `print_style::indent_char`

These fields provide the step width and character to use for indentation. The step is in number of characters; e.g., don't set `indent_step` 8 and set `indent_char` to `'\t'`.

This parameter is ignored if no indentation occurs.

:warning: Currently, it is not possible to change indentation depending on context.

:question: Is that something we want to allow?

### `strings_maximum_length`

This will truncate strings internally that are too long. The value is the maximum length of the string, not counting the quotation marks (which are always printed). It cannot be 0.

If the string is short enough, it will be displayed in full. Otherwise, space permitting, it will print the longest prefix possible, followed by `...`, followed by the last character of the string. If it is too long even for that, it will leave off the last character, then the prefix entirely, and then start shortening the ellipsis.

Example:

    print_style style;
    style.strings_maximum_length = 10;

    json j = "The quick brown fox jumps over the lazy brown dog";
    styled_dump(std::cout, j, style);
    // Prints: "The qu...g"  (including quotes)

### :exclamation: TODO: `list_maximum_length`

This is analogous to `strings_maximum_length`, but for lists. When this option takes effect, the result will not be valid JSON.

### `depth_limit`

This option specifies a maximum recursion depth beyond which objects should be elided, replaced with ellipses. A `0` value will print values at the top-level, but compound objects (arrays and objects) will print with ellipses internally.

Example:

    print_style style = print_style::preset_one_line();
    style.depth_limit = 1;

    json j = {1, {1}};
    styled_dump(std::cout, j, style);

### `space_after_colon`, `space_after_comma`

These Boolean values specify whether a space should be printed after their respective separators. The setting of these options makes the difference between `preset_compact` and `preset_one_line`.

:question: [Issue 229](https://github.com/nlohmann/json/issues/229) has a number of comments, and implementation work, with a similar structure to mine, but with strings that had what to print here. So instead of `space_after_colon`, there was a string the user would set to either `":"` or `": "` as appropriate. I could change to that approach, but I think I prefer this one. I am dogmatically enforcing that the setting not result in syntactically-incorrect JSON. Related to `multiline`, next, it means I don't have to look through that string for a `\n` to see if the next line needs to indent. The main thing I can think of here is maybe the user would sometimes want to print *multiple* spaces, or a tab -- but (i) that seems easy enough to add (especially multiple spaces), and (ii) I suspect the main reason to do this is alignment, and that would need to know more about context.

:question: Another alternative choice I could have made here (I think better-founded) is to combine these into one `space_after_separator`. This would sort of bring this in alignment with `multiline` -- e.g., there is no way (within a single style; it can be done with stylizers, later) to make objects multi-line and arrays single-line.

### `multiline`

This indicates whether to print newlines separating list entries or object key/value pairs. It is the difference between `preset_one_line` and `preset_multiline`.

### :exclamation: TODO: Other future attributes

Some other things I think could be wanted/useful:

* `ensure_ascii` -- this is currently a fixed argument passed through the serializers's `dump` function, but should probably be split out here
* `array_max_length` -- inspired by [this comment](https://github.com/nlohmann/json/issues/229#issuecomment-300783790), where a user wanted to be able to print a nine-element list as a 3x3 array (three lines, three elements/line). This should be easy to do for simple cases, but I suspect that aligning into columns might be useful and that'd be harder.
* `spaces_inside_braces`/`spaces_inside_brackets` -- `[ 1, 2 ]` and `{ "key": 1 }`
* Anything that might affect the formatting of numbers?
