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

## Stylizers -- Flexible Formatting

You may want to change the style used by the printer depending on the context or the object being printed. Stylizers provide a way to do this. Harking back to the analogy about code formatters and CSS, stylizers implement the CSS portion of that analogy. As the pretty printer performs its recursive traversal, it will query the stylizer to determine what style changes (if any) should be applied to the current subtree. (Like CSS, those changes only apply to that subtree, and are automatically unapplied when the subtree is finished.)

:exclamation: At the moment, the above description is a bit wrong -- the stylizer doesn't provide *changes*, it provides a complete new style. It's as if for every CSS selector you provide, you have to list all possible CSS attributes or let them be the default value; it can't cascade up from the context, *whatever* that might be. This should be fixed by the final version of this PR. Basically, fields of `print_style` will conceptually become `optional<.>`, where `none` indicates that the value should bubble up from the parent context. (In actuality, I'll be using something other than `optional` that will be both more compact and not be C++17. :-))

A stylizer stores a list of predicates on the current context and node. As the serializer visits each node in the tree, the stylizer will query each predicate in turn to determine if it wants to style the current node, appyling a corresponding style provided with the predicate if so.

:exclamation: Because of the prior point, this is also wrong. Right now it just stops at the first predicate that returns `true`, and takes its style. This actually in some sense means it's doing the exact opposite of what it will eventually do -- the *last* predicate to run will be the one that applies.

:question: Actually now that I type that out, maybe instead of predicates, it should just be a list of functions that are allowed to mutate, if they're interested, the style. Hmmm.

Each predicate can take either or both of two parameters:

* A `json_pointer` object providing the context to the current node.
* The `json` object (or rather, a `const&` to it) that is the root of the current subtree.

Predicates and styles are registered with the function `register_style`.

In addition, there is a convenience function, `register_key_matcher_style`; given a string, this will generate a context predicate that will trigger when the current object is the value of the associated key. For example, given `"foo"`, it will trigger for (and hence style) `[1, 2]` in `{"foo": [1, 2], "bar": 7}`.

Both `register_style` and `register_key_matcher_style` can be used in a couple different ways, depending on how many changes to the style are needed:

* If a `print_style` object is already available, it can be passed as a second argument: `stylizer.register_style(pred, my_style)`
* `register_style` and `register_key_matcher_style` return a mutable reference to the style that will be used when the predicate matches, so it can be used as, for example, `stylizer.register_style(pred) = print_style::preset_one_line()`
* `last_registered_style()` returns a mutable reference to the last style added with a `register` call

:question: I think I want to remove the mutable reference return thing and remove `last_registered_style` entirely. Those were convenience things from before I had the presets, `last_registered_style` isn't even needed or used in my tests any more, and the second bullet point is only used once in a way that isn't trivial (`stylizer.register_style(...).space_after_comma = true`). Or I could remove `last_registered_style()` but leave the mutable return on `register`. Thoughts?

The predicate can be any object that is callable as `p(json)`, `p(json_pointer)`, or `p(json_pointer, json)`. (It probably expects a `const&` for each, as mentioned above.)

A stylizer can be provided a default `print_style` that is used for the root object.

:question: I feel like there's some uglyness here. To get the overloaded `register_style` functions, I had to do some template hackery to avoid ambiguous calls, *and* to avoid needing to go through two `std::function` calls. ("And" as in if you wanted to do either and keep the ability to pass both `pred(json)` and `pred(json_pointer)` using functions with the same name, you'd hit my problems.) I don't feel confident that this is as well-written as it could be. One problem I ran into was the use of `json_pointer`. (1) I had to add accessors so predicates can to get to the components of it (see examples, below). (2) I'm not happy with those accessors. Should it have `size()` and `[]` too? `begin` and `end`? If yes on `begin` and `end`, should they return `iterator` (and so `json_pointer` now has a mutable API) or `const_iterator`? (3) There are (apparent) implicit conversions both from `json` to `json_pointer` and vice versa, which made my template hackery on `register_style` a lot harder to figure out, though only slightly more complex to actually implement and explain. (Note: the conversion from `json` to `json_pointer` will fail, but it's a hard error and not SFIANE-friendly. Actually, now that I think about it -- disabling that conversion would be very plesant.)

:question: So one specific idea is to not use `json_pointer`. Another thought I had was that it could pass the entire line of `json` objects (or rather, `const*`) along with the textual path, in case that's useful to anyone.

Example of `register_key_matcher_style`:

    print_stylizer stylizer(print_style::preset_multiline());
    stylizer.register_key_matcher_style("one line", print_style::preset_one_line());

    json j = {
        {"one line", {1, 2}},
        {"two lines", {1, 2}}
    };
    styled_dump(std::cout, j, stylizer);

    // Prints (no comments):
    //{
    //    "one line": [1,2],
    //    "two lines": [
    //        1,
    //        2
    //    ]
    //}
    
Example of `register_style` with a context-based predicate:

    print_stylizer stylizer(print_style::preset_multiline());
    
    stylizer.register_style(
        [] (const json_pointer<json>& context)
    {
        // Matches if context[-2] is "each elem on one line"
        // -- so uses preset_one_line for *subobjects* of that.
        // (register_key_matcher_style would put the list
        // subobject on one line, but we want elements on multiple
        // lines.)
        return (context.cend() - context.cbegin() >= 2)
               && (*(context.cend() - 2) == "each elem on one line");
    }
    ) = print_style::preset_one_line();
    
    json j = {
        {
            "each elem on one line", {
                {1, 2, 3, 4, 5},
                {1, 2, 3, 4, 5}
            },
        },
        {
            "fully multiline", {
                {1, 2, 3},
            }
        };
    
    styled_dump(std::cout, j, stylizer);
    // Prints (no comments):
    //{
    //    "each elem on one line": [
    //        [1, 2, 3, 4, 5],
    //        [1, 2, 3, 4, 5]
    //    ],
    //    "fully multiline": [
    //        [
    //            1,
    //            2,
    //            3
    //        ]
    //    ]
    //}

Example of `register_style` with an object predicate:

    print_stylizer stylizer;
    stylizer.get_default_style() = print_style::preset_multiline;
    
    stylizer.register_style(
        [] (const json & j)
    {
        return j.type() == json::value_t::array;
    }
    ) = print_style::preset_one_line;
    
    json j = {
        {"an array", {1, 2, 3}},
        {"an object", {{"key", "val"}}}
    };
    
    styled_dump(std::cout, j, stylizer);
    // Prints (no comment):
    //{
    //    "an array": [1, 2, 3],
    //    "an object": {
    //        "key": "val"
    //    }
    //}
