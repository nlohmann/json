# Debugging

This page collects the library's built-in debugger integrations and other debugging-related features. They are not
covered by any single page elsewhere in the docs, so they are collected here.

## Visual Studio (natvis)

The repository ships [`nlohmann_json.natvis`](https://github.com/nlohmann/json/blob/develop/nlohmann_json.natvis)
at its root, a [Natvis](https://learn.microsoft.com/en-us/visualstudio/debugger/create-custom-views-of-native-objects)
file that gives `json`/`ordered_json` values a friendly, key/value debugger view instead of showing raw internal
fields, when debugging with the MSVC debug engine (`cppvsdbg`) in Visual Studio or VS Code.

The checked-in visualizers cover namespace variants with zero, one, or two ABI tags. Configurations with three or more
ABI tags are not covered and may show raw internal fields instead. To generate a Natvis file for such a configuration:

1. Check out the release tag of the library version you use.
2. List the ABI tags and the macros that enable them:

    ```shell
    make natvis NATVIS_ARGS="--list-tags"
    ```

3. Generate a Natvis file with the tags of your configuration, for example for `JSON_DIAGNOSTICS`,
    `JSON_DIAGNOSTIC_POSITIONS`, and `JSON_VIEW_NO_SIMD`:

    ```shell
    make natvis NATVIS_ARGS="--abi-tags _diag,_dp,_vns --output my_nlohmann_json.natvis"
    ```

4. Use the generated file instead of `nlohmann_json.natvis`.

`--abi-tags` can be repeated for several configurations, and `--all` generates every combination (about 60 MB for 12
ABI tags, doubling with each further tag). See
[`tools/generate_natvis`](https://github.com/nlohmann/json/tree/develop/tools/generate_natvis) for all options.

Debug engines that wrap LLDB instead of the MSVC debug engine (for example, `codelldb` in VS Code) only have
partial/experimental Natvis support, and commonly fall back to showing raw internal fields even with the
`.natvis` file present. Switching to `cppvsdbg` where available, or checking your debug extension's own Natvis
support/version, are the next things to try if this happens. There is currently no bundled LLDB-native
pretty-printer script in this repository.

## GDB

The repository ships a [GDB Python pretty printer](https://github.com/nlohmann/json/tree/develop/tools/gdb_pretty_printer)
under `tools/gdb_pretty_printer`, with its own usage instructions in that directory's `README.md`.

## Extended exception diagnostics

Defining [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) before including the library augments
`type_error`/`out_of_range`-style exceptions with a JSON Pointer to the offending value, which can help pinpoint
where in a large document a runtime error occurred. This only applies to exceptions thrown *after* a value
exists (e.g. during element access); parse errors, which happen before any value exists to point at, are not
covered by this mechanism -- see [Parsing and exceptions](../features/parsing/parse_exceptions.md) for how parse
errors report their own location instead.
