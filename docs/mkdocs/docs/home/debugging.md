# Debugging

This page collects the library's built-in debugger integrations and other debugging-related features. They are
not linked from a single place elsewhere in the docs, so are collected here.

## Visual Studio (natvis)

The repository ships [`nlohmann_json.natvis`](https://github.com/nlohmann/json/blob/develop/nlohmann_json.natvis)
at its root, a [Natvis](https://learn.microsoft.com/en-us/visualstudio/debugger/create-custom-views-of-native-objects)
file that gives `json`/`ordered_json` values a friendly, key/value debugger view instead of showing raw internal
fields, when debugging with the MSVC debug engine (`cppvsdbg`) in Visual Studio or VS Code.

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
