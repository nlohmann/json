# macro_builder

Generates the argument-counting macros behind the `NLOHMANN_DEFINE_TYPE_*` and `NLOHMANN_DEFINE_DERIVED_TYPE_*`
macros in [`include/nlohmann/detail/macro_scope.hpp`](../../include/nlohmann/detail/macro_scope.hpp):

- `NLOHMANN_JSON_EXPAND`
- `NLOHMANN_JSON_GET_MACRO`, which selects a macro by the number of its arguments (64 slots)
- `NLOHMANN_JSON_PASTE`, which calls a function-like macro for each member, and its helpers `NLOHMANN_JSON_PASTE2`
  to `NLOHMANN_JSON_PASTE64`
- `NLOHMANN_JSON_DOUBLE_PASTE`, which the `*_WITH_NAMES` macros use to call a function-like macro for each
  (JSON name, member) pair, and its helpers `NLOHMANN_JSON_DOUBLE_PASTE3` to `NLOHMANN_JSON_DOUBLE_PASTE63`
- the slot table of `NLOHMANN_JSON_TYPE_BODY`, which dispatches `NLOHMANN_DEFINE_TYPE_*(Type)` (no further
  arguments) to the zero-member implementation and every other argument count to the one-or-more-member
  implementation

The number of slots (`max_args` in [`main.cpp`](main.cpp)) sets the member limit of these macros.
`NLOHMANN_JSON_PASTE` and `NLOHMANN_JSON_TYPE_BODY` take the function/prefix as their first argument, so 64 slots
allow 63 members; `NLOHMANN_JSON_DOUBLE_PASTE` additionally consumes its members two at a time (name, member), so
it only defines the odd helpers up to `NLOHMANN_JSON_DOUBLE_PASTE63`.

## Usage

From the project root:

```shell
c++ -std=c++11 tools/macro_builder/main.cpp -o macro_builder
./macro_builder
./macro_builder type_body
```

1. Run `./macro_builder` (no arguments). In `include/nlohmann/detail/macro_scope.hpp`, replace the lines from
   `#define NLOHMANN_JSON_EXPAND( x ) x` to the `#define NLOHMANN_JSON_DOUBLE_PASTE63(...)` line with the output,
   without its trailing empty line.
2. Run `./macro_builder type_body`. Replace the lines from `#define NLOHMANN_JSON_TYPE_BODY(Prefix, ...)` to the
   `NLOHMANN_JSON_TYPE_BODY_SENTINEL))` line with the output.
3. Run `make amalgamate`. It updates `single_include/nlohmann/json.hpp` and runs `make pretty`, which indents the
   continuation lines that the tool writes unindented.

With an unchanged `main.cpp`, these steps reproduce both blocks of `macro_scope.hpp` byte for byte. `make
macro_builder_check` (also run by CI, see `.github/workflows/check_amalgamation.yml`) automates this: it builds
`main.cpp`, regenerates both blocks, and fails on a diff against the checked-in header.

## Maintained by hand

The tool does not generate everything that depends on the number of slots. When changing `max_args`, also update:

- the documented limit of 63 members in `docs/mkdocs/docs` and the tests at that limit in
  `tests/src/unit-udt_macro.cpp`

All three tables pass one macro name per slot to `NLOHMANN_JSON_GET_MACRO`, so they need exactly as many entries as
it has slots.
