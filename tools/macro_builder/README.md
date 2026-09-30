# macro_builder

Generates the argument-counting macros behind the `NLOHMANN_DEFINE_TYPE_*` and `NLOHMANN_DEFINE_DERIVED_TYPE_*`
macros in [`include/nlohmann/detail/macro_scope.hpp`](../../include/nlohmann/detail/macro_scope.hpp):

- `NLOHMANN_JSON_EXPAND`
- `NLOHMANN_JSON_GET_MACRO`, which selects a macro by the number of its arguments (64 slots)
- `NLOHMANN_JSON_PASTE`, which calls a function-like macro for each member, and its helpers `NLOHMANN_JSON_PASTE2`
  to `NLOHMANN_JSON_PASTE64`

The number of slots (`max_args` in [`main.cpp`](main.cpp)) sets the member limit of these macros.
`NLOHMANN_JSON_PASTE` takes the function as its first argument, so 64 slots allow 63 members.

## Usage

From the project root:

```shell
c++ -std=c++11 tools/macro_builder/main.cpp -o macro_builder
./macro_builder
```

1. In `include/nlohmann/detail/macro_scope.hpp`, replace the lines from `#define NLOHMANN_JSON_EXPAND( x ) x` to the
   `#define NLOHMANN_JSON_PASTE64(...)` line with the output, without its trailing empty line.
2. Run `make amalgamate`. It updates `single_include/nlohmann/json.hpp` and runs `make pretty`, which indents the
   continuation lines of `NLOHMANN_JSON_PASTE` that the tool writes unindented.

With an unchanged `main.cpp`, these steps reproduce the header byte for byte.

## Maintained by hand

The tool does not generate everything that depends on the number of slots. When changing `max_args`, also update:

- the `NLOHMANN_JSON_DOUBLE_PASTE` table right after the generated block (`NLOHMANN_JSON_DOUBLE_PASTE` and
  `NLOHMANN_JSON_DOUBLE_PASTE3`, `NLOHMANN_JSON_DOUBLE_PASTE5`, ..., `NLOHMANN_JSON_DOUBLE_PASTE63`), which the
  `*_WITH_NAMES` macros use
- the slot table of `NLOHMANN_JSON_TYPE_BODY`, which chooses between the implementations for zero members and for one
  or more members
- the documented limit of 63 members in `docs/mkdocs/docs` and the tests at that limit in
  `tests/src/unit-udt_macro.cpp`

Both tables pass one macro name per slot to `NLOHMANN_JSON_GET_MACRO`, so they need exactly as many entries as it has
slots.
