# generate_natvis.py

Generate the Natvis debugger visualization file for all supported namespace combinations.

The ABI tag list and the library version are parsed from
`include/nlohmann/detail/abi_macros.hpp`, so this script must be re-run (via
`make natvis`) whenever an `NLOHMANN_JSON_ABI_TAG_*` macro is added to that
file or the library version is bumped — otherwise the committed
`nlohmann_json.natvis` drifts from the header it visualizes, and
`make check-amalgamation` fails.

## Usage

```shell
make natvis
```

or, equivalently:

```shell
./generate_natvis.py [--version X.Y.Z] [repository_root/]
```

`--version` and the output/repository-root directory both default to values
derived from this script's own location, so they only need to be given
explicitly when generating a Natvis file for a different checkout or a
version other than the one in `abi_macros.hpp`.
