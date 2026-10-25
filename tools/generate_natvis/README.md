# generate_natvis.py

Generate the Natvis debugger visualization file for namespace combinations with up to two ABI tags.

The checked-in `nlohmann_json.natvis` covers the default namespace (no ABI tags), every single ABI tag, and every pair
of ABI tags, with both versioned and unversioned namespace variants. Configurations that enable three or more ABI tags
are not covered by this reduced file; use `--abi-tags` or `--all` (see below) to generate a file for them.

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

`make natvis` sets up a virtual environment `tools/generate_natvis/venv` with the dependencies from
`requirements.txt` (Jinja2) and runs the script with it. Alternatively, install the requirements yourself and run:

```shell
./generate_natvis.py [--version X.Y.Z] [--abi-tags TAGS]... [--all] [--list-tags] [--output FILE] [repository_root/]
```

`--version` and the repository root both default to values
derived from this script's own location, so they only need to be given
explicitly when generating a Natvis file for a different checkout or a
version other than the one in `abi_macros.hpp`.

| Option            | Description                                                                                                                                                                                                                                         |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--list-tags`     | Print every ABI tag (in namespace order) with the macro that enables it and the `NLOHMANN_JSON_ABI_TAG_*` identifier, then exit.                                                                                                                    |
| `--abi-tags TAGS` | Add the namespaces of one configuration, given as a comma-separated list of ABI tags (`_diag,_dp,_ns`; the leading underscore is optional, and the order does not matter). Can be repeated for several configurations. Unknown tags are an error. |
| `--all`           | Generate the namespaces for every combination of ABI tags. The file size doubles with each tag (about 60 MB for 12 tags). Cannot be combined with `--abi-tags`.                                                                                    |
| `--output FILE`   | Write the Natvis file to `FILE` instead of `nlohmann_json.natvis` in the repository root.                                                                                                                                                           |

Each configuration gets both the versioned (`json_abi_diag_dp_ns_v3_12_0`) and the unversioned (`json_abi_diag_dp_ns`,
used with `NLOHMANN_JSON_NAMESPACE_NO_VERSION`) namespace. The default namespaces (up to two ABI tags) are always
included, so a generated file can replace the checked-in one.

### Generating a Natvis file for your configuration

1. Check out the release tag of the library version you use (the ABI tags and the version are read from the checkout).
2. Find the ABI tags of the macros you enable:

   ```shell
   make natvis NATVIS_ARGS="--list-tags"
   ```

3. Generate a Natvis file with them, for example for `JSON_DIAGNOSTICS`, `JSON_DIAGNOSTIC_POSITIONS`, and
   `JSON_NO_SIMD`:

   ```shell
   make natvis NATVIS_ARGS="--abi-tags _diag,_dp,_ns --output my_nlohmann_json.natvis"
   ```

4. Use `my_nlohmann_json.natvis` instead of the shipped `nlohmann_json.natvis`, for example by adding it to your Visual
   Studio project.

Passing `--output` keeps the checked-in `nlohmann_json.natvis` unchanged; without it, `make check-amalgamation` would
report the file as out of date.
