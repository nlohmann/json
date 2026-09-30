# amalgamate.py - Amalgamate C source and header files

Origin: https://github.com/edlund/amalgamate (formerly hosted at
https://bitbucket.org/erikedlund/amalgamate, which no longer exists; see
`CHANGES.md` for the upstream commit this copy is based on)

`amalgamate.py` aims to make it easy to use SQLite-style C source and header
amalgamation in projects.

For more information, please refer to: http://sqlite.org/amalgamation.html

## Here be dragons

`amalgamate.py` is quite dumb, it only knows the bare minimum about C code
required in order to be able to handle trivial include directives. It can
produce weird results for unexpected code.

Things to be aware of:

`amalgamate.py` will not handle complex include directives correctly:

        #define HEADER_PATH "path/to/header.h"
        #include HEADER_PATH

In the above example, `path/to/header.h` will not be included in the
amalgamation (HEADER_PATH is never expanded).

`amalgamate.py` makes the assumption that each source and header file which
is not empty will end in a new-line character, which is not immediately
preceded by a backslash character (see 5.1.1.2p1.2 of ISO C99).

`amalgamate.py` should be usable with C++ code, but raw string literals from
C++11 will definitely cause problems:

        R"delimiter(Terrible raw \ data " #include <sneaky.hpp>)delimiter"
        R"delimiter(Terrible raw \ data " escaping)delimiter"

In the examples above, `amalgamate.py` will stop parsing the raw string literal
when it encounters the first quotation mark, which will produce unexpected
results.

## Installing amalgamate.py

Python 3 is required.

In this repository, `amalgamate.py` is not installed separately; it is run in
place through `make amalgamate`, which calls it once for `json.hpp` and once
for `json_fwd.hpp` (see the root `Makefile`).

## Using amalgamate.py

        amalgamate.py -c path/to/config.json -s path/to/source/dir \
                [-p path/to/prologue.(c|h)] [--verbose=yes|no]

 * The `-c, --config` option should specify the path to a JSON config file which
   lists the source files, include paths and where to write the resulting
   amalgamation. `config_json.json` and `config_json_fwd.json` in this
   directory are the configs used for `json.hpp` and `json_fwd.hpp`; each
   sets `target`, `sources` and `include_paths`.

   The optional `external` list names include paths that are kept as `#include`
   directives instead of being inlined, e.g. `["nlohmann/json.hpp"]` for a header
   that includes another amalgamated header. Only the first directive for each
   of these paths is kept; the repeated ones are commented out.

 * The `-s, --source` option should specify the path to the source directory.
   This is useful for supporting separate source and build directories.

 * The `-p, --prologue` option should specify the path to a file which will be
   added to the beginning of the amalgamation. It is optional.

 * The `-v, --verbose` option takes `yes` or `no` (for example
   `--verbose=yes`, as used by the Makefile). It is optional.

