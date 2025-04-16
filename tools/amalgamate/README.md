# amalgamate.py - Amalgamate C source and header files

Origin: https://bitbucket.org/erikedlund/amalgamate

Mirror: https://github.com/edlund/amalgamate

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

Python v.2.7.0 or higher is required.

`amalgamate.py` can be tested and installed using the following commands:

        ./test.sh && sudo -k cp ./amalgamate.py /usr/local/bin/

## Using amalgamate.py

        amalgamate.py [-v] -c path/to/config.json -s path/to/source/dir \
                [-p path/to/prologue.(c|h)]

 * The `-c, --config` option should specify the path to a JSON config file which
   lists the source files, include paths and where to write the resulting
   amalgamation. Have a look at `test/source.c.json` and `test/include.h.json`
   to see two examples.

 * The `-s, --source` option should specify the path to the source directory.
   This is useful for supporting separate source and build directories.

 * The `-p, --prologue` option should specify the path to a file which will be
   added to the beginning of the amalgamation. It is optional.

