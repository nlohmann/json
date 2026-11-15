# JSON_RECURSION_DEPTH_LIMIT

```cpp
#define JSON_RECURSION_DEPTH_LIMIT /* value */
```

This macro sets how many nesting levels the operations that walk a value recurse into on the call stack. Beyond that,
they continue with an explicit stack on the heap. The value is an integer constant from `0` to `254`; the default is
`128`.

The operations are copying a value, comparing two values, serializing with [`dump`](../basic_json/dump.md) or
[`operator<<`](../operator_ltlt.md), hashing with `std::hash`, [`merge_patch`](../basic_json/merge_patch.md),
[`update`](../basic_json/update.md) with `merge_objects`, [`diff`](../basic_json/diff.md),
[`merge_diff`](../basic_json/merge_diff.md), converting a value to another specialization of `basic_json`, destroying a
value, and the binary writers [`to_cbor`](../basic_json/to_cbor.md),
[`to_msgpack`](../basic_json/to_msgpack.md), [`to_ubjson`](../basic_json/to_ubjson.md),
[`to_bjdata`](../basic_json/to_bjdata.md), and [`to_bon8`](../basic_json/to_bon8.md). They share this one limit; none
has
a limit of its own. Recursing is the fastest way to walk a value, but a value nested deeply enough would exhaust the
call
stack, so the library recurses only as far as the limit and finishes the levels below with an explicit stack. This is
what makes all of them safe for untrusted input
(see [Nesting depth](../../features/parsing/untrusted_input.md#nesting-depth)). Parsing, the binary readers,
[`flatten`](../basic_json/flatten.md), [`unflatten`](../basic_json/unflatten.md), and
[`to_bson`](../basic_json/to_bson.md) always use an explicit stack and do not depend on the macro. The lockstep
comparison of two [`json_view`](../basic_json_view/index.md) documents has a fixed bound of its own, 48 levels,
and does not depend on it either.

The call stack that these operations need grows with the limit: roughly *a few kilobytes plus a cost per level times the
limit*, where the cost per level is up to about 1.8 KiB in an unoptimized and up to about 0.5 KiB in an optimized build
(see [Stack needed](#stack-needed)). The default of `128` levels is tuned for threads with ordinary stacks of a few
hundred kilobytes or more. Set a lower limit if your threads have small stacks (RTOS tasks, fibers, threads of the musl
C
library, which has a default stack of 128 KiB), or a higher limit to trade stack for speed on deeply nested values.

The macro changes only how much stack is used and how fast the operations are. It never changes a result: every
operation returns the same value for every setting of the limit, for values nested less deeply than the limit as well as
for values nested more deeply.

## Default definition

The default value is `128`.

```cpp
#define JSON_RECURSION_DEPTH_LIMIT 128
```

When the macro is not defined, the library defines it to its default value.

## Notes

!!! note "Allowed values"

    The value must be an integer constant expression from `0` to `254`; any other value (a negative number, a number
    above `254`, a floating-point number such as `254.0`, or `true` or `false`) is rejected at compile time with an
    error message that names the macro. A character of any character type (`'a'`, `L'a'`, `u8'a'`, ...) is rejected,
    too, although it is an integer.

    - `0` is allowed, and means that every operation uses its explicit stack from the first level on and no operation
      recurses over the nesting of a value at all. That needs a constant amount of call stack (at most 16 KiB in the
      measurements below, for a value nested 20,000 levels deep) and is the setting for tiny stacks, at the price of
      speed (see [Speed](#speed)).
    - `254` is the largest allowed value. Copying a value and comparing two values (with `<=>`, or with the operators on
      objects and arrays of a custom type) cannot pass the depth down as an argument, because the signatures of the
      copy constructor and the operators are fixed. They count the levels they have descended into in a variable of type
      `#!cpp std::uint8_t` that exists once per thread (see [`JSON_NO_THREAD_LOCAL`](json_no_thread_local.md)). Only
      the levels that are descended into are counted, so the count never exceeds the limit, not even when user code (a
      copy constructor of a custom base class, say) copies a value while a copy is going on. A byte holds `255` at
      most, and the limit stays below that, so that the count cannot wrap around. (More levels would hardly be
      useful: `254` levels need up to 448 KiB of stack in an unoptimized build already, twice as much as the
      default.)

### Stack needed

The tables show the smallest stack that an operation needs, in KiB, at several limits, on a value that is nested
more deeply than the limit (limit + 10 levels). Each cell shows the result for Clang (Apple clang 21) and for
GCC 16, separated by a slash; both measured on macOS with arm64, compiling in C++20 mode. The operations run in a
thread whose stack has the size given, and are not given any stack that they do not need: the value is built, and
the result destroyed, outside of that thread. Stacks can only be set in steps of 16 KiB (the page size), so `16`
means "16 KiB or less". A row stands for all operations listed; the table shows the largest value among them.

Unoptimized (`-O0`):

| Operation | limit 16 | limit 32 | limit 64 | limit 128 | limit 254 |
|---|---:|---:|---:|---:|---:|
| `dump()` and `dump(indent)`, `operator<<` | 16 / 16 | 16 / 16 | 32 / 32 | 48 / 48 | 96 / 96 |
| copy construction and assignment | 32 / 16 | 48 / 32 | 112 / 80 | 224 / 144 | 432 / 304 |
| `==` | 16 / 16 | 16 / 16 | 16 / 16 | 48 / 32 | 96 / 48 |
| `<=>` (C++20) | 16 / 16 | 16 / 16 | 32 / 32 | 64 / 64 | 144 / 128 |
| `std::hash` | 16 / 16 | 16 / 16 | 32 / 32 | 80 / 64 | 160 / 128 |
| `merge_patch`, `update(j, true)`, `patch` | 32 / 16 | 48 / 32 | 112 / 80 | 224 / 144 | 432 / 304 |
| `diff` | 16 / 16 | 16 / 16 | 32 / 32 | 64 / 48 | 144 / 96 |
| `merge_diff` | 16 / 16 | 48 / 32 | 80 / 48 | 176 / 112 | 352 / 224 |
| `to_cbor`, `to_msgpack` | 16 / 16 | 32 / 16 | 64 / 32 | 112 / 80 | 224 / 160 |
| `to_ubjson`, `to_bjdata` | 16 / 16 | 16 / 16 | 48 / 32 | 96 / 64 | 176 / 112 |
| `to_bon8` | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 16 | 64 / 48 |
| conversion to another `basic_json` type | 32 / 16 | 64 / 32 | 112 / 80 | 224 / 144 | 448 / 304 |
| destruction | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 32 |

Optimized (`-O2`):

| Operation | limit 16 | limit 32 | limit 64 | limit 128 | limit 254 |
|---|---:|---:|---:|---:|---:|
| `dump()` and `dump(indent)`, `operator<<` | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 32 |
| copy construction and assignment | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 32 | 64 / 48 |
| `==` | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 |
| `<=>` (C++20) | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 48 / 16 |
| `std::hash` | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 48 | 80 / 80 |
| `merge_patch`, `update(j, true)`, `patch` | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 32 | 64 / 48 |
| `diff` | 16 / 16 | 16 / 16 | 16 / 32 | 48 / 48 | 96 / 112 |
| `merge_diff` | 16 / 16 | 16 / 16 | 16 / 16 | 48 / 32 | 96 / 64 |
| `to_cbor`, `to_msgpack` | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 |
| `to_ubjson`, `to_bjdata` | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 32 | 64 / 64 |
| `to_bon8` | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 32 | 32 / 64 |
| conversion to another `basic_json` type | 16 / 16 | 16 / 16 | 16 / 16 | 32 / 48 | 64 / 96 |
| destruction | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 | 16 / 16 |

With a limit of `0`, every operation in the tables ran in a 16 KiB stack at `-O0` (Clang and GCC), on a value nested
20,000 levels deep. The operations that do not depend on the macro (`flatten`, `unflatten`, `to_bson`) needed
16 KiB or less at every limit.

The rule of thumb is

> stack needed ≈ a few KiB + cost per level × limit

with a cost per level of up to 1.8 KiB (conversion to another `basic_json` type at `-O0` with Clang; 1.3 KiB with
GCC), 1.7 KiB for copying and merging (1.3 KiB with GCC), 0.4 KiB for `dump`, and 0.1 to 0.5 KiB for most other
operations at `-O0`; and 0.5 KiB or less at `-O2`. The numbers come from the difference between the limits `128` and
`254` in the tables, so they are rough: other compilers, other targets (the frames of x86-64 code are about as large),
other standard libraries, `JSON_DIAGNOSTICS`, and sanitizers change them. Measure with your own tool chain (see the
example below) rather than relying on the tables. The stack that your own code and the operating system need comes on
top of these numbers.

Which limit to choose, for the stack that you can spare for the library (the largest limit of those measured
for which the slowest operation needs at most that much):

| Stack for the library | optimized (`-O2`) | unoptimized (`-O0`) |
|---|---:|---:|
| 32 KiB | 64 | 16 |
| 64 KiB | 128 | 32 |
| 128 KiB (the default stack of threads on musl) | 254 | 64 |
| 256 KiB | 254 | 128 |
| 512 KiB | 254 | 254 |
| 1 MiB or more | 254 | 254 |

### Speed

Operations are faster the more of a value they handle with plain recursion. The levels below the limit are handled with
an explicit stack, which has to be kept on the heap and costs more per level. The macro therefore trades speed against
stack.

The table shows the time of copying a value (including destroying the copy), of `==` on two equal values, of `dump`, and
of `std::hash` for several limits, relative to the default of `128` (`1.00` means the same time; more is slower). It was
measured with Clang 21 at `-O2` in C++17 mode on macOS with arm64, as the best of seven runs of each setting (two
rounds, best of both). The documents are ordinary JSON files that are nested 7 (`canada.json`), 8
(`citm_catalog.json`), 10 (`twitter.json`), and 2 levels deep (`jeopardy.json`); the other values are one array or object
with one member per level, nested 1,000 and 100,000 levels deep. The absolute time at the limit `128` is given in the
third column. Differences of up to about 0.1 are noise: a different limit changes the layout of the compiled code, and
timings of the same binary vary by about as much. The slow columns (limits 0 and 1) vary more: repeating `std::hash` on
`canada.json` gave 1.27 to 1.30 for limit 0 and 1.4 to 1.9 for limit 1, so read the cells of those two columns as
accurate to about 0.3.

| Value | Operation | limit 128 (absolute) | limit 0 | limit 1 | limit 16 | limit 254 |
|---|---|---:|---:|---:|---:|---:|
| `canada.json` (2.1 MB) | copy | 3.5 ms | 1.80 | 1.80 | 0.99 | 1.00 |
| `canada.json` (2.1 MB) | `==` | 350.5 µs | 2.36 | 2.38 | 1.00 | 0.99 |
| `canada.json` (2.1 MB) | `dump` | 2.4 ms | 1.11 | 1.11 | 1.00 | 1.00 |
| `canada.json` (2.1 MB) | `std::hash` | 920.2 µs | 1.33 | 1.59 | 1.00 | 1.00 |
| `citm_catalog.json` (1.7 MB) | copy | 1.8 ms | 1.38 | 1.36 | 1.00 | 0.99 |
| `citm_catalog.json` (1.7 MB) | `==` | 275.5 µs | 1.31 | 1.31 | 0.99 | 1.00 |
| `citm_catalog.json` (1.7 MB) | `dump` | 314.6 µs | 1.24 | 1.23 | 1.00 | 1.00 |
| `citm_catalog.json` (1.7 MB) | `std::hash` | 309.1 µs | 1.77 | 1.42 | 1.06 | 1.05 |
| `twitter.json` (0.6 MB) | copy | 865.7 µs | 1.45 | 1.47 | 1.01 | 1.00 |
| `twitter.json` (0.6 MB) | `==` | 135.8 µs | 1.26 | 1.23 | 1.00 | 1.00 |
| `twitter.json` (0.6 MB) | `dump` | 224.6 µs | 1.12 | 1.12 | 1.01 | 1.00 |
| `twitter.json` (0.6 MB) | `std::hash` | 132.9 µs | 1.28 | 1.27 | 1.03 | 1.04 |
| `jeopardy.json` (53 MB) | copy | 111.1 ms | 1.22 | 1.25 | 1.00 | 1.00 |
| `jeopardy.json` (53 MB) | `==` | 23.5 ms | 1.29 | 1.53 | 1.07 | 1.00 |
| `jeopardy.json` (53 MB) | `dump` | 33.2 ms | 1.14 | 1.34 | 1.03 | 1.01 |
| `jeopardy.json` (53 MB) | `std::hash` | 19.9 ms | 1.17 | 1.52 | 1.05 | 1.00 |
| arrays, 1,000 levels | copy | 69.9 µs | 0.95 | 0.98 | 0.92 | 0.99 |
| arrays, 1,000 levels | `==` | 10.4 µs | 1.02 | 1.01 | 0.96 | 1.00 |
| arrays, 1,000 levels | `dump` | 9.6 µs | 0.97 | 0.96 | 0.97 | 1.06 |
| arrays, 1,000 levels | `std::hash` | 16.9 µs | 1.00 | 1.01 | 1.01 | 0.98 |
| objects, 1,000 levels | copy | 77.1 µs | 0.98 | 0.97 | 0.97 | 1.03 |
| objects, 1,000 levels | `==` | 12.0 µs | 0.96 | 0.95 | 0.95 | 1.07 |
| objects, 1,000 levels | `dump` | 12.6 µs | 0.97 | 0.95 | 0.98 | 1.01 |
| objects, 1,000 levels | `std::hash` | 17.3 µs | 0.99 | 1.01 | 0.98 | 1.00 |
| arrays, 100,000 levels | copy | 6.4 ms | 1.00 | 1.00 | 1.00 | 1.00 |
| arrays, 100,000 levels | `==` | 1.1 ms | 1.01 | 1.03 | 1.00 | 1.06 |
| arrays, 100,000 levels | `dump` | 917.9 µs | 1.01 | 1.01 | 1.02 | 1.01 |
| arrays, 100,000 levels | `std::hash` | 1.7 ms | 1.04 | 1.05 | 0.99 | 0.99 |
| objects, 100,000 levels | copy | 7.5 ms | 0.99 | 1.02 | 1.01 | 0.99 |
| objects, 100,000 levels | `==` | 1.3 ms | 1.02 | 1.09 | 1.08 | 0.96 |
| objects, 100,000 levels | `dump` | 1.2 ms | 1.06 | 0.99 | 1.01 | 0.99 |
| objects, 100,000 levels | `std::hash` | 1.8 ms | 1.00 | 1.00 | 1.00 | 1.00 |

The results are as follows.

- A limit of `16` or more does not change the speed of ordinary documents (differences are within noise), because they
  are not nested more deeply than that anyway. A document nested more deeply than the limit is walked partly with the
  explicit stack.
- A limit of `0` or `1` makes the operations on ordinary documents 1.1 to 2.4 times as slow, because even their first
  levels are handled with the explicit stack. The slowdown is largest for `==` on a document of many small containers
  (`canada.json`: 2.4 times) and for copying (up to 1.8 times).
- For values that are nested far more deeply than any limit (1,000 and 100,000 levels deep), the limit makes no
  measurable difference: almost all of the levels are handled with the explicit stack for every setting.
  Raising the limit gains nothing for them, and lowering it costs nothing.

!!! note "Other macros"

    - With [`JSON_NO_THREAD_LOCAL`](json_no_thread_local.md) defined (or for Clang targeting MinGW, where the library
      defines it by itself), copying and comparing never descend, so for them the limit does not matter. The other
      operations still recurse as many levels as the limit says. The range of the limit is the same.
    - The macro is not part of the [ABI tag](../../features/namespace.md), as `JSON_NO_THREAD_LOCAL` is not, and it is
      not undefined at the end of `json.hpp`.

!!! warning "Use the same value in every translation unit"

    All translation units of a program that include the library must define the same value. Otherwise, the program
    violates the One Definition Rule: the function `nlohmann::detail::recursion_depth_limit()` and all the functions
    that use it are defined differently in different translation units. Which limit a call uses then depends on which
    functions the compiler inlined (an inlined copy uses the value of its own translation unit) and which out-of-line
    copy of each remaining function the linker kept, which is not specified. A function compiled with one value can
    call a function compiled with another, so a single operation can mix both limits.

    Mixing values cannot corrupt the byte per thread that counts the levels of copying and comparing: each limit
    is at most `254`, and all of them stop counting at their own limit, so the count never exceeds `254`, whichever
    translation unit's definition runs. The counter exists once per thread and `basic_json` specialization, and is
    shared by all translation units. Nor can mixing values change any result, as no result depends on the limit. What
    changes is how much stack is used and how fast the operations are. Nevertheless, avoid it: the program has undefined
    behavior as far as the C++ standard is concerned.

## Examples

??? example "Example: lower the limit"

    The example nests an array 5,000 levels deep. With the limit set to 16, the library recurses over the first 16
    levels
    and over the rest uses an explicit stack. The results are those of the default limit.

    ```cpp
    --8<-- "examples/json_recursion_depth_limit.cpp"
    ```

    Output:

    ```
    --8<-- "examples/json_recursion_depth_limit.output"
    ```

??? example "Example: find out how much stack an operation needs"

    The program runs `dump()` on a value nested `depth` levels deep in a thread with a stack of `kib` KiB. Compile it
    with the options and the limit that you use, e.g. `-DJSON_RECURSION_DEPTH_LIMIT=64`, run it with `depth` set to the
    limit plus 10 and decreasing values of `kib` (the stack size must be a multiple of the page size, often 4 or 16
    KiB),
    and note the smallest stack with which it still finishes. That is how the tables above were measured.

    ```cpp
    #include <cstdlib>
    #include <iostream>
    #include <string>
    #include <utility>
    #include <pthread.h>
    #include <nlohmann/json.hpp>

    static nlohmann::json value;

    static void* run(void*)
    {
        std::cout << "dump() ok, " << value.dump().size() << " bytes\n";
        return nullptr;
    }

    int main(int argc, char** argv)
    {
        const int depth = std::atoi(argv[1]);
        const std::size_t kib = static_cast<std::size_t>(std::atoi(argv[2]));

        // built on the main thread, without recursion
        value = 1;
        for (int i = 0; i < depth; ++i)
        {
            nlohmann::json outer = nlohmann::json::array();
            outer.push_back(std::move(value));
            value = std::move(outer);
        }

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, kib * 1024);
        pthread_t thread;
        pthread_create(&thread, &attr, run, nullptr);
        pthread_join(thread, nullptr);
    }
    ```

## See also

- [Nesting depth](../../features/parsing/untrusted_input.md#nesting-depth) - how the library handles deeply nested
  values
- [`JSON_NO_THREAD_LOCAL`](json_no_thread_local.md) - switch off the use of `thread_local` storage
- [Supported Macros](../../features/macros.md) - guide to all supported macros

## Version history

- Added in version 3.13.0.
