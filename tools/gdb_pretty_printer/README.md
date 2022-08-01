# GDB Pretty Printer

File [nlohmann-json.py](nlohmann-json.py) contains a pretty printer for GDB for JSON values of this library. It was originally published as [Gist](https://gist.github.com/ssbssa/60da5339c6e6036b2afce17de06050ea#file-nlohmann-json-py) by [Hannes Domani](https://github.com/ssbssa).

## How to use

- Add line
  
  ```
  source /path/to/nlohmann-json.py
  ```
  
  to `~/.gdbinit`. Note you must replace `/path/to` with whatever path you stored file `nlohmann-json.py`.
- In GDB, debug as usual. When you want to pretty-print a JSON value `var`, type
  
  ```
  p -pretty on -array on -- var
  ```
  
  The result should look like
  
  ```
    $1 = std::map with 5 elements = {
        ["Baptiste"] = std::map with 1 element = {
            ["first"] = "second"
        },
        ["Emmanuel"] = std::vector of length 3, capacity 3 = {
            3,
            "25",
            0.5
        },
        ["Jean"] = 0.7,
        ["Zorg"] = std::map with 8 elements = {
            ["array"] = std::vector of length 3, capacity 3 = {
                1,
                0,
                2
            },
            ["awesome_str"] = "bleh",
            ["bool"] = true,
            ["flex"] = 0.2,
            ["float"] = 5.22,
            ["int"] = 5,
            ["nested"] = std::map with 1 element = {
                ["bar"] = "barz"
            },
            ["trap "] = "you fell"
        },
        ["empty"] = nlohmann::detail::value_t::null
    }
    ```

Requires Python 3.9+. Last tested with GDB 12.1.
See [#1952](https://github.com/nlohmann/json/issues/1952) for more information. Please post questions there.

## Copyright

MIT License

Copyright (C) 2020 [Hannes Domani](https://github.com/ssbssa)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
