# Object Order

The [JSON standard](https://tools.ietf.org/html/rfc8259.html) defines objects as "an unordered collection of zero or more name/value pairs". As such, an implementation does not need to preserve any specific order of object keys.

## Default behavior: sort keys

The default type `nlohmann::json` uses a `std::map` to store JSON objects, and thus stores object keys **sorted alphabetically**.

??? example

    ```cpp
    #include <iostream>
    #include "json.hpp"
    
    using json = nlohmann::json;
    
    int main()
    {
        json j;
        j["one"] = 1;
        j["two"] = 2;
        j["three"] = 3;
        
        std::cout << j.dump(2) << '\n';
    }
    ```
    
    Output:

    ```json
    {
      "one": 1,
      "three": 3,
      "two": 2
    }
    ```

## Alternative behavior: preserve insertion order

If you do want to preserve the **insertion order**, you can try the type [`nlohmann::ordered_json`](https://github.com/nlohmann/json/issues/2179).

??? example

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using ordered_json = nlohmann::ordered_json;
    
    int main()
    {
        ordered_json j;
        j["one"] = 1;
        j["two"] = 2;
        j["three"] = 3;
        
        std::cout << j.dump(2) << '\n';
    }
    ```
    
    Output:
    
    ```json
    {
      "one": 1,
      "two": 2,
      "three": 3
    }
    ```

Alternatively, you can use a more sophisticated ordered map like [`tsl::ordered_map`](https://github.com/Tessil/ordered-map) ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)) or [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map) ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)).

### Notes on parsing

Note that you also need to call the right [`parse`](../api/basic_json/parse.md) function when reading from a file.
Assume file `input.json` contains the JSON object above:

```json
{
  "one": 1,
  "two": 2,
  "three": 3
}
```

!!! success "Right way"

    The following code correctly calls the `parse` function from `nlohmann::ordered_json`:

    ```cpp
    std::ifstream i("input.json");
    auto j = nlohmann::ordered_json::parse(i);
    std::cout << j.dump(2) << std::endl;
    ```

    The output will be:

    ```json
    {
      "one": 1,
      "two": 2,
      "three": 3
    }
    ```

??? failure "Wrong way"

    The following code incorrectly calls the `parse` function from `nlohmann::json` which does not preserve the
    insertion order, but sorts object keys. Assigning the result to `nlohmann::ordered_json` compiles, but does not
    restore the order from the input file.

    ```cpp
    std::ifstream i("input.json");
    nlohmann::ordered_json j = nlohmann::json::parse(i);
    std::cout << j.dump(2) << std::endl;
    ```

    The output will be:

    ```json
    {
      "one": 1,
      "three": 3
      "two": 2,
    }
    ```
