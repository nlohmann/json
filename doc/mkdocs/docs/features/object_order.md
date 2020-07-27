# Object Order

The [JSON standard](https://tools.ietf.org/html/rfc8259.html) defines objects as "an unordered collection of zero or more name/value pairs". As such, an implementation does not need to preserve any specific order of object keys.

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
