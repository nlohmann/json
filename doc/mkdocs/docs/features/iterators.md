# Iterators

## Overview

A JSON value is a container and allows access via iterators. 

![](../images/range-begin-end.svg)

![](../images/range-rbegin-rend.svg)

## Iterator getters

### `begin()`

??? example

    The following code shows an example for `begin()`.

    ```cpp
    --8<-- "examples/begin.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/begin.output"
    ```

### `cbegin()`

??? example

    The following code shows an example for `cbegin()`.

    ```cpp
    --8<-- "examples/cbegin.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/cbegin.output"
    ```

### `end()`

??? example

    The following code shows an example for `end()`.

    ```cpp
    --8<-- "examples/end.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/end.output"
    ```

### `cend()`

??? example

    The following code shows an example for `cend()`.

    ```cpp
    --8<-- "examples/cend.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/cend.output"
    ```

### `rbegin()`

??? example

    The following code shows an example for `rbegin()`.

    ```cpp
    --8<-- "examples/rbegin.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/rbegin.output"
    ```

### `rend()`

??? example

    The following code shows an example for `rend()`.

    ```cpp
    --8<-- "examples/rend.cpp"
    ```
    
    Output:

    ```json
    --8<-- "examples/rend.output"
    ```

### `items()`

??? example

    The following code shows an example for `items()`.

    ```cpp
    --8<-- "examples/items.cpp"
    ```
    
    Output:

    ```
    --8<-- "examples/items.output"
    ```

## Iterator invalidation

| Operations | invalidated iterators |
| ---------- | --------------------- |
| `clear`    | all                   |
