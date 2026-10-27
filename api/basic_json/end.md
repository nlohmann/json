# <small>nlohmann::basic_json::</small>end

```cpp
iterator end() noexcept;
const_iterator end() const noexcept;
```

Returns an iterator to one past the last element.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-fig--range" viewBox="0 0 600 150" role="img" aria-labelledby="fig-be-title" xmlns="http://www.w3.org/2000/svg">
<title id="fig-be-title">A row of fifteen elements followed by a dashed past-the-last position. begin() points to the first element and end() points to the past-the-last position.</title>
<defs><marker id="fig-be-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>
<rect class="fg-cell" x="30" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="64" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="98" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="132" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="166" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="200" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="234" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="268" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="302" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="336" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="370" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="404" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="438" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="472" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell" x="506" y="62" width="30" height="30" rx="5"/>
<rect class="fg-cell fg-cell--end" x="540" y="62" width="30" height="30" rx="5"/>
<rect class="fg-pill" x="15" y="8" width="60" height="24" rx="6"/>
<text class="fg-pilltext" x="45" y="24">begin</text>
<line class="fg-arrow" x1="45" y1="32" x2="45" y2="60" marker-end="url(#fig-be-arrow)"/>
<rect class="fg-pill" x="531" y="8" width="48" height="24" rx="6"/>
<text class="fg-pilltext" x="555" y="24">end</text>
<line class="fg-arrow" x1="555" y1="32" x2="555" y2="60" marker-end="url(#fig-be-arrow)"/>
<text class="fg-note fg-note--r" x="537" y="132">Past-the-last element</text>
<line class="fg-arrow" x1="555" y1="124" x2="555" y2="96" marker-end="url(#fig-be-arrow)"/>
</svg>

</div>

<p class="nj-caption" markdown>`end()` points to the position after the last element and `begin()` to the first element;
the dashed cell is the past-the-last position, which must not be dereferenced.</p>

## Return value

iterator one past the last element

## Exception safety

No-throw guarantee: this member function never throws exceptions.

## Complexity

Constant.

## Examples

??? example

    The following code shows an example for `end()`.
    
    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create an array value
        json array = {1, 2, 3, 4, 5};
    
        // get an iterator to one past the last element
        json::iterator it = array.end();
    
        // decrement the iterator to point to the last element
        --it;
    
        // serialize the element that the iterator points to
        std::cout << *it << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    5
    
    ```

## See also

- [`begin`](begin.md) - returns an iterator to the first element
- [`cend`](cend.md) - returns a const iterator to one past the last element
- [`rend`](rend.md) - returns a reverse iterator to one before the first element
- [Iterators](../../features/iterators.md) - the article on iterators
- [`basic_json_view::end`](../basic_json_view/end.md) - the same iteration on a zero-copy view

## Version history

- Added in version 1.0.0.
