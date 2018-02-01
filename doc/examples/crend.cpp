#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the reverse-end
    json::const_reverse_iterator it = array.crend();

    // increment the iterator to point to the first element
    --it;

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
