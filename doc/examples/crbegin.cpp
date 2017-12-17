#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create an array value
    json array = {1, 2, 3, 4, 5};

    // get an iterator to the reverse-beginning
    json::const_reverse_iterator it = array.crbegin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
