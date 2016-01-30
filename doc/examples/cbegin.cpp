#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array value
    const json array = {1, 2, 3, 4, 5};

    // get am iterator to the first element
    json::const_iterator it = array.cbegin();

    // serialize the element that the iterator points to
    std::cout << *it << '\n';
}
