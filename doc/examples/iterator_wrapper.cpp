#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    //////////////////////////////////////////////////////////////////////////
    // The static function iterator_wrapper was deprecated in version 3.1.0
    // and will be removed in version 4.0.0. Please replace all occurrences
    // of iterator_wrapper(j) with j.items().
    //////////////////////////////////////////////////////////////////////////

    // example for an object
    for (auto& x : json::iterator_wrapper(j_object))
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }

    // example for an array
    for (auto& x : json::iterator_wrapper(j_array))
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }
}
