#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("/foo");
    json::json_pointer ptr2("/foo/0");

    // call empty()
    std::cout << "last reference token of " << ptr1 << " is " << ptr1.back() << '\n'
              << "last reference token of " << ptr2 << " is " << ptr2.back() << std::endl;
}
