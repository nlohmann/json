#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr0;
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");
    json::json_pointer ptr3("/foo/0");

    // call empty()
    std::cout << std::boolalpha
              << "\"" << ptr0 << "\": " << ptr0.empty() << '\n'
              << "\"" << ptr1 << "\": " << ptr1.empty() << '\n'
              << "\"" << ptr2 << "\": " << ptr2.empty() << '\n'
              << "\"" << ptr3 << "\": " << ptr3.empty() << std::endl;
}
