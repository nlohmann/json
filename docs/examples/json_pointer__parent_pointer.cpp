#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");
    json::json_pointer ptr3("/foo/0");

    // call parent_pointer()
    std::cout << std::boolalpha
              << "parent of \"" << ptr1 << "\" is \"" << ptr1.parent_pointer() << "\"\n"
              << "parent of \"" << ptr2 << "\" is \"" << ptr2.parent_pointer() << "\"\n"
              << "parent of \"" << ptr3 << "\" is \"" << ptr3.parent_pointer() << "\"" << std::endl;
}
