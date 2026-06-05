#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON pointers
    json::json_pointer ptr0;
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");

    // compare JSON pointers
    std::cout << std::boolalpha
              << "\"" << ptr0 << "\" == \"" << ptr0 << "\": " << (ptr0 == ptr0) << '\n'
              << "\"" << ptr0 << "\" == \"" << ptr1 << "\": " << (ptr0 == ptr1) << '\n'
              << "\"" << ptr1 << "\" == \"" << ptr2 << "\": " << (ptr1 == ptr2) << '\n'
              << "\"" << ptr2 << "\" == \"" << ptr2 << "\": " << (ptr2 == ptr2) << std::endl;
}
