#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON pointers
    json::json_pointer ptr0;
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");

    // different strings
    std::string str0("");
    std::string str1("/foo");
    std::string str2("bar");

    // compare JSON pointers and strings
    std::cout << std::boolalpha
              << "\"" << ptr0 << "\" != \"" << str0 << "\": " << (ptr0 != str0) << '\n'
              << "\"" << str0 << "\" != \"" << ptr1 << "\": " << (str0 != ptr1) << '\n'
              << "\"" << ptr2 << "\" != \"" << str1 << "\": " << (ptr2 != str1) << std::endl;

    try
    {
        std::cout << "\"" << str2 << "\" != \"" << ptr2 << "\": " << (str2 != ptr2) << std::endl;
    }
    catch (const json::parse_error& ex)
    {
        std::cout << ex.what() << std::endl;
    }
}
