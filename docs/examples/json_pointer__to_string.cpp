#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // different JSON Pointers
    json::json_pointer ptr1("");
    json::json_pointer ptr2("/foo");
    json::json_pointer ptr3("/foo/0");
    json::json_pointer ptr4("/");
    json::json_pointer ptr5("/a~1b");
    json::json_pointer ptr6("/c%d");
    json::json_pointer ptr7("/e^f");
    json::json_pointer ptr8("/g|h");
    json::json_pointer ptr9("/i\\j");
    json::json_pointer ptr10("/k\"l");
    json::json_pointer ptr11("/ ");
    json::json_pointer ptr12("/m~0n");

    std::cout << ptr1.to_string() << '\n'
              << ptr2.to_string() << '\n'
              << ptr3.to_string() << '\n'
              << ptr4.to_string() << '\n'
              << ptr5.to_string() << '\n'
              << ptr6.to_string() << '\n'
              << ptr7.to_string() << '\n'
              << ptr8.to_string() << '\n'
              << ptr9.to_string() << '\n'
              << ptr10.to_string() << '\n'
              << ptr11.to_string() << '\n'
              << ptr12.to_string() << std::endl;
}
