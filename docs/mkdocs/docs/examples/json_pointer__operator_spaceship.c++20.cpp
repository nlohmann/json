#include <compare>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

const char* to_string(const std::strong_ordering& so)
{
    if (std::is_lt(so))
    {
        return "less";
    }
    else if (std::is_gt(so))
    {
        return "greater";
    }
    return "equal";
}

int main()
{
    // different JSON pointers
    json::json_pointer ptr1("/a/b");
    json::json_pointer ptr2("/a/c");
    json::json_pointer ptr3("/a/b/c");
    json::json_pointer ptr4("/a/b");

    // 3-way compare JSON pointers
    std::cout << "\"" << ptr1 << "\" <=> \"" << ptr2 << "\": " << to_string(ptr1 <=> ptr2) << '\n' // *NOPAD*
              << "\"" << ptr1 << "\" <=> \"" << ptr3 << "\": " << to_string(ptr1 <=> ptr3) << '\n' // *NOPAD*
              << "\"" << ptr1 << "\" <=> \"" << ptr4 << "\": " << to_string(ptr1 <=> ptr4) << std::endl; // *NOPAD*
}
