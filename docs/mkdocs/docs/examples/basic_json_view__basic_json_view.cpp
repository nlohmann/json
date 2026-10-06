#include <iostream>
#include <nlohmann/json_view.hpp>

int main()
{
    std::cout << std::boolalpha;

    // the default constructor is the only public one: it creates an invalid
    // (discarded) view, useful as a "no value yet" placeholder
    nlohmann::json_view v;
    std::cout << static_cast<bool>(v) << ' ' << v.is_discarded() << '\n';

    // views are trivially copyable handles (two pointers); the document owns
    // the actual data
    nlohmann::json_view copy = v;
    std::cout << static_cast<bool>(copy) << '\n';
}
