#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    auto alloc = json::get_allocator();
    using traits_t = std::allocator_traits<decltype(alloc)>;

    json* j = traits_t::allocate(alloc, 1);
    traits_t::construct(alloc, j, "Hello, world!");

    std::cout << *j << '\n';

    traits_t::destroy(alloc, j);
    traits_t::deallocate(alloc, j, 1);
}
