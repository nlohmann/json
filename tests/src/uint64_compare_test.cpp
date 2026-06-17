#include <cstdint>
#include <iostream>
#include <limits>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    const json a = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1ULL;
    const json b = (std::numeric_limits<std::uint64_t>::max)();
    const json neg = -1;

    std::cout << std::boolalpha;
    std::cout << "a == -1: " << (a == neg) << '\n';
    std::cout << "-1 < a : " << (neg < a) << '\n';
    std::cout << "b == -1: " << (b == neg) << '\n';
    std::cout << "-1 < b : " << (neg < b) << '\n';
}
