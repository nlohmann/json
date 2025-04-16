#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j1 = {{"one", 1}, {"two", 2}};
    json j2 = {1, 2, 4, 8, 16};

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << '\n';

    // swap values
    std::swap(j1, j2);

    std::cout << "j1 = " << j1 << " | j2 = " << j2 << std::endl;
}
