#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text given as string that is not null-terminated
    const char* ptr = "[1,2,3]another value";

    // parse and serialize JSON
    json j_complete = json::parse(ptr, ptr + 7);
    std::cout << std::setw(4) << j_complete << "\n\n";
}
