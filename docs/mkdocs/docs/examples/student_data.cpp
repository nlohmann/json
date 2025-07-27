#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main() {
    // Realistic example: storing student information
    json student = {
        {"name", "Aryan"},
        {"roll_no", 1024},
        {"branch", "CSE"},
        {"marks", {
            {"Math", 85},
            {"Physics", 90},
            {"Chemistry", 78}
        }},
        {"is_enrolled", true}
    };

    std::cout << student.dump(4) << std::endl;
    return 0;
}
