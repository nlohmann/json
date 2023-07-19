#include <iostream>
#include <map>
#include <vector>

#include <nlohmann/json.hpp>

class ExampleClass {
private:
    int property1{1};
    double property2{2.5};
    std::string property3{"test"};
    std::map<std::string, int> property4{{"x", 1}, {"y", 2}};
    std::vector<double> property5{1.5, 5.4, 3.2};
public:
    ExampleClass() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(ExampleClass, property1, "comment1", 
                                                           property2, "comment2", 
                                                           property3, "comment3");
};

int main() {
    std::cout << "Hello, world!" << std::endl;
    ExampleClass ec;

    nlohmann::json j = ec;
    std::cout << j.dump_annotated<ExampleClass>() << std::endl;
    return 0;
}