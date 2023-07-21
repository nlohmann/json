#include <iostream>
#include <map>
#include <vector>
#include <fstream>

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

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(ExampleClass, property1, "comment两两", 
                                                           property2, "multiline\ncomment2", 
                                                           property3, "comment3",
                                                           property4, "comment4",
                                                           property5, "comment5");
};

class AnotherExampleClass {
private:
    int property1{1};
    double property2{2.5};
    std::string property3{"test"};
    std::map<std::string, int> property4{{"x", 1}, {"y", 2}};
    std::vector<double> property5{1.5, 5.4, 3.2};
public:
    AnotherExampleClass() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(AnotherExampleClass, property1, "comment两", 
                                                                  property2, "multiline\ncomment22", 
                                                                  property3, "comment33",
                                                                  property4, "comment44",
                                                                  property5, "comment55");
};

int main() {
    std::cout << "Hello, world!" << std::endl;
    ExampleClass ec;
    AnotherExampleClass aec;
    std::ofstream example_file;
    example_file.open("/Users/marekpiotrowski/private/json/example.json");

    nlohmann::json j = ec;
    example_file << j.dump_annotated<ExampleClass>(4, ' ', true) << std::endl;

    // nlohmann::json j2 = aec;
    // std::cout << j2.dump_annotated<AnotherExampleClass>() << std::endl;
    return 0;
}