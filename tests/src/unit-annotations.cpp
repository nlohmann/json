#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

namespace {
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
                                                           property3, "comment3",
                                                           property4, "comment4",
                                                           property5, "comment5");
};

class AnotherExampleClass {
private:
    int property1{11};
    double property2{25.5};
public:
    AnotherExampleClass() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(AnotherExampleClass, property1, "comment11", 
                                                                  property2, "comment22");
};

class MultiLineAnnotationExampleClass {
private:
    int property1{11};
    std::string property2{"test"};
public:
    MultiLineAnnotationExampleClass() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(MultiLineAnnotationExampleClass, property1, "multiline\ncomment11", 
                                                                              property2, "multiline\ncomment22");
};
}

TEST_CASE("annotation")
{
    SECTION("canonical")
    {
        ExampleClass ex;
        nlohmann::json j = ex;
        const auto ex_actual_json = j.dump_annotated<decltype(ex)>(4, ' ', true);
        const auto expected_json = "{\n"
        "    /* comment1 */\n"
        "    \"property1\": 1,\n"
        "    /* comment2 */\n"
        "    \"property2\": 2.5,\n"
        "    /* comment3 */\n"
        "    \"property3\": \"test\",\n"
        "    /* comment4 */\n"
        "    \"property4\": {\n"
        "        \"x\": 1,\n"
        "        \"y\": 2\n"
        "    },\n"
        "    /* comment5 */\n"
        "    \"property5\": [\n"
        "        1.5,\n"
        "        5.4,\n"
        "        3.2\n"
        "    ]\n"
        "}";
        CHECK(ex_actual_json == expected_json);
    }
    SECTION("macro_does_not_pollute_global_scope")
    {
        ExampleClass ex;
        AnotherExampleClass another_ex;
        nlohmann::json j1 = ex;
        nlohmann::json j2 = another_ex;
        const auto another_ex_actual_json = j2.dump_annotated<AnotherExampleClass>(4, ' ', true);
        const auto expected_json = "{\n"
        "    /* comment11 */\n"
        "    \"property1\": 11,\n"
        "    /* comment22 */\n"
        "    \"property2\": 25.5\n"
        "}";
        CHECK(another_ex_actual_json == expected_json);
    }
    SECTION("multi_line_annotation")
    {
        MultiLineAnnotationExampleClass ex;
        nlohmann::json j = ex;
        const auto ex_actual_json = j.dump_annotated<MultiLineAnnotationExampleClass>(4, ' ', true);
        const auto expected_json = "{\n"
        "    /* multiline */\n"
        "    /* comment11 */\n"
        "    \"property1\": 11,\n"
        "    /* multiline */\n"
        "    /* comment22 */\n"
        "    \"property2\": \"test\"\n"
        "}";
        CHECK(ex_actual_json == expected_json);
    }
    SECTION("utf8_comment_not_ascii")
    {
        // TODO
    }
    SECTION("utf8_comment_ensure_ascii")
    {
        // TODO
    }
}