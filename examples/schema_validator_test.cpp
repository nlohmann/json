#include <iostream>
#include <nlohmann/json.hpp>
#include <nlohmann/json_schema_validator.hpp>

using json = nlohmann::json;
using validator = nlohmann::json_schema_validator;

void test_basic_validation()
{
    std::cout << "========================================\n";
    std::cout << "Test 1: Basic Validation (User Example)\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "pattern": "^[A-Z]"},
                "age": {"type": "integer", "minimum": 0, "maximum": 150}
            },
            "required": ["name"]
        }
    )"_json;

    json data = R"(
        {
            "name": "john",
            "age": 200
        }
    )"_json;

    std::cout << "Schema:\n" << schema.dump(2) << "\n\n";
    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_nested_objects()
{
    std::cout << "========================================\n";
    std::cout << "Test 2: Nested Object Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "profile": {
                            "type": "object",
                            "properties": {
                                "age": {"type": "integer", "minimum": 0, "maximum": 120},
                                "email": {"type": "string", "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}
                            },
                            "required": ["age"]
                        }
                    },
                    "required": ["name"]
                }
            },
            "required": ["user"]
        }
    )"_json;

    json data = R"(
        {
            "user": {
                "name": "Alice",
                "profile": {
                    "age": 150,
                    "email": "invalid-email"
                }
            }
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - Path: " << error.path << "\n";
            std::cout << "    Keyword: " << error.keyword << "\n";
            std::cout << "    Message: " << error.message << "\n\n";
        }
    }
}

void test_array_validation()
{
    std::cout << "========================================\n";
    std::cout << "Test 3: Array Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "scores": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 0, "maximum": 100}
                }
            }
        }
    )"_json;

    json data = R"(
        {
            "tags": ["developer", 123, "tester"],
            "scores": [85, 95, -5, 150]
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_required_fields()
{
    std::cout << "========================================\n";
    std::cout << "Test 4: Required Fields Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "email": {"type": "string"}
            },
            "required": ["id", "name"]
        }
    )"_json;

    json data = R"(
        {
            "email": "test@example.com"
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_type_validation()
{
    std::cout << "========================================\n";
    std::cout << "Test 5: Type Validation (Multiple Types)\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "value": {"type": ["string", "integer"]},
                "flag": {"type": "boolean"},
                "count": {"type": "integer"}
            }
        }
    )"_json;

    json data = R"(
        {
            "value": 3.14,
            "flag": "true",
            "count": "ten"
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_string_length()
{
    std::cout << "========================================\n";
    std::cout << "Test 6: String Length Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 20},
                "password": {"type": "string", "minLength": 8}
            }
        }
    )"_json;

    json data = R"(
        {
            "username": "ab",
            "password": "123"
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_enum_and_const()
{
    std::cout << "========================================\n";
    std::cout << "Test 7: Enum and Const Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "status": {"enum": ["active", "inactive", "pending"]},
                "version": {"const": "1.0"}
            }
        }
    )"_json;

    json data = R"(
        {
            "status": "unknown",
            "version": "2.0"
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

void test_custom_error_formatter()
{
    std::cout << "========================================\n";
    std::cout << "Test 8: Custom Error Formatter\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 2},
                "age": {"type": "integer", "minimum": 0}
            },
            "required": ["name", "age"]
        }
    )"_json;

    json data = R"(
        {
            "name": "A",
            "age": -1
        }
    )"_json;

    validator v(schema);

    v.set_error_formatter([](const validator::validation_error& err) {
        std::string severity = (err.keyword == "required") ? "CRITICAL" : "ERROR";
        return "[" + severity + "] Field '" + err.path + "': " + err.message;
    });

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    bool is_valid = v.validate(data);
    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Custom Formatted Errors:\n";
        for (const auto& msg : v.get_error_messages())
        {
            std::cout << "  " << msg << "\n";
        }
    }
    std::cout << "\n";
}

void test_valid_data()
{
    std::cout << "========================================\n";
    std::cout << "Test 9: Valid Data (Should Pass)\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "pattern": "^[A-Z]"},
                "age": {"type": "integer", "minimum": 0, "maximum": 150},
                "email": {"type": "string", "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}
            },
            "required": ["name", "age"]
        }
    )"_json;

    json data = R"(
        {
            "name": "John",
            "age": 30,
            "email": "john@example.com"
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (is_valid)
    {
        std::cout << "All validations passed successfully!\n";
    }
    std::cout << "\n";
}

void test_exclusive_range()
{
    std::cout << "========================================\n";
    std::cout << "Test 10: Exclusive Range Validation\n";
    std::cout << "========================================\n\n";

    json schema = R"(
        {
            "type": "object",
            "properties": {
                "percentage": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "exclusiveMinimum": true,
                    "exclusiveMaximum": true
                }
            }
        }
    )"_json;

    json data = R"(
        {
            "percentage": 0
        }
    )"_json;

    std::cout << "Data:\n" << data.dump(2) << "\n\n";
    std::cout << "Note: percentage must be > 0 and < 100 (exclusive)\n\n";

    validator v(schema);
    bool is_valid = v.validate(data);

    std::cout << "Result: " << (is_valid ? "VALID" : "INVALID") << "\n\n";

    if (!is_valid)
    {
        std::cout << "Errors:\n";
        for (const auto& error : v.get_errors())
        {
            std::cout << "  - " << error.to_string() << "\n";
        }
    }
    std::cout << "\n";
}

int main()
{
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        JSON Schema Validator - Test Suite                  ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n\n";

    test_basic_validation();
    test_nested_objects();
    test_array_validation();
    test_required_fields();
    test_type_validation();
    test_string_length();
    test_enum_and_const();
    test_custom_error_formatter();
    test_valid_data();
    test_exclusive_range();

    std::cout << "========================================\n";
    std::cout << "All tests completed!\n";
    std::cout << "========================================\n";

    return 0;
}
