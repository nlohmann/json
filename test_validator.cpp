#include <iostream>
#include "json_schema_validator.hpp"

void test_basic_example() {
    std::cout << "=== Test 1: Basic Example from User ===" << std::endl;
    
    json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"pattern", "^[A-Z]"}}},
            {"age", {{"type", "integer"}, {"minimum", 0}, {"maximum", 150}}}
        }},
        {"required", {"name"}}
    };
    
    json data = {{"name", "john"}, {"age", 200}};
    
    JsonSchemaValidator validator;
    validator.set_schema(schema);
    
    bool result = validator.validate(data);
    std::cout << "Validation result: " << (result ? "PASS" : "FAIL") << std::endl;
    
    if (!result) {
        std::cout << "Errors:" << std::endl;
        for (const auto& err : validator.get_formatted_errors()) {
            std::cout << "  " << err << std::endl;
        }
    }
}

void test_valid_data() {
    std::cout << "\n=== Test 2: Valid Data ===" << std::endl;
    
    json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"pattern", "^[A-Z]"}}},
            {"age", {{"type", "integer"}, {"minimum", 0}, {"maximum", 150}}}
        }},
        {"required", {"name"}}
    };
    
    json data = {{"name", "John"}, {"age", 30}};
    
    JsonSchemaValidator validator;
    validator.set_schema(schema);
    
    bool result = validator.validate(data);
    std::cout << "Validation result: " << (result ? "PASS" : "FAIL") << std::endl;
}

void test_nested_object() {
    std::cout << "\n=== Test 3: Nested Object Validation ===" << std::endl;
    
    json schema = {
        {"type", "object"},
        {"properties", {
            {"user", {
                {"type", "object"},
                {"properties", {
                    {"email", {{"type", "string"}}},
                    {"profile", {
                        {"type", "object"},
                        {"properties", {
                            {"age", {{"type", "integer"}, {"minimum", 0}}}
                        }}
                    }}
                }}
            }}
        }}
    };
    
    json data = {
        {"user", {
            {"email", "test@example.com"},
            {"profile", {
                {"age", -5}
            }}
        }}
    };
    
    JsonSchemaValidator validator;
    validator.set_schema(schema);
    
    bool result = validator.validate(data);
    std::cout << "Validation result: " << (result ? "PASS" : "FAIL") << std::endl;
    
    if (!result) {
        for (const auto& err : validator.get_formatted_errors()) {
            std::cout << "  " << err << std::endl;
        }
    }
}

void test_required_field() {
    std::cout << "\n=== Test 4: Required Field ===" << std::endl;
    
    json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}}}
        }},
        {"required", {"name"}}
    };
    
    json data = {{"age", 30}};
    
    JsonSchemaValidator validator;
    validator.set_schema(schema);
    
    bool result = validator.validate(data);
    std::cout << "Validation result: " << (result ? "PASS" : "FAIL") << std::endl;
    
    if (!result) {
        for (const auto& err : validator.get_formatted_errors()) {
            std::cout << "  " << err << std::endl;
        }
    }
}

void test_custom_error_formatter() {
    std::cout << "\n=== Test 5: Custom Error Formatter ===" << std::endl;
    
    json schema = {
        {"type", "object"},
        {"properties", {
            {"age", {{"type", "integer"}, {"minimum", 0}}}
        }}
    };
    
    json data = {{"age", -10}};
    
    JsonSchemaValidator validator;
    validator.set_schema(schema);
    validator.set_error_formatter([](const ValidationError& err) {
        return "Error at '" + err.path + "': " + err.message;
    });
    
    bool result = validator.validate(data);
    std::cout << "Validation result: " << (result ? "PASS" : "FAIL") << std::endl;
    
    if (!result) {
        for (const auto& err : validator.get_formatted_errors()) {
            std::cout << "  " << err << std::endl;
        }
    }
}

int main() {
    test_basic_example();
    test_valid_data();
    test_nested_object();
    test_required_field();
    test_custom_error_formatter();
    
    std::cout << "\n=== All tests completed ===" << std::endl;
    return 0;
}
