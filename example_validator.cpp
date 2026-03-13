#include <iostream>
#include "json_schema_validator.hpp"

using json = nlohmann::json;
using namespace nlohmann;

void print_result(const ValidationResult& result) {
    if (result.is_valid()) {
        std::cout << "✓ Validation passed!" << std::endl;
    } else {
        std::cout << "✗ Validation failed:" << std::endl;
        for (const auto& error : result.errors()) {
            std::cout << "  - Path: " << (error.path.empty() ? "<root>" : error.path) << std::endl;
            std::cout << "    Message: " << error.message << std::endl;
            std::cout << "    Keyword: " << error.keyword << std::endl;
        }
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "JSON Schema Validator Demo" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;

    // 示例 1: 基本验证（用户提供的示例）
    std::cout << "--- Example 1: Basic Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "name": {"type": "string", "pattern": "^[A-Z]"},
                "age": {"type": "integer", "minimum": 0, "maximum": 150}
            },
            "required": ["name"]
        })"_json;

        json data = R"({"name": "john", "age": 200})"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        auto result = validator.validate(data);
        print_result(result);
    }

    // 示例 2: 修复数据后的验证
    std::cout << "--- Example 2: Fixed Data Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "name": {"type": "string", "pattern": "^[A-Z]"},
                "age": {"type": "integer", "minimum": 0, "maximum": 150}
            },
            "required": ["name"]
        })"_json;

        json data = R"({"name": "John", "age": 25})"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        auto result = validator.validate(data);
        print_result(result);
    }

    // 示例 3: 嵌套对象验证
    std::cout << "--- Example 3: Nested Object Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "minimum": 1},
                        "email": {"type": "string", "pattern": "^[^@]+@[^@]+$"}
                    },
                    "required": ["id", "email"]
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1}
                }
            },
            "required": ["user"]
        })"_json;

        // 无效数据 - email 格式错误
        json invalid_data = R"({
            "user": {
                "id": 123,
                "email": "invalid-email"
            },
            "tags": ["important", ""]
        })"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << invalid_data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        auto result = validator.validate(invalid_data);
        print_result(result);
    }

    // 示例 4: 类型验证
    std::cout << "--- Example 4: Type Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "price": {"type": "number"},
                "name": {"type": "string"},
                "active": {"type": "boolean"},
                "metadata": {"type": ["object", "null"]}
            }
        })"_json;

        json data = R"({
            "count": 10,
            "price": 19.99,
            "name": "Product",
            "active": true,
            "metadata": null
        })"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        auto result = validator.validate(data);
        print_result(result);
    }

    // 示例 5: 数组验证
    std::cout << "--- Example 5: Array Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "value": {"type": "string"}
                },
                "required": ["id", "value"]
            }
        })"_json;

        json data = R"([
            {"id": 1, "value": "first"},
            {"id": 2, "value": "second"},
            {"id": 3}
        ])"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        auto result = validator.validate(data);
        print_result(result);
    }

    // 示例 6: 自定义错误格式化
    std::cout << "--- Example 6: Custom Error Formatter ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "username": {"type": "string", "minLength": 3, "maxLength": 20},
                "age": {"type": "integer", "minimum": 18, "maximum": 120}
            },
            "required": ["username", "age"]
        })"_json;

        json data = R"({
            "username": "ab",
            "age": 15
        })"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << "Data:   " << data.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        
        // 设置自定义错误格式化器
        validator.set_error_formatter([](const ValidationError& err) -> std::string {
            std::ostringstream oss;
            oss << "[ERROR] Field '" << err.path << "' failed validation" << std::endl;
            oss << "        Keyword: " << err.keyword << std::endl;
            oss << "        Details: " << err.message;
            return oss.str();
        });

        auto result = validator.validate(data);
        std::cout << "Custom formatted errors:" << std::endl;
        for (const auto& error : result.errors()) {
            std::cout << error.to_string() << std::endl;
        }
        std::cout << std::endl;
    }

    // 示例 7: 枚举验证
    std::cout << "--- Example 7: Enum Validation ---" << std::endl;
    {
        json schema = R"({
            "type": "object",
            "properties": {
                "status": {"enum": ["pending", "active", "inactive"]}
            }
        })"_json;

        json valid_data = R"({"status": "active"})"_json;
        json invalid_data = R"({"status": "deleted"})"_json;

        std::cout << "Schema: " << schema.dump(2) << std::endl;
        std::cout << std::endl;

        SchemaValidator validator(schema);
        
        std::cout << "Valid data: " << valid_data.dump() << std::endl;
        auto result1 = validator.validate(valid_data);
        print_result(result1);

        std::cout << "Invalid data: " << invalid_data.dump() << std::endl;
        auto result2 = validator.validate(invalid_data);
        print_result(result2);
    }

    std::cout << "========================================" << std::endl;
    std::cout << "All examples completed!" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
