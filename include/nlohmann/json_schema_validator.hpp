//     __ _____ _____ _____
//  |  JSON Schema Validator for Modern C++
//  |  version 1.0.0
//  |  Based on nlohmann/json library
//  |  SPDX-License-Identifier: MIT

#ifndef INCLUDE_NLOHMANN_JSON_SCHEMA_VALIDATOR_HPP_
#define INCLUDE_NLOHMANN_JSON_SCHEMA_VALIDATOR_HPP_

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <regex>
#include <functional>
#include <sstream>

NLOHMANN_JSON_NAMESPACE_BEGIN

class json_schema_validator
{
public:
    struct validation_error
    {
        std::string path;
        std::string keyword;
        std::string message;
        std::string schema_path;

        std::string to_string() const
        {
            std::ostringstream oss;
            oss << "Validation error at '" << path << "': ";
            oss << "[" << keyword << "] " << message;
            if (!schema_path.empty())
            {
                oss << " (schema: " << schema_path << ")";
            }
            return oss.str();
        }
    };

    using error_formatter = std::function<std::string(const validation_error&)>;

    json_schema_validator() = default;

    explicit json_schema_validator(const json& schema)
        : schema_(schema)
    {}

    void set_schema(const json& schema)
    {
        schema_ = schema;
    }

    void set_error_formatter(error_formatter formatter)
    {
        error_formatter_ = std::move(formatter);
    }

    bool validate(const json& data)
    {
        errors_.clear();
        validate_schema(schema_, data, "");
        return errors_.empty();
    }

    bool validate(const json& schema, const json& data)
    {
        schema_ = schema;
        return validate(data);
    }

    const std::vector<validation_error>& get_errors() const
    {
        return errors_;
    }

    std::vector<std::string> get_error_messages() const
    {
        std::vector<std::string> messages;
        messages.reserve(errors_.size());
        for (const auto& error : errors_)
        {
            if (error_formatter_)
            {
                messages.push_back(error_formatter_(error));
            }
            else
            {
                messages.push_back(error.to_string());
            }
        }
        return messages;
    }

    std::string get_error_report() const
    {
        std::ostringstream oss;
        for (const auto& msg : get_error_messages())
        {
            oss << msg << "\n";
        }
        return oss.str();
    }

private:
    json schema_;
    std::vector<validation_error> errors_;
    error_formatter error_formatter_;

    void add_error(const std::string& path, const std::string& keyword,
                   const std::string& message, const std::string& schema_path = "")
    {
        errors_.push_back({path, keyword, message, schema_path});
    }

    void validate_schema(const json& schema, const json& data, const std::string& path)
    {
        if (!schema.is_object())
        {
            return;
        }

        if (schema.contains("type"))
        {
            validate_type(schema, data, path);
        }

        if (schema.contains("properties") && data.is_object())
        {
            validate_properties(schema, data, path);
        }

        if (schema.contains("required") && data.is_object())
        {
            validate_required(schema, data, path);
        }

        if (schema.contains("minimum") || schema.contains("maximum"))
        {
            validate_range(schema, data, path);
        }

        if (schema.contains("pattern") && data.is_string())
        {
            validate_pattern(schema, data, path);
        }

        if (schema.contains("items") && data.is_array())
        {
            validate_items(schema, data, path);
        }

        if (schema.contains("minLength") || schema.contains("maxLength"))
        {
            validate_length(schema, data, path);
        }

        if (schema.contains("enum"))
        {
            validate_enum(schema, data, path);
        }

        if (schema.contains("const"))
        {
            validate_const(schema, data, path);
        }
    }

    void validate_type(const json& schema, const json& data, const std::string& path)
    {
        const auto& type_spec = schema["type"];
        std::string expected_type;

        if (type_spec.is_string())
        {
            expected_type = type_spec.get<std::string>();
            if (!check_type(data, expected_type))
            {
                add_error(path, "type",
                    "expected " + expected_type + ", but got " + get_type_name(data),
                    get_schema_path(schema, "type"));
            }
        }
        else if (type_spec.is_array())
        {
            bool matched = false;
            for (const auto& t : type_spec)
            {
                if (check_type(data, t.get<std::string>()))
                {
                    matched = true;
                    break;
                }
            }
            if (!matched)
            {
                std::string types_str;
                for (size_t i = 0; i < type_spec.size(); ++i)
                {
                    if (i > 0) types_str += ", ";
                    types_str += type_spec[i].get<std::string>();
                }
                add_error(path, "type",
                    "value does not match any of the allowed types: " + types_str,
                    get_schema_path(schema, "type"));
            }
        }
    }

    bool check_type(const json& data, const std::string& type_name)
    {
        if (type_name == "object") return data.is_object();
        if (type_name == "array") return data.is_array();
        if (type_name == "string") return data.is_string();
        if (type_name == "number") return data.is_number();
        if (type_name == "integer") return data.is_number_integer();
        if (type_name == "boolean") return data.is_boolean();
        if (type_name == "null") return data.is_null();
        return false;
    }

    std::string get_type_name(const json& data)
    {
        if (data.is_object()) return "object";
        if (data.is_array()) return "array";
        if (data.is_string()) return "string";
        if (data.is_number_float()) return "number (float)";
        if (data.is_number_integer()) return "integer";
        if (data.is_boolean()) return "boolean";
        if (data.is_null()) return "null";
        return "unknown";
    }

    void validate_properties(const json& schema, const json& data, const std::string& path)
    {
        const auto& properties = schema["properties"];
        for (auto it = properties.begin(); it != properties.end(); ++it)
        {
            const std::string& prop_name = it.key();
            const json& prop_schema = it.value();
            std::string prop_path = path.empty() ? prop_name : path + "." + prop_name;

            if (data.contains(prop_name))
            {
                validate_schema(prop_schema, data[prop_name], prop_path);
            }
        }
    }

    void validate_required(const json& schema, const json& data, const std::string& path)
    {
        const auto& required = schema["required"];
        if (!required.is_array())
        {
            return;
        }

        for (const auto& field : required)
        {
            if (!field.is_string())
            {
                continue;
            }
            std::string field_name = field.get<std::string>();
            if (!data.contains(field_name))
            {
                std::string field_path = path.empty() ? field_name : path + "." + field_name;
                add_error(field_path, "required",
                    "missing required property '" + field_name + "'",
                    get_schema_path(schema, "required"));
            }
        }
    }

    void validate_range(const json& schema, const json& data, const std::string& path)
    {
        if (!data.is_number())
        {
            return;
        }

        double value = data.get<double>();

        if (schema.contains("minimum"))
        {
            double min_val = schema["minimum"].get<double>();
            bool exclusive = schema.value("exclusiveMinimum", false);

            if (exclusive)
            {
                if (value <= min_val)
                {
                    add_error(path, "minimum",
                        "value " + std::to_string(value) + " must be greater than " + std::to_string(min_val),
                        get_schema_path(schema, "minimum"));
                }
            }
            else
            {
                if (value < min_val)
                {
                    add_error(path, "minimum",
                        "value " + std::to_string(value) + " is less than minimum " + std::to_string(min_val),
                        get_schema_path(schema, "minimum"));
                }
            }
        }

        if (schema.contains("maximum"))
        {
            double max_val = schema["maximum"].get<double>();
            bool exclusive = schema.value("exclusiveMaximum", false);

            if (exclusive)
            {
                if (value >= max_val)
                {
                    add_error(path, "maximum",
                        "value " + std::to_string(value) + " must be less than " + std::to_string(max_val),
                        get_schema_path(schema, "maximum"));
                }
            }
            else
            {
                if (value > max_val)
                {
                    add_error(path, "maximum",
                        "value " + std::to_string(value) + " is greater than maximum " + std::to_string(max_val),
                        get_schema_path(schema, "maximum"));
                }
            }
        }
    }

    void validate_pattern(const json& schema, const json& data, const std::string& path)
    {
        if (!data.is_string())
        {
            return;
        }

        std::string pattern_str = schema["pattern"].get<std::string>();
        std::string value = data.get<std::string>();

        try
        {
            std::regex pattern(pattern_str);
            if (!std::regex_search(value, pattern))
            {
                add_error(path, "pattern",
                    "string '" + value + "' does not match pattern '" + pattern_str + "'",
                    get_schema_path(schema, "pattern"));
            }
        }
        catch (const std::regex_error& e)
        {
            add_error(path, "pattern",
                "invalid regex pattern: " + pattern_str + " (" + e.what() + ")",
                get_schema_path(schema, "pattern"));
        }
    }

    void validate_items(const json& schema, const json& data, const std::string& path)
    {
        const auto& items = schema["items"];

        if (items.is_object())
        {
            for (size_t i = 0; i < data.size(); ++i)
            {
                std::string item_path = path + "[" + std::to_string(i) + "]";
                validate_schema(items, data[i], item_path);
            }
        }
        else if (items.is_array())
        {
            for (size_t i = 0; i < items.size() && i < data.size(); ++i)
            {
                std::string item_path = path + "[" + std::to_string(i) + "]";
                validate_schema(items[i], data[i], item_path);
            }
        }
    }

    void validate_length(const json& schema, const json& data, const std::string& path)
    {
        size_t length = 0;

        if (data.is_string())
        {
            length = data.get<std::string>().length();
        }
        else if (data.is_array())
        {
            length = data.size();
        }
        else
        {
            return;
        }

        if (schema.contains("minLength"))
        {
            size_t min_len = schema["minLength"].get<size_t>();
            if (length < min_len)
            {
                add_error(path, "minLength",
                    "length " + std::to_string(length) + " is less than minimum " + std::to_string(min_len),
                    get_schema_path(schema, "minLength"));
            }
        }

        if (schema.contains("maxLength"))
        {
            size_t max_len = schema["maxLength"].get<size_t>();
            if (length > max_len)
            {
                add_error(path, "maxLength",
                    "length " + std::to_string(length) + " is greater than maximum " + std::to_string(max_len),
                    get_schema_path(schema, "maxLength"));
            }
        }
    }

    void validate_enum(const json& schema, const json& data, const std::string& path)
    {
        const auto& enum_values = schema["enum"];
        if (!enum_values.is_array())
        {
            return;
        }

        for (const auto& val : enum_values)
        {
            if (data == val)
            {
                return;
            }
        }

        add_error(path, "enum",
            "value is not one of the allowed enum values",
            get_schema_path(schema, "enum"));
    }

    void validate_const(const json& schema, const json& data, const std::string& path)
    {
        const auto& const_val = schema["const"];
        if (data != const_val)
        {
            add_error(path, "const",
                "value does not match the required constant value",
                get_schema_path(schema, "const"));
        }
    }

    std::string get_schema_path(const json& schema, const std::string& keyword) const
    {
        if (schema.contains("$id"))
        {
            return schema["$id"].get<std::string>() + "#/" + keyword;
        }
        return "#/" + keyword;
    }
};

NLOHMANN_JSON_NAMESPACE_END

#endif
