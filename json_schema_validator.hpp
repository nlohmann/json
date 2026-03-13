#pragma once

#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

// namespace nlohmann/jsons
namespace nlohmann {

struct ValidationError {
    std::string path;
    std::string message;
    std::string keyword;
    
    ValidationError(const std::string& p, const std::string& m, const std::string& k = "")
        : path(p), message(m), keyword(k) {}
    
    std::string to_string() const {
        std::ostringstream oss;
        if (!path.empty()) {
            oss << "[" << path << "] ";
        }
        oss << message;
        return oss.str();
    }
};

class ValidationResult {
public:
    bool is_valid() const { return errors_.empty(); }
    
    const std::vector<ValidationError>& errors() const { return errors_; }
    
    void add_error(const std::string& path, const std::string& message, const std::string& keyword = "") {
        errors_.emplace_back(path, message, keyword);
    }
    
    void merge(const ValidationResult& other, const std::string& prefix = "") {
        for (const auto& err : other.errors_) {
            std::string full_path = prefix.empty() ? err.path : (prefix + "." + err.path);
            errors_.emplace_back(full_path, err.message, err.keyword);
        }
    }
    
    std::string to_string() const {
        if (is_valid()) {
            return "Validation passed";
        }
        std::ostringstream oss;
        oss << "Validation failed with " << errors_.size() << " error(s):\n";
        for (const auto& err : errors_) {
            oss << "  - " << err.to_string() << "\n";
        }
        return oss.str();
    }
    
private:
    std::vector<ValidationError> errors_;
};

using ErrorFormatter = std::function<std::string(const ValidationError&)>;

class SchemaValidator {
public:
    SchemaValidator() = default;
    
    explicit SchemaValidator(const json& schema) : schema_(schema) {}
    
    void set_schema(const json& schema) {
        schema_ = schema;
    }
    
    void set_error_formatter(ErrorFormatter formatter) {
        error_formatter_ = formatter;
    }
    
    ValidationResult validate(const json& data) const {
        return validate_value(data, schema_, "");
    }
    
    ValidationResult validate(const json& data, const json& schema) const {
        return validate_value(data, schema, "");
    }

private:
    json schema_;
    ErrorFormatter error_formatter_;
    
    std::string format_error(const ValidationError& err) const {
        if (error_formatter_) {
            return error_formatter_(err);
        }
        return err.to_string();
    }
    
    ValidationResult validate_value(const json& data, const json& schema, const std::string& path) const {
        ValidationResult result;
        
        if (!schema.is_object()) {
            result.add_error(path, "Schema must be an object", "schema");
            return result;
        }
        
        // Validate type
        if (schema.contains("type")) {
            auto type_result = validate_type(data, schema["type"], path);
            if (!type_result.is_valid()) {
                result.merge(type_result);
                return result;
            }
        }
        
        // Validate properties (for object type)
        if (schema.contains("properties") && data.is_object()) {
            auto props_result = validate_properties(data, schema["properties"], path);
            result.merge(props_result);
        }
        
        // Validate required fields
        if (schema.contains("required") && data.is_object()) {
            auto required_result = validate_required(data, schema["required"], path);
            result.merge(required_result);
        }
        
        // Validate items (for array type)
        if (schema.contains("items") && data.is_array()) {
            auto items_result = validate_items(data, schema["items"], path);
            result.merge(items_result);
        }
        
        // Validate minimum/maximum (for number type)
        if (data.is_number()) {
            if (schema.contains("minimum")) {
                auto min_result = validate_minimum(data, schema["minimum"], path);
                result.merge(min_result);
            }
            if (schema.contains("maximum")) {
                auto max_result = validate_maximum(data, schema["maximum"], path);
                result.merge(max_result);
            }
        }
        
        // Validate pattern (for string type)
        if (schema.contains("pattern") && data.is_string()) {
            auto pattern_result = validate_pattern(data, schema["pattern"], path);
            result.merge(pattern_result);
        }
        
        // Validate minLength/maxLength (for string type)
        if (data.is_string()) {
            if (schema.contains("minLength")) {
                auto minlen_result = validate_minlength(data, schema["minLength"], path);
                result.merge(minlen_result);
            }
            if (schema.contains("maxLength")) {
                auto maxlen_result = validate_maxlength(data, schema["maxLength"], path);
                result.merge(maxlen_result);
            }
        }
        
        // Validate enum
        if (schema.contains("enum")) {
            auto enum_result = validate_enum(data, schema["enum"], path);
            result.merge(enum_result);
        }
        
        return result;
    }
    
    ValidationResult validate_type(const json& data, const json& type_spec, const std::string& path) const {
        ValidationResult result;
        
        if (type_spec.is_string()) {
            std::string type = type_spec.get<std::string>();
            if (!check_type(data, type)) {
                result.add_error(path, 
                    "Expected type '" + type + "' but got '" + json_type_to_string(data.type()) + "'", 
                    "type");
            }
        } else if (type_spec.is_array()) {
            bool matched = false;
            std::vector<std::string> types;
            for (const auto& t : type_spec) {
                if (t.is_string()) {
                    std::string type = t.get<std::string>();
                    types.push_back(type);
                    if (check_type(data, type)) {
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                std::ostringstream oss;
                oss << "Expected one of types [";
                for (size_t i = 0; i < types.size(); ++i) {
                    if (i > 0) oss << ", ";
                    oss << "'" << types[i] << "'";
                }
                oss << "] but got '" << json_type_to_string(data.type()) << "'";
                result.add_error(path, oss.str(), "type");
            }
        }
        
        return result;
    }
    
    bool check_type(const json& data, const std::string& type) const {
        if (type == "object") return data.is_object();
        if (type == "array") return data.is_array();
        if (type == "string") return data.is_string();
        if (type == "integer") return data.is_number_integer();
        if (type == "number") return data.is_number();
        if (type == "boolean") return data.is_boolean();
        if (type == "null") return data.is_null();
        return false;
    }
    
    std::string json_type_to_string(json::value_t type) const {
        switch (type) {
            case json::value_t::object: return "object";
            case json::value_t::array: return "array";
            case json::value_t::string: return "string";
            case json::value_t::boolean: return "boolean";
            case json::value_t::number_integer: return "integer";
            case json::value_t::number_unsigned: return "integer";
            case json::value_t::number_float: return "number";
            case json::value_t::null: return "null";
            case json::value_t::binary: return "binary";
            case json::value_t::discarded: return "discarded";
            default: return "unknown";
        }
    }
    
    ValidationResult validate_properties(const json& data, const json& properties, const std::string& path) const {
        ValidationResult result;
        
        if (!properties.is_object()) {
            result.add_error(path, "'properties' must be an object", "properties");
            return result;
        }
        
        for (auto& [key, subschema] : properties.items()) {
            if (data.contains(key)) {
                std::string new_path = path.empty() ? key : (path + "." + key);
                auto sub_result = validate_value(data[key], subschema, new_path);
                result.merge(sub_result);
            }
        }
        
        return result;
    }
    
    ValidationResult validate_required(const json& data, const json& required, const std::string& path) const {
        ValidationResult result;
        
        if (!required.is_array()) {
            result.add_error(path, "'required' must be an array", "required");
            return result;
        }
        
        for (const auto& field : required) {
            if (field.is_string()) {
                std::string field_name = field.get<std::string>();
                if (!data.contains(field_name)) {
                    result.add_error(path, "Missing required field '" + field_name + "'", "required");
                }
            }
        }
        
        return result;
    }
    
    ValidationResult validate_items(const json& data, const json& items_schema, const std::string& path) const {
        ValidationResult result;
        
        for (size_t i = 0; i < data.size(); ++i) {
            std::string item_path = path + "[" + std::to_string(i) + "]";
            auto item_result = validate_value(data[i], items_schema, item_path);
            result.merge(item_result);
        }
        
        return result;
    }
    
    ValidationResult validate_minimum(const json& data, const json& minimum, const std::string& path) const {
        ValidationResult result;
        
        double min_val = minimum.get<double>();
        double data_val = data.get<double>();
        
        if (data_val < min_val) {
            result.add_error(path, 
                "Value " + std::to_string(data_val) + " is less than minimum " + std::to_string(min_val), 
                "minimum");
        }
        
        return result;
    }
    
    ValidationResult validate_maximum(const json& data, const json& maximum, const std::string& path) const {
        ValidationResult result;
        
        double max_val = maximum.get<double>();
        double data_val = data.get<double>();
        
        if (data_val > max_val) {
            result.add_error(path, 
                "Value " + std::to_string(data_val) + " is greater than maximum " + std::to_string(max_val), 
                "maximum");
        }
        
        return result;
    }
    
    ValidationResult validate_pattern(const json& data, const json& pattern, const std::string& path) const {
        ValidationResult result;
        
        std::string pattern_str = pattern.get<std::string>();
        std::string data_str = data.get<std::string>();
        
        try {
            std::regex re(pattern_str);
            if (!std::regex_search(data_str, re)) {
                result.add_error(path, 
                    "String '" + data_str + "' does not match pattern '" + pattern_str + "'", 
                    "pattern");
            }
        } catch (const std::regex_error& e) {
            result.add_error(path, "Invalid regex pattern: " + std::string(e.what()), "pattern");
        }
        
        return result;
    }
    
    ValidationResult validate_minlength(const json& data, const json& minlength, const std::string& path) const {
        ValidationResult result;
        
        size_t min_len = minlength.get<size_t>();
        std::string data_str = data.get<std::string>();
        
        if (data_str.length() < min_len) {
            result.add_error(path, 
                "String length " + std::to_string(data_str.length()) + " is less than minimum length " + std::to_string(min_len), 
                "minLength");
        }
        
        return result;
    }
    
    ValidationResult validate_maxlength(const json& data, const json& maxlength, const std::string& path) const {
        ValidationResult result;
        
        size_t max_len = maxlength.get<size_t>();
        std::string data_str = data.get<std::string>();
        
        if (data_str.length() > max_len) {
            result.add_error(path, 
                "String length " + std::to_string(data_str.length()) + " is greater than maximum length " + std::to_string(max_len), 
                "maxLength");
        }
        
        return result;
    }
    
    ValidationResult validate_enum(const json& data, const json& enum_values, const std::string& path) const {
        ValidationResult result;
        
        bool found = false;
        for (const auto& val : enum_values) {
            if (data == val) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            result.add_error(path, "Value does not match any of the allowed enum values", "enum");
        }
        
        return result;
    }
};

} // namespace nlohmann
