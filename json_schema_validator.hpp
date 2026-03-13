#pragma once

#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

struct ValidationError {
    std::string path;
    std::string message;
    std::string keyword;

    ValidationError(std::string p, std::string m, std::string k)
        : path(std::move(p)), message(std::move(m)), keyword(std::move(k)) {}
};

class JsonSchemaValidator {
public:
    using ErrorFormatter = std::function<std::string(const ValidationError&)>;

    JsonSchemaValidator() = default;

    void set_schema(const json& schema) {
        schema_ = schema;
    }

    void set_error_formatter(ErrorFormatter formatter) {
        error_formatter_ = std::move(formatter);
    }

    bool validate(const json& data) {
        errors_.clear();
        validate(data, schema_, "");
        return errors_.empty();
    }

    const std::vector<ValidationError>& get_errors() const {
        return errors_;
    }

    std::vector<std::string> get_formatted_errors() const {
        std::vector<std::string> result;
        for (const auto& err : errors_) {
            if (error_formatter_) {
                result.push_back(error_formatter_(err));
            } else {
                result.push_back(format_error_default(err));
            }
        }
        return result;
    }

private:
    json schema_;
    std::vector<ValidationError> errors_;
    ErrorFormatter error_formatter_;

    static std::string format_error_default(const ValidationError& err) {
        std::string path = err.path.empty() ? "." : err.path;
        return path + ": " + err.message + " [" + err.keyword + "]";
    }

    std::string make_path(const std::string& base, const std::string& key) {
        if (base.empty()) {
            return "/" + key;
        }
        return base + "/" + key;
    }

    void validate(const json& data, const json& schema, const std::string& path) {
        if (schema.contains("type")) {
            validate_type(data, schema["type"], path);
        }

        if (schema.contains("properties") && data.is_object()) {
            validate_properties(data, schema["properties"], path);
        }

        if (schema.contains("required") && data.is_object()) {
            validate_required(data, schema["required"], path);
        }

        if (schema.contains("minimum") && data.is_number()) {
            validate_minimum(data, schema["minimum"], path);
        }

        if (schema.contains("maximum") && data.is_number()) {
            validate_maximum(data, schema["maximum"], path);
        }

        if (schema.contains("pattern") && data.is_string()) {
            validate_pattern(data, schema["pattern"], path);
        }
    }

    void validate_type(const json& data, const json& type, const std::string& path) {
        if (type.is_string()) {
            if (!check_single_type(data, type.get<std::string>())) {
                std::string msg = "expected type '" + type.get<std::string>() + 
                                  "', but got '" + get_type_name(data) + "'";
                errors_.emplace_back(path, msg, "type");
            }
        } else if (type.is_array()) {
            bool matched = false;
            for (const auto& t : type) {
                if (t.is_string() && check_single_type(data, t.get<std::string>())) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                std::string msg = "expected one of types " + type.dump() + 
                                  ", but got '" + get_type_name(data) + "'";
                errors_.emplace_back(path, msg, "type");
            }
        }
    }

    bool check_single_type(const json& data, const std::string& type) {
        if (type == "null") return data.is_null();
        if (type == "boolean") return data.is_boolean();
        if (type == "object") return data.is_object();
        if (type == "array") return data.is_array();
        if (type == "string") return data.is_string();
        if (type == "number") return data.is_number();
        if (type == "integer") return data.is_number_integer() || data.is_number_unsigned();
        return false;
    }

    std::string get_type_name(const json& data) {
        if (data.is_null()) return "null";
        if (data.is_boolean()) return "boolean";
        if (data.is_object()) return "object";
        if (data.is_array()) return "array";
        if (data.is_string()) return "string";
        if (data.is_number_float()) return "number";
        if (data.is_number_integer() || data.is_number_unsigned()) return "integer";
        return "unknown";
    }

    void validate_properties(const json& data, const json& properties, const std::string& path) {
        for (auto it = properties.begin(); it != properties.end(); ++it) {
            const std::string& key = it.key();
            const json& prop_schema = it.value();
            if (data.contains(key)) {
                validate(data[key], prop_schema, make_path(path, key));
            }
        }
    }

    void validate_required(const json& data, const json& required, const std::string& path) {
        for (const auto& req : required) {
            if (req.is_string() && !data.contains(req.get<std::string>())) {
                std::string msg = "required property '" + req.get<std::string>() + "' is missing";
                errors_.emplace_back(path, msg, "required");
            }
        }
    }

    static std::string number_to_string(double val) {
        std::ostringstream oss;
        oss << std::noshowpoint << val;
        std::string s = oss.str();
        size_t dot = s.find('.');
        if (dot != std::string::npos) {
            size_t end = s.find_last_not_of('0');
            if (end == dot) {
                s = s.substr(0, dot);
            } else if (end != std::string::npos) {
                s = s.substr(0, end + 1);
            }
        }
        return s;
    }

    void validate_minimum(const json& data, const json& minimum, const std::string& path) {
        if (minimum.is_number()) {
            double min_val = minimum.get<double>();
            double data_val = data.get<double>();
            if (data_val < min_val) {
                std::string msg = "value " + number_to_string(data_val) + 
                                  " is less than minimum " + number_to_string(min_val);
                errors_.emplace_back(path, msg, "minimum");
            }
        }
    }

    void validate_maximum(const json& data, const json& maximum, const std::string& path) {
        if (maximum.is_number()) {
            double max_val = maximum.get<double>();
            double data_val = data.get<double>();
            if (data_val > max_val) {
                std::string msg = "value " + number_to_string(data_val) + 
                                  " is greater than maximum " + number_to_string(max_val);
                errors_.emplace_back(path, msg, "maximum");
            }
        }
    }

    void validate_pattern(const json& data, const json& pattern, const std::string& path) {
        if (pattern.is_string()) {
            try {
                std::regex re(pattern.get<std::string>());
                if (!std::regex_search(data.get<std::string>(), re)) {
                    std::string msg = "string '" + data.get<std::string>() + 
                                      "' does not match pattern '" + pattern.get<std::string>() + "'";
                    errors_.emplace_back(path, msg, "pattern");
                }
            } catch (const std::regex_error&) {
                errors_.emplace_back(path, "invalid regex pattern: " + pattern.get<std::string>(), "pattern");
            }
        }
    }
};
