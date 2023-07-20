#include <nlohmann/detail/macro_scope.hpp>

#define NLOHMANN_JSON_ANNOTATED_TO(v1, w1) nlohmann_json_j[#v1] = nlohmann_json_t.v1;

#define NLOHMANN_JSON_ANNOTATED_EXPAND( x ) x
#define NLOHMANN_JSON_ANNOTATED_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, NAME,...) NAME
#define NLOHMANN_JSON_ANNOTATED_PASTE(...) NLOHMANN_JSON_ANNOTATED_EXPAND(NLOHMANN_JSON_ANNOTATED_GET_MACRO(__VA_ARGS__, \
        NLOHMANN_JSON_ANNOTATED_PASTE7, \
        NLOHMANN_JSON_ANNOTATED_PASTE5, \
        NLOHMANN_JSON_ANNOTATED_PASTE2, \
        NLOHMANN_JSON_ANNOTATED_PASTE1)(__VA_ARGS__))
#define NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) func(v1, w1)
#define NLOHMANN_JSON_ANNOTATED_PASTE5(func, v1, w1, v2, w2) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v2, w2)
#define NLOHMANN_JSON_ANNOTATED_PASTE7(func, v1, w1, v2, w2, v3, w3) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE5(func, v2, w2, v3, w3)


#define TERNARY_EXPAND1(v1, w1) (property == #v1 ? w1 : "")
#define TERNARY_EXPAND2(v1, w1, v2, w2) (property == #v2 ? w2 : TERNARY_EXPAND1(v1, w1))
#define TERNARY_EXPAND3(v1, w1, v2, w2, v3, w3) (property == #v3 ? w3 : TERNARY_EXPAND2(v1, w1, v2, w2))
#define TERNARY_NOT_ALLOWED static_assert(false, "Annotated macro requires even number of arguments where each property is accompanied by a string comment.")

#define GET_TERNARY_EXPAND_MACRO(_1,_2,_3,_4,_5,_6,NAME,...) NAME
#define TERNARY_EXPAND(...) GET_TERNARY_EXPAND_MACRO(__VA_ARGS__, TERNARY_EXPAND3, TERNARY_NOT_ALLOWED, TERNARY_EXPAND2, TERNARY_NOT_ALLOWED, TERNARY_EXPAND1)(__VA_ARGS__)

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(Type, ...)  \
    friend void to_json(nlohmann::json& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_ANNOTATED_EXPAND(NLOHMANN_JSON_ANNOTATED_PASTE(NLOHMANN_JSON_ANNOTATED_TO, __VA_ARGS__)) } \
    static std::string get_annotation(const std::string& property) { return TERNARY_EXPAND(__VA_ARGS__); }