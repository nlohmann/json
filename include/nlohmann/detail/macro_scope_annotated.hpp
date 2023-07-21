#include <nlohmann/detail/macro_scope.hpp>

#define NLOHMANN_JSON_ANNOTATED_TO(v1, w1) nlohmann_json_j[#v1] = nlohmann_json_t.v1;

#define NLOHMANN_JSON_ANNOTATED_EXPAND( x ) x
#define NLOHMANN_JSON_ANNOTATED_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, NAME,...) NAME
#define NLOHMANN_JSON_ANNOTATED_PASTE(...) NLOHMANN_JSON_ANNOTATED_EXPAND(NLOHMANN_JSON_ANNOTATED_GET_MACRO(__VA_ARGS__, \
        NLOHMANN_JSON_ANNOTATED_PASTE30, \
        NLOHMANN_JSON_ANNOTATED_PASTE28, \
        NLOHMANN_JSON_ANNOTATED_PASTE26, \
        NLOHMANN_JSON_ANNOTATED_PASTE24, \
        NLOHMANN_JSON_ANNOTATED_PASTE22, \
        NLOHMANN_JSON_ANNOTATED_PASTE20, \
        NLOHMANN_JSON_ANNOTATED_PASTE18, \
        NLOHMANN_JSON_ANNOTATED_PASTE16, \
        NLOHMANN_JSON_ANNOTATED_PASTE14, \
        NLOHMANN_JSON_ANNOTATED_PASTE12, \
        NLOHMANN_JSON_ANNOTATED_PASTE10, \
        NLOHMANN_JSON_ANNOTATED_PASTE8, \
        NLOHMANN_JSON_ANNOTATED_PASTE6, \
        NLOHMANN_JSON_ANNOTATED_PASTE4, \
        NLOHMANN_JSON_ANNOTATED_PASTE2, \
        NLOHMANN_JSON_ANNOTATED_PASTE1)(__VA_ARGS__))
#define NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) func(v1, w1)
#define NLOHMANN_JSON_ANNOTATED_PASTE4(func, v1, w1, v2, w2) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v2, w2)
#define NLOHMANN_JSON_ANNOTATED_PASTE6(func, v1, w1, v2, w2, v3, w3) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE4(func, v2, w2, v3, w3)
#define NLOHMANN_JSON_ANNOTATED_PASTE8(func, v1, w1, v2, w2, v3, w3, v4, w4) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE6(func, v2, w2, v3, w3, v4, w4)
#define NLOHMANN_JSON_ANNOTATED_PASTE10(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE8(func, v2, w2, v3, w3, v4, w4, v5, w5)
#define NLOHMANN_JSON_ANNOTATED_PASTE12(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE10(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6)
#define NLOHMANN_JSON_ANNOTATED_PASTE14(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE12(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7)
#define NLOHMANN_JSON_ANNOTATED_PASTE16(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE14(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8)
#define NLOHMANN_JSON_ANNOTATED_PASTE18(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE16(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9)
#define NLOHMANN_JSON_ANNOTATED_PASTE20(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE18(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10)
#define NLOHMANN_JSON_ANNOTATED_PASTE22(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE20(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11)
#define NLOHMANN_JSON_ANNOTATED_PASTE24(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE22(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12)
#define NLOHMANN_JSON_ANNOTATED_PASTE26(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE24(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13)
#define NLOHMANN_JSON_ANNOTATED_PASTE28(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE26(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14)
#define NLOHMANN_JSON_ANNOTATED_PASTE30(func, v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14, v15, w15) NLOHMANN_JSON_ANNOTATED_PASTE2(func, v1, w1) NLOHMANN_JSON_ANNOTATED_PASTE28(func, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14, v15, w15)


#define TERNARY_EXPAND1(v1, w1) (property == #v1 ? w1 : "")
#define TERNARY_EXPAND2(v1, w1, v2, w2) (property == #v2 ? w2 : TERNARY_EXPAND1(v1, w1))
#define TERNARY_EXPAND3(v1, w1, v2, w2, v3, w3) (property == #v3 ? w3 : TERNARY_EXPAND2(v1, w1, v2, w2))
#define TERNARY_EXPAND4(v1, w1, v2, w2, v3, w3, v4, w4) (property == #v4 ? w4 : TERNARY_EXPAND3(v1, w1, v2, w2, v3, w3))
#define TERNARY_EXPAND5(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5) (property == #v5 ? w5 : TERNARY_EXPAND4(v1, w1, v2, w2, v3, w3, v4, w4))
#define TERNARY_EXPAND6(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6) (property == #v6 ? w6 : TERNARY_EXPAND5(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5))
#define TERNARY_EXPAND7(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7) (property == #v7 ? w7 : TERNARY_EXPAND6(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6))
#define TERNARY_EXPAND8(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8) (property == #v8 ? w8 : TERNARY_EXPAND7(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7))
#define TERNARY_EXPAND9(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9) (property == #v9 ? w9 : TERNARY_EXPAND8(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8))
#define TERNARY_EXPAND10(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10) (property == #v10 ? w10 : TERNARY_EXPAND9(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9))
#define TERNARY_EXPAND11(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11) (property == #v11 ? w11 : TERNARY_EXPAND10(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10))
#define TERNARY_EXPAND12(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12) (property == #v12 ? w12 : TERNARY_EXPAND11(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11))
#define TERNARY_EXPAND13(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13) (property == #v13 ? w13 : TERNARY_EXPAND12(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12))
#define TERNARY_EXPAND14(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14) (property == #v14 ? w14 : TERNARY_EXPAND13(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13))
#define TERNARY_EXPAND15(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14, v15, w15) (property == #v15 ? w15 : TERNARY_EXPAND14(v1, w1, v2, w2, v3, w3, v4, w4, v5, w5, v6, w6, v7, w7, v8, w8, v9, w9, v10, w10, v11, w11, v12, w12, v13, w13, v14, w14))
#define TERNARY_NOT_ALLOWED static_assert(false, "Annotated macro requires even number of arguments where each property is accompanied by a string comment.")

#define GET_TERNARY_EXPAND_MACRO(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,NAME,...) NAME
#define TERNARY_EXPAND(...) GET_TERNARY_EXPAND_MACRO(__VA_ARGS__, \
                TERNARY_EXPAND15, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND14, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND13, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND12, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND11, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND10, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND9, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND8, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND7, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND6, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND5, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND4, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND3, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND2, TERNARY_NOT_ALLOWED, \
                TERNARY_EXPAND1)(__VA_ARGS__)

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(Type, ...)  \
    friend void to_json(nlohmann::json& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_ANNOTATED_EXPAND(NLOHMANN_JSON_ANNOTATED_PASTE(NLOHMANN_JSON_ANNOTATED_TO, __VA_ARGS__)) } \
    static std::string get_annotation(const std::string& property) { return TERNARY_EXPAND(__VA_ARGS__); }