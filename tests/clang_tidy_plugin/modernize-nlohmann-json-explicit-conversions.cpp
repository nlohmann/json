// SPDX-FileCopyrightText: 2025-2026 Mike Crowe
// SPDX-License-Identifier: MIT

// The test is limited to C++17 because the version of
// check_clang_tidy.py here would like to test with -std=c++23, but
// Clang 16 doesn't support that.

// RUN: %check_clang_tidy -std=c++17 %s modernize-nlohmann-json-explicit-conversions %t -- -- -isystem %clang_tidy_headers

struct MyStruct
{
    int i1;
    int i2;
};

#if defined(USE_REAL_HEADER)
#include <nlohmann/json.hpp>
#include <optional>

using nlohmann::json;

void from_json(const json &j, MyStruct &ms)
{
    j.at("i1").get_to(ms.i1);
    j.at("i2").get_to(ms.i2);
}

#else // !defined(USE_REAL_HEADER)
// check_clang_tidy.py passes -nostdinc++ so we need to declare everything ourselves

typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __SIZE_TYPE__ size_t;

typedef unsigned __INT16_TYPE__ char16;
typedef unsigned __INT32_TYPE__ char32;

namespace std
{
template <typename T>
class allocator {};

template <typename T>
class char_traits {};

template <typename C, typename T = char_traits<C>>
struct basic_string_view;

template <typename C, typename T = char_traits<C>, typename A = allocator<C>>
struct basic_string
{
    typedef size_t size_type;
    typedef basic_string<C, T, A> _Type;
    basic_string();
    basic_string(const C* p, const A& a = A());
    basic_string(const C* p, size_type count);
    basic_string(const C* b, const C* e);

    ~basic_string();

    const C* c_str() const;
    const C* data() const;

    bool empty() const;
    size_type size() const;
    size_type length() const;

    _Type& append(const C* s);
    _Type& append(const C* s, size_type n);
    _Type& assign(const C* s);
    _Type& assign(const C* s, size_type n);

    int compare(const _Type&) const;
    int compare(const C* s) const;
    int compare(size_type pos, size_type len, const _Type&) const;
    int compare(size_type pos, size_type len, const C* s) const;
    template<class StringViewLike>
    int compare(size_type pos1, size_type count1, const StringViewLike& t) const;

    size_type find(const _Type& str, size_type pos = 0) const;
    size_type find(const C* s, size_type pos = 0) const;
    size_type find(const C* s, size_type pos, size_type n) const;

    size_type rfind(const _Type& str, size_type pos = npos) const;
    size_type rfind(const C* s, size_type pos, size_type count) const;
    size_type rfind(const C* s, size_type pos = npos) const;
    size_type rfind(C ch, size_type pos = npos) const;

    _Type& insert(size_type pos, const _Type& str);
    _Type& insert(size_type pos, const C* s);
    _Type& insert(size_type pos, const C* s, size_type n);

    _Type substr(size_type pos = 0, size_type count = npos) const;

    constexpr bool starts_with(std::basic_string_view<C, T> sv) const noexcept;
    constexpr bool starts_with(C ch) const noexcept;
    constexpr bool starts_with(const C* s) const;

    constexpr bool ends_with(std::basic_string_view<C, T> sv) const noexcept;
    constexpr bool ends_with(C ch) const noexcept;
    constexpr bool ends_with(const C* s) const;

    _Type& operator[](size_type);
    const _Type& operator[](size_type) const;

    _Type& operator+=(const _Type& str);
    _Type& operator+=(const C* s);
    _Type& operator=(const _Type& str);
    _Type& operator=(const C* s);

    static constexpr size_t npos = -1;
};

typedef basic_string<char> string;
typedef basic_string<wchar_t> wstring;
typedef basic_string<char16> u16string;
typedef basic_string<char32> u32string;

template <typename C, typename T>
struct basic_string_view
{
    typedef size_t size_type;
    typedef basic_string_view<C, T> _Type;

    const C* str;
    constexpr basic_string_view(const C* s) : str(s) {}

    const C* data() const;

    bool empty() const;
    size_type size() const;
    size_type length() const;

    size_type find(_Type v, size_type pos = 0) const;
    size_type find(C ch, size_type pos = 0) const;
    size_type find(const C* s, size_type pos, size_type count) const;
    size_type find(const C* s, size_type pos = 0) const;

    size_type rfind(_Type v, size_type pos = npos) const;
    size_type rfind(C ch, size_type pos = npos) const;
    size_type rfind(const C* s, size_type pos, size_type count) const;
    size_type rfind(const C* s, size_type pos = npos) const;

    constexpr bool starts_with(basic_string_view sv) const noexcept;
    constexpr bool starts_with(C ch) const noexcept;
    constexpr bool starts_with(const C* s) const;

    constexpr bool ends_with(basic_string_view sv) const noexcept;
    constexpr bool ends_with(C ch) const noexcept;
    constexpr bool ends_with(const C* s) const;

    constexpr int compare(basic_string_view sv) const noexcept;

    static constexpr size_t npos = -1;
};

typedef basic_string_view<char> string_view;
typedef basic_string_view<wchar_t> wstring_view;
typedef basic_string_view<char16> u16string_view;
typedef basic_string_view<char32> u32string_view;

std::string operator+(const std::string&, const std::string&);
std::string operator+(const std::string&, const char*);
std::string operator+(const char*, const std::string&);

bool operator==(const std::string&, const std::string&);
bool operator==(const std::string&, const char*);
bool operator==(const char*, const std::string&);

bool operator==(const std::wstring&, const std::wstring&);
bool operator==(const std::wstring&, const wchar_t*);
bool operator==(const wchar_t*, const std::wstring&);

bool operator==(const std::string_view&, const std::string_view&);
bool operator==(const std::string_view&, const char*);
bool operator==(const char*, const std::string_view&);

#if __cplusplus < 202002L
    bool operator!=(const std::string&, const std::string&);
    bool operator!=(const std::string&, const char*);
    bool operator!=(const char*, const std::string&);

    bool operator!=(const std::string_view&, const std::string_view&);
    bool operator!=(const std::string_view&, const char*);
    bool operator!=(const char*, const std::string_view&);
#endif

size_t strlen(const char* str);

template <typename T>
class vector
{
};

}

namespace nlohmann
{
inline namespace json_abi_vx_y_z
{
template <typename T>
class iter
{
  public:
    T& operator*();
    T* operator->();
};

class basic_json
{
  public:
    using iterator = iter<basic_json>;

    template <typename ValueType>
    ValueType get() const
    {
        return ValueType{};
    }

    // nlohmann::json uses SFINAE to limit the types that can be converted to.
    // Rather than do that here, let's just provide the overloads we need
    // instead.
    operator int() const
    {
        return get<int>();
    }

    operator double() const
    {
        return get<double>();
    }

    operator std::string() const
    {
        return get<std::string>();
    }

    operator MyStruct() const
    {
        return get<MyStruct>();
    }

    operator std::vector<std::string>() const
    {
        return get<std::vector<std::string>>();
    }

    iterator find(const char *) const;

    basic_json &at(const char *) const;
    basic_json &operator[](const char *) const;

    bool is_array() const;
};

using json = basic_json;
}
}

using nlohmann::json;
#endif // !defined(USE_REAL_HEADER)

int get_int(json& j)
{
    return j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

int get_int_cpp_cast(json& j)
{
    return static_cast<int>(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

int get_int_c_cast(json& j)
{
    return (int)j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

int get_int_functional_cast(json& j)
{
    return int(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

int get_int_functional_cast_expression(json& j)
{
    return int(j) + 1;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>() + 1;
}

int get_int_constructor_cast(json& j)
{
    return int{j};
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

int get_int_const_cast_type(json& j)
{
    return static_cast<const int>(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

typedef int MyInt;

MyInt get_int_typedef_cast(json& j)
{
    return (MyInt)j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<int>();
}

std::string get_string_cpp_cast(json& j)
{
    return static_cast<std::string>(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::string>();
}

std::string get_string_c_cast(json& j)
{
    return (std::string)j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::string>();
}

std::string get_string_functional_cast(json& j)
{
    return std::string(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::string>();
}

std::string get_string_constructor_cast(json& j)
{
    return std::string{j};
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::string>();
}

int get_int_ptr_cast(json* j)
{
    return (int)*j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j->get<int>();
}

int get_int_iterator_cast(json::iterator i)
{
    return static_cast<int>(*i);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return i->get<int>();
}

int get_int_at(json j)
{
    return j.at("value");
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.at("value").get<int>();
}

int get_int_property(json j)
{
    return j["value"];
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j["value"].get<int>();
}

int get_int_find(json j)
{
    return *j.find("value");
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.find("value")->get<int>();
}

// A cast to a different type that is constructed from the result of the
// conversion is still required, so only the conversion is fixed.
struct FromInt
{
    explicit FromInt(int) {}
};

FromInt get_from_int_cpp_cast(json& j)
{
    return static_cast<FromInt>(j);
    // CHECK-MESSAGES: [[@LINE-1]]:33: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return static_cast<FromInt>(j.get<int>());
}

FromInt get_from_int_functional_cast(json& j)
{
    return FromInt(j);
    // CHECK-MESSAGES: [[@LINE-1]]:20: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return FromInt(j.get<int>());
}

FromInt get_from_int_c_cast(json& j)
{
    return (FromInt)j;
    // CHECK-MESSAGES: [[@LINE-1]]:21: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return (FromInt)j.get<int>();
}

FromInt get_from_int_constructor_cast(json& j)
{
    return FromInt{j};
    // CHECK-MESSAGES: [[@LINE-1]]:20: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return FromInt{j.get<int>()};
}

struct OneInt
{
    int i;
};

OneInt get_one_int_aggregate(json& j)
{
    return OneInt{j};
    // CHECK-MESSAGES: [[@LINE-1]]:19: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return OneInt{j.get<int>()};
}

OneInt get_one_int_aggregate_compound_literal(json& j)
{
    return (OneInt){j};
    // CHECK-MESSAGES: [[@LINE-1]]:21: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return (OneInt){j.get<int>()};
}

std::string get_string(json& j)
{
    return j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::string>();
}

std::vector<std::string> get_string_vector(json& j)
{
    return j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::vector<std::string> should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<std::vector<std::string>>();
}

std::vector<std::string> get_string_vector_cast(json* j)
{
    return static_cast<std::vector<std::string>>(*j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::vector<std::string> should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j->get<std::vector<std::string>>();
}

MyStruct get_struct(json& j)
{
    return j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to MyStruct should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j.get<MyStruct>();
}

int get_int_ptr(json* j)
{
    return *j;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return j->get<int>();
}

int get_int_ptr_expr(json* j)
{
    return *(j + 1);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return (j + 1)->get<int>();
}

int get_int_iterator(json::iterator i)
{
    return *i;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return i->get<int>();
}

int get_int_fn()
{
    extern json get_json();
    return get_json();
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return get_json().get<int>();
}

double get_double_fn_ref()
{
    extern nlohmann::json& get_json_ref();
    return get_json_ref();
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to double should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return get_json_ref().get<double>();
}

std::string get_string_fn_ptr()
{
    extern json* get_json_ptr();
    return *get_json_ptr();
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return get_json_ptr()->get<std::string>();
}

bool call_other_member(nlohmann::json& j)
{
    return j.is_array();
}

bool call_other_member_ptr(nlohmann::json* j)
{
    return j->is_array();
}

bool call_other_member_iterator(json::iterator i)
{
    return i->is_array();
}

// Conversions in templates that don't depend on the template parameters are
// fixed, but only diagnosed once.
template <typename T>
int templated_not_dependent(json &j)
{
    int i = j;
    // CHECK-MESSAGES: [[@LINE-1]]:13: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: int i = j.get<int>();
    return i;
}

int templated_not_dependent_test(json &j)
{
    return templated_not_dependent<double>(j) + templated_not_dependent<int>(j);
}

// Conversions in templates that depend on the template parameters are
// diagnosed for each instantiation but not fixed since a fix for one
// instantiation would break the others. The unfixed code can't be
// compiled once implicit conversions are disabled.
#if !defined(JSON_USE_IMPLICIT_CONVERSIONS) || JSON_USE_IMPLICIT_CONVERSIONS != 0
template <typename T>
T templated_once(json &j)
{
    T t = j;
    // CHECK-MESSAGES: [[@LINE-1]]:11: warning: implicit nlohmann::json conversion to templated type should be explicit [modernize-nlohmann-json-explicit-conversions]
    return t;
}

int templated_once_test(json &j)
{
    return templated_once<int>(j);
}

template <typename T>
T templated_multiple(json &j)
{
    T t = j;
    // CHECK-MESSAGES: [[@LINE-1]]:11: warning: implicit nlohmann::json conversion to templated type should be explicit [modernize-nlohmann-json-explicit-conversions]
    return t;
}

double templated_double_test(json &j)
{
    return templated_multiple<double>(j);
}

int templated_int_test(json &j)
{
    return templated_multiple<int>(j);
}
#endif

#define CONVERSION_OUTSIDE_MACRO(j) j["value"]

int conversion_outside_macro(json &j)
{
    return CONVERSION_OUTSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:37: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CONVERSION_OUTSIDE_MACRO(j).get<int>();
}

#define CONVERSION_INSIDE_MACRO(j) static_cast<int>(j)

// The conversion is diagnosed, but not fixed since that would require changing
// the macro definition.
int conversion_inside_macro_not_fixed(json &j)
{
    return CONVERSION_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CONVERSION_INSIDE_MACRO(j);
}

// An implicit conversion inside a macro definition is diagnosed, but not fixed.
#if !defined(USE_REAL_HEADER)
#define IMPLICIT_CONVERSION_INSIDE_MACRO(j) const int value = j["value"]

int implicit_conversion_inside_macro_not_fixed(json &j)
{
    IMPLICIT_CONVERSION_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:38: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: IMPLICIT_CONVERSION_INSIDE_MACRO(j);
    return value;
}
#endif

json global_json;

#if !defined(USE_REAL_HEADER)
#define DECLARE_FROM_GLOBAL_JSON int d = global_json;

int implicit_conversion_of_global_inside_macro_not_fixed()
{
    DECLARE_FROM_GLOBAL_JSON
    // CHECK-MESSAGES: [[@LINE-1]]:5: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: {{^}}    DECLARE_FROM_GLOBAL_JSON{{$}}
    return d;
}
#endif

void take_int(int);

#define CALL_TAKE_INT(x) take_int(x)

void conversion_of_macro_argument(json &j)
{
    CALL_TAKE_INT(j);
    // CHECK-MESSAGES: [[@LINE-1]]:19: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: CALL_TAKE_INT(j.get<int>());
}

#define GLOBAL_JSON global_json

int conversion_of_object_like_macro()
{
    int i = GLOBAL_JSON;
    // CHECK-MESSAGES: [[@LINE-1]]:13: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: int i = GLOBAL_JSON.get<int>();
    return i;
}

int cast_of_object_like_macro()
{
    return static_cast<int>(GLOBAL_JSON);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return GLOBAL_JSON.get<int>();
}

#define C_CAST_INSIDE_MACRO(x) (int)(x)

int c_cast_inside_macro_not_fixed(json &j)
{
    return C_CAST_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return C_CAST_INSIDE_MACRO(j);
}

#define CAST_OF_GLOBAL_INSIDE_MACRO static_cast<int>(global_json)

int cast_of_global_inside_macro_not_fixed()
{
    return CAST_OF_GLOBAL_INSIDE_MACRO;
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CAST_OF_GLOBAL_INSIDE_MACRO;
}

#define CAST_PLUS_ONE_INSIDE_MACRO(x) static_cast<int>(x) + 1

int cast_inside_larger_macro_not_fixed(json &j)
{
    return CAST_PLUS_ONE_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CAST_PLUS_ONE_INSIDE_MACRO(j);
}

// A conversion inside a macro used in a template is only diagnosed once,
// rather than again for each instantiation.
template <typename T>
int templated_conversion_inside_macro_not_fixed(json &j)
{
    return CONVERSION_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CONVERSION_INSIDE_MACRO(j);
}

#define CAST_TO_T_INSIDE_MACRO(x) static_cast<T>(x)

template <typename T>
T templated_dependent_conversion_inside_macro_not_fixed(json &j)
{
    return CAST_TO_T_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:12: warning: implicit nlohmann::json conversion to templated type should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return CAST_TO_T_INSIDE_MACRO(j);
}

double templated_conversion_inside_macro_test(json &j)
{
    return templated_conversion_inside_macro_not_fixed<int>(j) +
           templated_conversion_inside_macro_not_fixed<double>(j) +
           templated_dependent_conversion_inside_macro_not_fixed<int>(j) +
           templated_dependent_conversion_inside_macro_not_fixed<double>(j);
}

#if !defined(USE_REAL_HEADER)
#define IMPLICIT_RETURN_INSIDE_MACRO(x) return x["value"]

int implicit_return_inside_macro_not_fixed(json &j)
{
    IMPLICIT_RETURN_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:34: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: {{^}}    IMPLICIT_RETURN_INSIDE_MACRO(j);{{$}}
}

int add_one(int);

#define IMPLICIT_ADD_ONE_PLUS_ONE_INSIDE_MACRO(x) add_one(x["value"]) + 1

int implicit_conversion_inside_larger_macro_not_fixed(json &j)
{
    return IMPLICIT_ADD_ONE_PLUS_ONE_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:51: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: return IMPLICIT_ADD_ONE_PLUS_ONE_INSIDE_MACRO(j);
}

template <typename T>
int templated_implicit_conversion_inside_macro_not_fixed(json &j)
{
    IMPLICIT_RETURN_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:34: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: {{^}}    IMPLICIT_RETURN_INSIDE_MACRO(j);{{$}}
}

#define IMPLICIT_DECLARE_T_INSIDE_MACRO(x) T t = x["value"]

template <typename T>
T templated_dependent_implicit_conversion_inside_macro_not_fixed(json &j)
{
    IMPLICIT_DECLARE_T_INSIDE_MACRO(j);
    // CHECK-MESSAGES: [[@LINE-1]]:37: warning: implicit nlohmann::json conversion to templated type should be explicit [modernize-nlohmann-json-explicit-conversions]
    // CHECK-FIXES: {{^}}    IMPLICIT_DECLARE_T_INSIDE_MACRO(j);{{$}}
    return t;
}

double templated_implicit_conversion_inside_macro_test(json &j)
{
    return templated_implicit_conversion_inside_macro_not_fixed<int>(j) +
           templated_implicit_conversion_inside_macro_not_fixed<double>(j) +
           templated_dependent_implicit_conversion_inside_macro_not_fixed<int>(j) +
           templated_dependent_implicit_conversion_inside_macro_not_fixed<double>(j);
}
#endif

#if defined(USE_REAL_HEADER) && (!defined(JSON_USE_IMPLICIT_CONVERSIONS) || JSON_USE_IMPLICIT_CONVERSIONS != 0)
// This is not fixed because the conversion happens inside a system header.
std::optional<int> optional_test(const nlohmann::json &j)
{
  const auto &it = j.find("value");
  if (it != j.end())
      return *it;
  else
      return std::nullopt;
}
#endif
