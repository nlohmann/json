// SPDX-FileCopyrightText: 2025 Mike Crowe
// SPDX-License-Identifier: MIT

// The test is limited to C++17 because the version of
// check_clang_tidy.py here would like to test with -std=c++23, but
// Clang 16 doesn't support that.

// RUN: %check_clang_tidy -std=c++17 %s modernize-nlohmann-json-explicit-conversions %t -- -- -isystem %clang_tidy_headers

typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __SIZE_TYPE__ size_t;

typedef unsigned __INT16_TYPE__ char16;
typedef unsigned __INT32_TYPE__ char32;

namespace std {
template <typename T>
class allocator {};

template <typename T>
class char_traits {};

template <typename C, typename T = char_traits<C>>
struct basic_string_view;

template <typename C, typename T = char_traits<C>, typename A = allocator<C>>
struct basic_string {
  typedef size_t size_type;
  typedef basic_string<C, T, A> _Type;
  basic_string();
  basic_string(const C *p, const A &a = A());
  basic_string(const C *p, size_type count);
  basic_string(const C *b, const C *e);

  ~basic_string();

  const C *c_str() const;
  const C *data() const;

  bool empty() const;
  size_type size() const;
  size_type length() const;

  _Type& append(const C *s);
  _Type& append(const C *s, size_type n);
  _Type& assign(const C *s);
  _Type& assign(const C *s, size_type n);

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
struct basic_string_view {
  typedef size_t size_type;
  typedef basic_string_view<C, T> _Type;

  const C *str;
  constexpr basic_string_view(const C* s) : str(s) {}

  const C *data() const;

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

struct MyStruct {
  int i1;
  int i2;
};

namespace nlohmann
{
  class basic_json
  {
  public:
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

    int otherMember() const;
  };

  class iterator
  {
  public:
    basic_json &operator*();
    basic_json *operator->();
  };

  using json = basic_json;
}

using nlohmann::json;
using nlohmann::iterator;

int get_int(json &j)
{
  return j;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return j.get<int>();
}

std::string get_string(json &j)
{
  return j;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return j.get<std::string>();
}

std::vector<std::string> get_string_vector(json &j)
{
  return j;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to std::vector<std::string> should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return j.get<std::vector<std::string>>();
}

MyStruct get_struct(json &j)
{
  return j;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to MyStruct should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return j.get<MyStruct>();
}

int get_int_ptr(json *j)
{
  return *j;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return j->get<int>();
}

int get_int_ptr_expr(json *j)
{
  return *(j+1);
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return (j+1)->get<int>();
}

int get_int_iterator(iterator i)
{
  return *i;
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return i->get<int>();
}

int get_int_fn()
{
  extern json get_json();
  return get_json();
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to int should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return get_json().get<int>();
}

double get_double_fn_ref()
{
  extern nlohmann::json &get_json_ref();
  return get_json_ref();
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to double should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return get_json_ref().get<double>();
}

std::string get_string_fn_ptr()
{
  extern json *get_json_ptr();
  return *get_json_ptr();
  // CHECK-MESSAGES: [[@LINE-1]]:10: warning: implicit nlohmann::json conversion to std::string should be explicit [modernize-nlohmann-json-explicit-conversions]
  // CHECK-FIXES: return get_json_ptr()->get<std::string>();
}

int call_other_member(nlohmann::json &j)
{
  return j.otherMember();
}

int call_other_member_ptr(nlohmann::json *j)
{
  return j->otherMember();
}

int call_other_member_iterator(iterator i)
{
  return i->otherMember();
}
