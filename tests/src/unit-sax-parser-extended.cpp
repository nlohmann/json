/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <iostream>
#include <set>
#include <string>
#include <tuple>
#include <type_traits>

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

// ignore warning to replace if with if constexpr since there are
// several in the file, just deactivate it here to prevent repeated ifdefs
DOCTEST_MSVC_SUPPRESS_WARNING(4127)

//option to make this test more verbose
#define verbose_out \
    if (0)          \
        std::cout

//prototype to make -Wmissing-prototypes happy
struct element_info_t;
bool operator<(const element_info_t& l, const element_info_t& r);
std::ostream& operator<<(std::ostream& out, const element_info_t& v);
std::ostream& operator<<(std::ostream& out, const std::set<element_info_t>& v);
template<class SAX, class FN>
void fill_expected_sax_pos_json(SAX& sax,
                                const FN& element,
                                const nlohmann::json& part,
                                std::size_t& offset);
template<class SAX, class FN>
void fill_expected_sax_pos_bson(SAX& sax,
                                const FN& element,
                                const nlohmann::json& part,
                                std::size_t& offset);
template<class SAX, class FN>
void fill_expected_sax_pos_cbor(SAX& sax, const FN& element, const nlohmann::json& part);
template<class SAX, class FN>
void fill_expected_sax_pos_msgpack(SAX& sax, const FN& element, const nlohmann::json& part);
template<class SAX, class FN>
void fill_expected_sax_pos_ubjson(SAX& sax, const FN& element, const nlohmann::json& part);
void test_json(nlohmann::json& json);

//implementation

struct element_info_t
{
    element_info_t(std::size_t idx, std::size_t first, std::size_t last)
        : index{idx}
        , start{first}
        , end{last}
    {}
    std::size_t index = 0;
    std::size_t start = 0;
    std::size_t end = 0;
};
bool operator<(const element_info_t& l, const element_info_t& r)
{
    return std::tie(l.index, l.start, l.end) < std::tie(r.index, r.start, r.end);
}
std::ostream& operator<<(std::ostream& out, const element_info_t& v)
{
    return (out << v.index << ':' << v.start << '-' << v.end
            << '(' << v.end - v.start << ')');
}
std::ostream& operator<<(std::ostream& out, const std::set<element_info_t>& v)
{
    out << "{";
    if (v.size() > 32)
    {
        out << ">32 elements...";
    }
    else
    {
        for (const auto& e : v)
        {
            out << ' ' << e;
        }
    }
    out << " }";
    return out;
}

template<bool LexCallImpossible, bool WithPos, bool WithLex>
struct Sax
{
    static constexpr bool has_callback = WithPos || (WithLex && !LexCallImpossible);
    using json = nlohmann::json;

    enum class last_call_t
    {
        element,
        start_pos,
        end_pos
    };

    last_call_t last_call = last_call_t::element;

    element_info_t se{0, 0, 0};

    std::set<element_info_t> pos_null{};
    std::set<element_info_t> pos_boolean{};
    std::set<element_info_t> pos_number_integer{};
    std::set<element_info_t> pos_number_unsigned{};
    std::set<element_info_t> pos_number_float{};
    std::set<element_info_t> pos_string{};
    std::set<element_info_t> pos_binary{};
    std::set<element_info_t> pos_start_object{};
    std::set<element_info_t> pos_key{};
    std::set<element_info_t> pos_end_object{};
    std::set<element_info_t> pos_start_array{};
    std::set<element_info_t> pos_end_array{};

    void check_call(std::set<element_info_t>& set, const char* fnname)
    {
        INFO("function " << fnname << ": " << se
             << " (options = " << set << ')');
        if (has_callback)
        {
            CHECK(set.count(se) == 1);
            CHECK(last_call == last_call_t::end_pos);
        }
        last_call = last_call_t::element;
        set.erase(se);
        ++se.index;
    }
    void check_start(std::size_t pos)
    {
        INFO("set start pos " << pos);
        CHECK((last_call == last_call_t::element || last_call == last_call_t::end_pos));
        se.start = pos;
        last_call = last_call_t::start_pos;
    }
    void check_end(std::size_t pos)
    {
        INFO("set end pos " << pos);
        CHECK(last_call == last_call_t::start_pos);
        se.end = pos;
        last_call = last_call_t::end_pos;
    }

    template<bool Act = WithPos>
    typename std::enable_if<Act>::type next_token_start(std::size_t pos)
    {
        check_start(pos);
        CHECK((!WithLex || LexCallImpossible));
    }

    template < class LexT, bool Act = WithLex && !std::is_same<LexT, std::size_t>::value >
    typename std::enable_if<Act>::type next_token_start(const LexT& lex)
    {
        check_start(lex.get_position().chars_read_total - 1);
        CHECK(WithLex);
    }

    template<bool Act = WithPos>
    typename std::enable_if<Act>::type next_token_end(std::size_t pos)
    {
        check_end(pos);
        CHECK((!WithLex || LexCallImpossible));
    }

    template < class LexT, bool Act = WithLex && !std::is_same<LexT, std::size_t>::value >
    typename std::enable_if<Act>::type next_token_end(const LexT& lex)
    {
        check_end(lex.get_position().chars_read_total);
        CHECK(WithLex);
    }

    bool null()
    {
        check_call(pos_null, __func__);
        verbose_out << "got null\n";
        return true;
    }
    bool boolean(bool val)
    {
        check_call(pos_boolean, __func__);
        verbose_out << "got boolean " << val << "\n";
        return true;
    }
    bool number_integer(json::number_integer_t val)
    {
        check_call(pos_number_integer, __func__);
        verbose_out << "got number_integer " << val << "\n";
        return true;
    }
    bool number_unsigned(json::number_unsigned_t val)
    {
        check_call(pos_number_unsigned, __func__);
        verbose_out << "got number_unsigned " << val << "\n";
        return true;
    }
    bool number_float(json::number_float_t val, const std::string& str)
    {
        check_call(pos_number_float, __func__);
        verbose_out << "got float " << val << " (" << str << ")"
                    << "\n";
        return true;
    }
    bool string(std::string& val)
    {
        check_call(pos_string, __func__);
        verbose_out << "got string " << val << "\n";
        return true;
    }
    bool binary(std::vector<std::uint8_t>& val)
    {
        check_call(pos_binary, __func__);
        verbose_out << "got binary: size " << val.size() << "\n";
        return true;
    }
    bool start_object(std::size_t val)
    {
        check_call(pos_start_object, __func__);
        verbose_out << "got start_object: size " << val << "\n";
        return true;
    }
    bool key(std::string& val)
    {
        check_call(pos_key, __func__);
        verbose_out << "got key " << val << "\n";
        return true;
    }
    bool end_object()
    {
        check_call(pos_end_object, __func__);
        verbose_out << "got end_object\n";
        return true;
    }
    bool start_array(std::size_t val)
    {
        check_call(pos_start_array, __func__);
        verbose_out << "got start_array: size " << val << "\n";
        return true;
    }
    bool end_array()
    {
        check_call(pos_end_array, __func__);
        verbose_out << "got end_array\n";
        return true;
    }
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const json::exception& /*unused*/)  // NOLINT(readability-convert-member-functions-to-static)
    {
        std::cout << "got parse_error\n";
        CHECK(false);  // should not happen
        return false;
    }
    void check_all_pos_found()
    {
        INFO("check all null were found (elements left: " << pos_null << ')');
        CHECK(pos_null.empty());
        INFO("check all boolean were found (elements left: " << pos_boolean << ')');
        CHECK(pos_boolean.empty());
        INFO("check all number_integer were found (elements left: " << pos_number_integer << ')');
        CHECK(pos_number_integer.empty());
        INFO("check all number_unsigned were found (elements left: " << pos_number_unsigned << ')');
        CHECK(pos_number_unsigned.empty());
        INFO("check all number_float were found (elements left: " << pos_number_float << ')');
        CHECK(pos_number_float.empty());
        INFO("check all string were found (elements left: " << pos_string << ')');
        CHECK(pos_string.empty());
        INFO("check all binary were found (elements left: " << pos_binary << ')');
        CHECK(pos_binary.empty());
        INFO("check all start_object were found (elements left: " << pos_start_object << ')');
        CHECK(pos_start_object.empty());
        INFO("check all key were found (elements left: " << pos_key << ')');
        CHECK(pos_key.empty());
        INFO("check all end_object were found (elements left: " << pos_end_object << ')');
        CHECK(pos_end_object.empty());
        INFO("check all start_array were found (elements left: " << pos_start_array << ')');
        CHECK(pos_start_array.empty());
        INFO("check all end_array were found (elements left: " << pos_end_array << ')');
        CHECK(pos_end_array.empty());
    }
};

template<bool WithPosV, bool WithLexV>
struct Opt
{
    static constexpr bool WithPos = WithPosV;
    static constexpr bool WithLex = WithLexV;
};

using OptNone = Opt<false, false>;
using OptLex = Opt<false, true>;
using OptPos = Opt<true, false>;
using OptBoth = Opt<true, true>;

//test basic functionality
TEST_CASE_TEMPLATE("extended parser", T, OptNone, OptLex, OptPos, OptBoth)
{
    const bool with_pos = T::WithPos;
    const bool with_lex = T::WithLex;

    INFO("WithPos " << with_pos << ", WithLex " << with_lex);
    //element count            0     1       2  3          4   5   6   7     8   9 10
    //index 10s place          0         1         2         3         4         5
    //index  1s place          012345678901234567890123456789012345678901234567890123
    const std::string str = R"({   "array" : [14294967296,-1,true,4.2,null,"str" ]  })";
    std::size_t elem_idx = 0;
    std::size_t char_idx = 0;
    const auto element = [&](std::size_t bytes)
    {
        const auto start = char_idx;
        char_idx += bytes;
        return element_info_t{elem_idx++, start, char_idx};
    };
    const auto skip = [&](std::size_t bytes)
    {
        char_idx += bytes;
    };
    SECTION("json")
    {
        std::string reconstructed;
        const auto elementFromStr = [&](const std::string & s)
        {
            reconstructed += s;
            return element(s.size());
        };
        const auto skipFromStr = [&](const std::string & s)
        {
            reconstructed += s;
            skip(s.size());
        };
        Sax</*LexCallImpossible*/ false, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(elementFromStr("{"));
        skipFromStr("   ");
        sax.pos_key.emplace(elementFromStr(R"("array")"));
        skipFromStr(" : ");
        sax.pos_start_array.emplace(elementFromStr("["));
        sax.pos_number_unsigned.emplace(elementFromStr("14294967296"));
        skipFromStr(",");
        sax.pos_number_integer.emplace(elementFromStr("-1"));
        skipFromStr(",");
        sax.pos_boolean.emplace(elementFromStr("true"));
        skipFromStr(",");
        sax.pos_number_float.emplace(elementFromStr("4.2"));
        skipFromStr(",");
        sax.pos_null.emplace(elementFromStr("null"));
        skipFromStr(",");
        sax.pos_string.emplace(elementFromStr(R"("str")"));
        skipFromStr(" ");
        sax.pos_end_array.emplace(elementFromStr("]"));
        skipFromStr("  ");
        sax.pos_end_object.emplace(elementFromStr("}"));
        CHECK(nlohmann::json::sax_parse(str, &sax, nlohmann::json::input_format_t::json));
        if (with_pos || with_lex)
        {
            sax.check_all_pos_found();
        }
        CHECK(char_idx == str.size());
        CHECK(str == reconstructed);
    }
    SECTION("bson")
    {
        const auto j = nlohmann::json::parse(str);
        const auto bin = nlohmann::json::to_bson(j);
        Sax</*LexCallImpossible*/ true, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(element(4));    //4 bytes size
        skip(1);                                     //one byte type array
        sax.pos_key.emplace(element(6));             //6 key (array\0)
        sax.pos_start_array.emplace(element(4));     //4 bytes size
        skip(3);                                     //one byte type + key 0\0
        sax.pos_number_integer.emplace(element(8));  //8 bytes int64
        skip(3);                                     //one byte type + key 1\0
        sax.pos_number_integer.emplace(element(4));  //4 bytes int32
        skip(3);                                     //one byte type + key 2\0
        sax.pos_boolean.emplace(element(1));         //1 byte bool
        skip(3);                                     //one byte type + key 3\0
        sax.pos_number_float.emplace(element(8));    //8 bytes double
        skip(3);                                     //one byte type + key 4\0
        sax.pos_null.emplace(element((0)));          //0 bytes
        skip(3);                                     //one byte type + key 4\0
        sax.pos_string.emplace(element(8));          //4 bytes size + (str\0)
        sax.pos_end_array.emplace(element(1));       //1 byte \0 end of array
        sax.pos_end_object.emplace(element(1));      //1 byte \0 end of object
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::bson));
        if (with_pos)
        {
            sax.check_all_pos_found();
        }
    }
    SECTION("cbor")
    {
        const auto j = nlohmann::json::parse(str);
        const auto bin = nlohmann::json::to_cbor(j);
        Sax</*LexCallImpossible*/ true, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(element(1));     //1 byte type + 0 bytes size (implicit in type)
        sax.pos_key.emplace(element(6));              //1 byte type + 5 bytes string (array) (size implicit)
        sax.pos_start_array.emplace(element(1));      //1 byte type + 0 bytes size (implicit in type)
        sax.pos_number_unsigned.emplace(element(9));  //1 byte type + 8 bytes uint64
        sax.pos_number_integer.emplace(element(1));   //1 byte type + 0 bytes int -> implicit value since small
        sax.pos_boolean.emplace(element(1));          //1 byte type + 0 byte bool (value in type)
        sax.pos_number_float.emplace(element(9));     //1 byte type + 8 bytes double
        sax.pos_null.emplace(element((1)));           //1 byte type + 0 bytes
        sax.pos_string.emplace(element(4));           //1 byte type + 3 bytes string (str) (size implicit)
        sax.pos_end_array.emplace(element(0));        //0 byte end of array
        sax.pos_end_object.emplace(element(0));       //0 byte end of object
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::cbor));
        if (with_pos)
        {
            sax.check_all_pos_found();
        }
    }
    SECTION("msgpack")
    {
        const auto j = nlohmann::json::parse(str);
        const auto bin = nlohmann::json::to_msgpack(j);
        Sax</*LexCallImpossible*/ true, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(element(1));     //1 byte type + 0 bytes size
        sax.pos_key.emplace(element(6));              //1 byte type + 5 bytes string (array) (size implicit)
        sax.pos_start_array.emplace(element(1));      //1 byte type + 0 bytes size (implicit in type)
        sax.pos_number_unsigned.emplace(element(9));  //1 byte type + 8 bytes uint64
        sax.pos_number_integer.emplace(element(1));   //1 byte type + 0 bytes int -> implicit value since small
        sax.pos_boolean.emplace(element(1));          //1 byte type + 0 byte bool (value in type)
        sax.pos_number_float.emplace(element(9));     //1 byte type + 8 bytes double
        sax.pos_null.emplace(element((1)));           //1 byte type + 0 bytes
        sax.pos_string.emplace(element(4));           //1 byte type + 3 bytes string (str) (size implicit)
        sax.pos_end_array.emplace(element(0));        //0 byte end of array
        sax.pos_end_object.emplace(element(0));       //0 byte end of object
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::msgpack));
        if (with_pos)
        {
            sax.check_all_pos_found();
        }
    }
    SECTION("ubjson")
    {
        const auto j = nlohmann::json::parse(str);
        const auto bin = nlohmann::json::to_ubjson(j);
        Sax</*LexCallImpossible*/ true, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(element(1));    //1 byte type + 0 bytes size
        sax.pos_key.emplace(element(7));             //1 byte type + 6 bytes string (array\0)
        sax.pos_start_array.emplace(element(1));     //1 byte type + 0 bytes size (implicit in type)
        sax.pos_number_integer.emplace(element(9));  //1 byte type + 8 bytes uint64
        sax.pos_number_integer.emplace(element(2));  //1 byte type + 1 bytes int8
        sax.pos_boolean.emplace(element(1));         //1 byte type + 0 byte bool (value in type)
        sax.pos_number_float.emplace(element(9));    //1 byte type + 8 bytes double
        sax.pos_null.emplace(element((1)));          //1 byte type + 0 bytes
        sax.pos_string.emplace(element(6));          //1 type + 1 type of len + 1 len +3 string (str)
        sax.pos_end_array.emplace(element(1));       //1 byte type + 0 byte end of array
        sax.pos_end_object.emplace(element(1));      //1 byte type + 0 byte end of object
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::ubjson));
        if (with_pos)
        {
            sax.check_all_pos_found();
        }
    }
    SECTION("bjdata")
    {
        const auto j = nlohmann::json::parse(str);
        const auto bin = nlohmann::json::to_bjdata(j);
        Sax</*LexCallImpossible*/ true, T::WithPos, T::WithLex> sax;
        sax.pos_start_object.emplace(element(1));    //1 byte type + 0 bytes size
        sax.pos_key.emplace(element(7));             //1 byte type + 6 bytes string (array\0)
        sax.pos_start_array.emplace(element(1));     //1 byte type + 0 bytes size (implicit in type)
        sax.pos_number_integer.emplace(element(9));  //1 byte type + 8 bytes uint64
        sax.pos_number_integer.emplace(element(2));  //1 byte type + 1 bytes int8
        sax.pos_boolean.emplace(element(1));         //1 byte type + 0 byte bool (value in type)
        sax.pos_number_float.emplace(element(9));    //1 byte type + 8 bytes double
        sax.pos_null.emplace(element((1)));          //1 byte type + 0 bytes
        sax.pos_string.emplace(element(6));          //1 type + 1 type of len + 1 len +3 string (str)
        sax.pos_end_array.emplace(element(1));       //1 byte type + 0 byte end of array
        sax.pos_end_object.emplace(element(1));      //1 byte type + 0 byte end of object
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::bjdata));
        if (with_pos)
        {
            sax.check_all_pos_found();
        }
    }
}

//cover more advanced cases (e.g. msgpack fixint) (but only use one templated version)
template<class SAX, class FN>
void fill_expected_sax_pos_json(SAX& sax,
                                const FN& element,
                                const nlohmann::json& part,
                                std::size_t& offset)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            sax.pos_null.emplace(element(4));  //null
        }
        break;
        case nlohmann::json::value_t::object:
        {
            sax.pos_start_object.emplace(element(1));  // {
            for (auto& el : part.items())
            {
                sax.pos_key.emplace(element(el.key().size() + 2));  //'"' + str + '"'
                offset += 1;                                        // separator ':' between key and value
                fill_expected_sax_pos_json(sax, element, el.value(), offset);
                offset += 1;  // add ,
            }
            if (!part.empty())
            {
                offset -= 1;  // remove last ,
            }
            sax.pos_end_object.emplace(element(1));  // }
        }
        break;
        case nlohmann::json::value_t::array:
        {
            sax.pos_start_array.emplace(element(1));  // [
            for (auto& el : part.items())
            {
                fill_expected_sax_pos_json(sax, element, el.value(), offset);
                offset += 1;  // add ,
            }
            if (!part.empty())
            {
                offset -= 1;  // remove last ,
            }
            sax.pos_end_array.emplace(element(1));  // ]
        }
        break;
        case nlohmann::json::value_t::string:
        {
            const auto val = part.get<std::string>();
            std::size_t nbytes = val.size() + 2;  //'"' + value + '"'
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            const auto val = part.get<bool>();
            if (val)
            {
                sax.pos_boolean.emplace(element(4));  // true
            }
            else
            {
                sax.pos_boolean.emplace(element(5));  // false
            }
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            const auto val = part.get<std::int64_t>();
            std::size_t nbytes = std::to_string(val).size();
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            const auto val = part.get<std::uint64_t>();
            std::size_t nbytes = std::to_string(val).size();
            sax.pos_number_unsigned.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            const auto val = part.get<double>();
            std::size_t nbytes = std::to_string(val).size();
            sax.pos_number_float.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            //stored as object with array and subtype
            nlohmann::json sub;
            sub["bytes"] = nlohmann::json::array();
            for (const auto e : part.get_binary())
            {
                sub["bytes"].emplace_back(e);
            }
            sub["subtype"];
            fill_expected_sax_pos_json(sax, element, sub, offset);
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

template<class SAX, class FN>
void fill_expected_sax_pos_bson(SAX& sax,
                                const FN& element,
                                const nlohmann::json& part,
                                std::size_t& offset)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            //type is before the key -> not included
            sax.pos_null.emplace(element(0));
        }
        break;
        case nlohmann::json::value_t::object:
        {
            sax.pos_start_object.emplace(element(4));  //32 bit size
            for (auto& el : part.items())
            {
                offset += 1;                                        // type of item
                sax.pos_key.emplace(element(el.key().size() + 1));  // str + terminator
                fill_expected_sax_pos_bson(sax, element, el.value(), offset);
            }
            sax.pos_end_object.emplace(element(1));  // \0 terminator
        }
        break;
        case nlohmann::json::value_t::array:
        {
            sax.pos_start_array.emplace(element(4));  //32 bit size
            std::size_t i = 0;
            for (auto& el : part.items())
            {
                offset += 1;                             // type of item
                offset += 1 + std::to_string(i).size();  // dummy key + terminator
                fill_expected_sax_pos_bson(sax, element, el.value(), offset);
                ++i;
            }
            sax.pos_end_array.emplace(element(1));  // \0 terminator
        }
        break;
        case nlohmann::json::value_t::string:
        {
            //type is before the key -> not included
            std::size_t nbytes = 4;  //size
            const auto val = part.get<std::string>();
            nbytes += val.size() + 1;  //value + \0 terminate
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            //type is before the key -> not included
            std::size_t nbytes = 1;  //value
            sax.pos_boolean.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::size_t nbytes = 0;  //type is before the key -> not included
            const auto val = part.get<std::int64_t>();
            //for <-24 : -n-1
            if (val >= 0)
            {
                std::cout << "unexpected int >= 0\n";
                throw std::logic_error{"unexpected int >= 0"};
            }
            if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            std::size_t nbytes = 0;  //type is before the key -> not included
            const auto val = part.get<std::uint64_t>();
            if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            std::size_t nbytes = 0;  //type is before the key -> not included
            nbytes += 8;             //value
            sax.pos_number_float.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            std::size_t nbytes = 0;  //type is before the key -> not included
            nbytes += 4;             // length of bin (32 bit)
            nbytes += 1;             // subtype
            nbytes += part.get_binary().size();
            sax.pos_binary.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

template<class SAX, class FN>
void fill_expected_sax_pos_cbor(SAX& sax, const FN& element, const nlohmann::json& part)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_null.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::object:
        {
            std::size_t nbytes = 1;  //type
            if (part.size() <= 0x17)
            {
                //size implicit in type
            }
            else if (part.size() <= std::numeric_limits<std::uint8_t>::max())
            {
                nbytes += 1;
            }
            else if (part.size() <= std::numeric_limits<std::uint16_t>::max())
            {
                nbytes += 2;
            }
            else if (part.size() <= std::numeric_limits<std::uint32_t>::max())
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_start_object.emplace(element(nbytes));
            //key follows same rules as string
            for (auto& el : part.items())
            {
                std::size_t nbyteskey = 1;  //type
                nbyteskey += el.key().size();
                if (el.key().size() <= 0x17)
                {
                    //size implicit in type
                }
                else if (el.key().size() <= std::numeric_limits<std::uint8_t>::max())
                {
                    nbyteskey += 1;
                }
                else if (el.key().size() <= std::numeric_limits<std::uint16_t>::max())
                {
                    nbyteskey += 2;
                }
                else if (el.key().size() <= std::numeric_limits<std::uint32_t>::max())
                {
                    nbyteskey += 4;
                }
                else
                {
                    nbyteskey += 8;
                }
                sax.pos_key.emplace(element(nbyteskey));
                fill_expected_sax_pos_cbor(sax, element, el.value());
            }
            sax.pos_end_object.emplace(element(0));
        }
        break;
        case nlohmann::json::value_t::array:
        {
            std::size_t nbytes = 1;  //type
            if (part.size() <= 0x17)
            {
                //size implicit in type
            }
            else if (part.size() <= std::numeric_limits<std::uint8_t>::max())
            {
                nbytes += 1;
            }
            else if (part.size() <= std::numeric_limits<std::uint16_t>::max())
            {
                nbytes += 2;
            }
            else if (part.size() <= std::numeric_limits<std::uint32_t>::max())
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_start_array.emplace(element(nbytes));
            //add elements
            for (const auto& elem : part)
            {
                fill_expected_sax_pos_cbor(sax, element, elem);
            }
            sax.pos_end_array.emplace(element(0));
        }
        break;
        case nlohmann::json::value_t::string:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::string>();
            nbytes += val.size();
            if (val.size() <= static_cast<std::size_t>(0x17))
            {
                //size implicit in type
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_boolean.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::int64_t>();
            //for <-24 : -n-1
            if (val >= 0)
            {
                std::cout << "unexpected int >= 0\n";
                throw std::logic_error{"unexpected int >= 0"};
            }
            if (val >= -24)
            {
                //value implicit in type
            }
            else if (-val - 1 <= static_cast<std::int64_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (-val - 1 <= static_cast<std::int64_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (-val - 1 <= static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::uint64_t>();
            if (val <= static_cast<std::uint64_t>(0x17))
            {
                //value implicit in type
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_unsigned.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<double>();
            //really depends on the input type
            if (val < 0)
            {
                std::cout << "unexpected float <0\n";
                throw std::logic_error{"unexpected float <0"};
            }
            if (val <= static_cast<double>(std::numeric_limits<float>::max()))
            {
                nbytes += 4;  //float
            }
            else
            {
                nbytes += 8;  //double float
            }
            sax.pos_number_float.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            std::size_t nbytes = 1;  //type
            const auto& val = part.get_binary();
            nbytes += val.size();
            if (val.size() <= static_cast<std::size_t>(0x17))
            {
                //size implicit in type
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_binary.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

template<class SAX, class FN>
void fill_expected_sax_pos_msgpack(SAX& sax, const FN& element, const nlohmann::json& part)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_null.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::object:
        {
            std::size_t nbytes = 1;  //type
            if (part.size() <= 0x0F)
            {
                //size implicit in type
            }
            else if (part.size() <= std::numeric_limits<std::uint16_t>::max())
            {
                nbytes += 2;
            }
            else if (part.size() <= std::numeric_limits<std::uint32_t>::max())
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_start_object.emplace(element(nbytes));
            //key follows same rules as string
            for (auto& el : part.items())
            {
                std::size_t nbyteskey = 1;  //type
                nbyteskey += el.key().size();
                if (el.key().size() <= 0x1F)
                {
                    //size implicit in type
                }
                else if (el.key().size() <= std::numeric_limits<std::uint8_t>::max())
                {
                    nbyteskey += 1;
                }
                else if (el.key().size() <= std::numeric_limits<std::uint16_t>::max())
                {
                    nbyteskey += 2;
                }
                else if (el.key().size() <= std::numeric_limits<std::uint32_t>::max())
                {
                    nbyteskey += 4;
                }
                else
                {
                    nbyteskey += 8;
                }
                sax.pos_key.emplace(element(nbyteskey));
                fill_expected_sax_pos_msgpack(sax, element, el.value());
            }
            sax.pos_end_object.emplace(element(0));
        }
        break;
        case nlohmann::json::value_t::array:
        {
            std::size_t nbytes = 1;  //type
            if (part.size() <= 0x0F)
            {
                //size implicit in type
            }
            else if (part.size() <= std::numeric_limits<std::uint16_t>::max())
            {
                nbytes += 2;
            }
            else if (part.size() <= std::numeric_limits<std::uint32_t>::max())
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_start_array.emplace(element(nbytes));
            //add elements
            for (const auto& elem : part)
            {
                fill_expected_sax_pos_msgpack(sax, element, elem);
            }
            sax.pos_end_array.emplace(element(0));
        }
        break;
        case nlohmann::json::value_t::string:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::string>();
            nbytes += val.size();
            if (val.size() <= static_cast<std::size_t>(0x1F))
            {
                //size implicit in type
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_boolean.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::int64_t>();
            //for <-24 : -n-1
            if (val >= 0)
            {
                std::cout << "unexpected int >= 0\n";
                throw std::logic_error{"unexpected int >= 0"};
            }
            if (val >= -32)
            {
                //value implicit in type
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int8_t>::min()))
            {
                nbytes += 1;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int16_t>::min()))
            {
                nbytes += 2;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::uint64_t>();
            if (val <= static_cast<std::uint64_t>(0x7F))
            {
                //value implicit in type
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_unsigned.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<double>();
            //really depends on the input type
            if (val < 0)
            {
                std::cout << "unexpected float <0\n";
                throw std::logic_error{"unexpected float <0"};
            }
            if (val <= static_cast<double>(std::numeric_limits<float>::max()))
            {
                nbytes += 4;  //float
            }
            else
            {
                nbytes += 8;  //double float
            }
            sax.pos_number_float.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            std::size_t nbytes = 1;  //type
            const auto& val = part.get_binary();
            nbytes += val.size();
            if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_binary.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

template<class SAX, class FN>
void fill_expected_sax_pos_ubjson(SAX& sax, const FN& element, const nlohmann::json& part)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_null.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::object:
        {
            sax.pos_start_object.emplace(element(1));
            //key follows same rules as string
            for (auto& el : part.items())
            {
                std::size_t nbyteskey = 1;  //type of len
                nbyteskey += el.key().size();
                if (el.key().size() <= std::numeric_limits<std::uint8_t>::max())
                {
                    nbyteskey += 1;  // size of len
                }
                else if (el.key().size() <= std::numeric_limits<std::uint16_t>::max())
                {
                    nbyteskey += 2;  // size of len
                }
                else if (el.key().size() <= std::numeric_limits<std::uint32_t>::max())
                {
                    nbyteskey += 4;  // size of len
                }
                else
                {
                    nbyteskey += 8;  // size of len
                }
                sax.pos_key.emplace(element(nbyteskey));
                fill_expected_sax_pos_ubjson(sax, element, el.value());
            }
            sax.pos_end_object.emplace(element(1));
        }
        break;
        case nlohmann::json::value_t::array:
        {
            sax.pos_start_array.emplace(element(1));
            //add elements
            for (const auto& elem : part)
            {
                fill_expected_sax_pos_ubjson(sax, element, elem);
            }
            sax.pos_end_array.emplace(element(1));
        }
        break;
        case nlohmann::json::value_t::string:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::string>();
            nbytes += val.size();
            nbytes += 1;  // type of length
            if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_boolean.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::int64_t>();
            //for <-24 : -n-1
            if (val >= 0)
            {
                std::cout << "unexpected int >= 0\n";
                throw std::logic_error{"unexpected int >= 0"};
            }
            if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int8_t>::min()))
            {
                nbytes += 1;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int16_t>::min()))
            {
                nbytes += 2;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            //supported integer types :
            // uint8
            // int8/16/32/64/High precision
            // --> only 128-255 are stored as uint + high precision > max int64
            bool use_uint = false;
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::uint64_t>();
            if (val < 128)
            {
                ++nbytes;
            }
            else if (val <= 255)
            {
                use_uint = true;
                ++nbytes;
            }
            else
            {
                //sorted as signed int!
                if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int8_t>::max()))
                {
                    nbytes += 1;
                }
                else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int16_t>::max()))
                {
                    nbytes += 2;
                }
                else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
                {
                    nbytes += 4;
                }
                else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                {
                    nbytes += 8;
                }
                else
                {
                    //High precision
                    //more complex calculation of size is not done here
                    //the size includes
                    // type (high precision)
                    // type of size of value length
                    // size of value length
                    // value as array of chars
                    //in this case
                    nbytes = 22;
                    if (val > std::numeric_limits<std::uint64_t>::max() - 128)
                    {
                        //in this test case the value needs one more char
                        nbytes += 1;
                    }
                    if (val > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                    {
                        use_uint = true;
                    }
                }
            }
            if (use_uint)
            {
                sax.pos_number_unsigned.emplace(element(nbytes));
            }
            else
            {
                sax.pos_number_integer.emplace(element(nbytes));
            }
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            //everything is serialized as double (type+double value)
            sax.pos_number_float.emplace(element(8 + 1));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            // Note, no reader for UBJSON binary types is implemented because they do
            auto sub = nlohmann::json::array();
            for (const auto i : part.get_binary())
            {
                sub.emplace_back(i);
            }
            fill_expected_sax_pos_ubjson(sax, element, sub);
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

template<class SAX, class FN>
void fill_expected_sax_pos_bjdata(SAX& sax, const FN& element, const nlohmann::json& part)
{
    switch (part.type())
    {
        case nlohmann::json::value_t::null:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_null.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::object:
        {
            sax.pos_start_object.emplace(element(1));
            //key follows same rules as string
            for (auto& el : part.items())
            {
                std::size_t nbyteskey = 1;  //type of len
                nbyteskey += el.key().size();
                if (el.key().size() <= std::numeric_limits<std::uint8_t>::max())
                {
                    nbyteskey += 1;  // size of len
                }
                else if (el.key().size() <= std::numeric_limits<std::uint16_t>::max())
                {
                    nbyteskey += 2;  // size of len
                }
                else if (el.key().size() <= std::numeric_limits<std::uint32_t>::max())
                {
                    nbyteskey += 4;  // size of len
                }
                else
                {
                    nbyteskey += 8;  // size of len
                }
                sax.pos_key.emplace(element(nbyteskey));
                fill_expected_sax_pos_bjdata(sax, element, el.value());
            }
            sax.pos_end_object.emplace(element(1));
        }
        break;
        case nlohmann::json::value_t::array:
        {
            sax.pos_start_array.emplace(element(1));
            //add elements
            for (const auto& elem : part)
            {
                fill_expected_sax_pos_bjdata(sax, element, elem);
            }
            sax.pos_end_array.emplace(element(1));
        }
        break;
        case nlohmann::json::value_t::string:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::string>();
            nbytes += val.size();
            nbytes += 1;  // type of length
            if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val.size() <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_string.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::boolean:
        {
            std::size_t nbytes = 1;  //type
            sax.pos_boolean.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_integer:
        {
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::int64_t>();
            if (val >= 0)
            {
                std::cout << "unexpected int >= 0\n";
                throw std::logic_error{"unexpected int >= 0"};
            }
            if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int8_t>::min()))
            {
                nbytes += 1;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int16_t>::min()))
            {
                nbytes += 2;
            }
            else if (val >= static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()))
            {
                nbytes += 4;
            }
            else
            {
                nbytes += 8;
            }
            sax.pos_number_integer.emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_unsigned:
        {
            auto* category = &sax.pos_number_unsigned;
            std::size_t nbytes = 1;  //type
            const auto val = part.get<std::uint64_t>();
            if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int8_t>::max()))
            {
                //the serializer uses int8 for these values
                category = &sax.pos_number_integer;
                nbytes += 1;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint8_t>::max()))
            {
                nbytes += 1;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int16_t>::max()))
            {
                //the serializer uses int6 for these values
                category = &sax.pos_number_integer;
                nbytes += 2;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint16_t>::max()))
            {
                nbytes += 2;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
            {
                //the serializer uses int32 for these values
                category = &sax.pos_number_integer;
                nbytes += 4;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                nbytes += 4;
            }
            else if (val <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            {
                //the serializer uses int64 for these values
                category = &sax.pos_number_integer;
                nbytes += 8;
            }
            else
            {
                nbytes += 8;
            }
            category->emplace(element(nbytes));
        }
        break;
        case nlohmann::json::value_t::number_float:
        {
            //everything is serialized as double (type+double value)
            sax.pos_number_float.emplace(element(8 + 1));
        }
        break;
        case nlohmann::json::value_t::binary:
        {
            // Note, no reader for UBJSON binary types is implemented because they do
            auto sub = nlohmann::json::array();
            for (const auto i : part.get_binary())
            {
                sub.emplace_back(i);
            }
            fill_expected_sax_pos_ubjson(sax, element, sub);
        }
        break;
        case nlohmann::json::value_t::discarded:
        {
            std::cout << "unexpected! value_t::discarded\n";
            throw std::logic_error{"unexpected! value_t::discarded"};
        }
        break;
        default:
            throw std::logic_error{"unexpected! default"};
    }
}

void test_json(nlohmann::json& json)
{
    Sax<true, true, false> sax;
    std::size_t elem_idx = 0;
    std::size_t char_idx = 0;
    const auto element = [&](std::size_t bytes)
    {
        const auto start = char_idx;
        char_idx += bytes;
        return element_info_t{elem_idx++, start, char_idx};
    };
    SECTION("json")
    {
        const auto bin = json.dump();
        std::cout << "json    has size of " << bin.size() << '\n';
        fill_expected_sax_pos_json(sax, element, json, char_idx);
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::json));
        sax.check_all_pos_found();
    }
    SECTION("bson")
    {
        //since bson can't deal with values > int64 max we need to remove some
        if (json.contains("uints"))
        {
            auto& ar = json["uints"];
            const std::uint64_t limit = std::numeric_limits<std::int64_t>::max();
            while (ar.back() > limit)
            {
                ar.erase(ar.size() - 1);
            }
        }
        const auto bin = nlohmann::json::to_bson(json);
        std::cout << "bson    has size of " << bin.size() << '\n';
        fill_expected_sax_pos_bson(sax, element, json, char_idx);
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::bson));
        sax.check_all_pos_found();
    }
    SECTION("cbor")
    {
        const auto bin = nlohmann::json::to_cbor(json);
        std::cout << "cbor    has size of " << bin.size() << '\n';
        fill_expected_sax_pos_cbor(sax, element, json);
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::cbor));
        sax.check_all_pos_found();
    }
    SECTION("msgpack")
    {
        const auto bin = nlohmann::json::to_msgpack(json);
        std::cout << "msgpack has size of " << bin.size() << '\n';
        fill_expected_sax_pos_msgpack(sax, element, json);
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::msgpack));
        sax.check_all_pos_found();
    }
    SECTION("ubjson")
    {
        const auto bin = nlohmann::json::to_ubjson(json);
        std::cout << "ubjson  has size of " << bin.size() << '\n';
        fill_expected_sax_pos_ubjson(sax, element, json);
        CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::ubjson));
        sax.check_all_pos_found();
    }
    SECTION("bjdata")
    {
        const auto bin = nlohmann::json::to_bjdata(json);
        std::cout << "bjdata  has size of " << bin.size() << '\n';
        fill_expected_sax_pos_bjdata(sax, element, json);
        //CHECK(char_idx == bin.size());
        CHECK(nlohmann::json::sax_parse(bin, &sax, nlohmann::json::input_format_t::bjdata));
        sax.check_all_pos_found();
    }
}

TEST_CASE("extended parser generated (uint)")
{
    std::cout << "extended parser generated (uint)          ";
    nlohmann::json json;
    auto& array = json["uints"];
    for (std::uint64_t i = 0; i < 512; ++i)
    {
        array.emplace_back(i);
    }
    //check area around key points
    const auto add_area = [&](std::uint64_t mid, std::uint64_t lower, std::uint64_t higher)
    {
        for (std::uint64_t i = mid - lower; i < mid + higher; ++i)
        {
            array.emplace_back(i);
        }
        array.emplace_back(mid + higher);
    };
    add_area(std::numeric_limits<std::int16_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint16_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint16_t>::max(), 32, 32);

    add_area(std::numeric_limits<std::int32_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint32_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint32_t>::max(), 32, 32);

    add_area(std::numeric_limits<std::int64_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint64_t>::max() / 2, 32, 32);
    add_area(std::numeric_limits<std::uint64_t>::max(), 32, 0);
    test_json(json);
}
TEST_CASE("extended parser generated (int)")
{
    std::cout << "extended parser generated (int)           ";
    nlohmann::json json;
    auto& array = json["ints"];
    for (std::int64_t i = -512; i <= -1; ++i)
    {
        array.emplace_back(i);
    }
    //check area around key points
    const auto add_area = [&](std::int64_t mid, std::int64_t lower, std::int64_t higher)
    {
        for (std::int64_t i = mid - lower; i <= mid + higher; ++i)
        {
            array.emplace_back(i);
        }
    };
    add_area(std::numeric_limits<std::int16_t>::min(), 32, 32);
    add_area(std::numeric_limits<std::int32_t>::min(), 32, 32);
    add_area(std::numeric_limits<std::int32_t>::min(), 32, 32);
    add_area(std::numeric_limits<std::int64_t>::min(), 0, 32);
    test_json(json);
}
TEST_CASE("extended parser generated (array / bool)")
{
    std::cout << "extended parser generated (array / bool)  ";
    nlohmann::json json;
    auto& array = json["arrays"];
    array = nlohmann::json::array();
    for (std::uint64_t i = 0; i < 512; ++i)
    {
        auto sub = nlohmann::json::array();
        for (std::uint64_t j = 0; j < i; ++j)
        {
            sub.emplace_back((j % 2 == 0));
        }
        array.emplace_back(std::move(sub));
    }
    //add large aray
    auto sub = nlohmann::json::array();
    for (std::uint64_t j = 0; j < std::numeric_limits<std::uint16_t>::max() + 1; ++j)
    {
        sub.emplace_back((j % 2 == 0));
    }
    array.emplace_back(std::move(sub));
    test_json(json);
}
TEST_CASE("extended parser generated (object / null)")
{
    std::cout << "extended parser generated (object / null) ";
    nlohmann::json json;
    auto& array = json["objects"];
    array = nlohmann::json::array();
    for (std::uint64_t i = 0; i < 512; ++i)
    {
        auto sub = nlohmann::json::object();
        for (std::uint64_t j = 0; j < i; ++j)
        {
            sub[std::string(static_cast<unsigned int>(j), 'k')];

        }
        array.emplace_back(std::move(sub));
    }
    //add object with long keý
    auto sub = nlohmann::json::object();
    sub[std::string(std::numeric_limits<std::uint16_t>::max() + 1, 'k')];
    array.emplace_back(std::move(sub));
    test_json(json);
}
TEST_CASE("extended parser generated (string)")
{
    std::cout << "extended parser generated (string)        ";
    nlohmann::json json;
    auto& array = json["strings"];
    array = nlohmann::json::array();
    for (std::uint64_t i = 0; i < 512; ++i)
    {
        array.emplace_back(std::string(static_cast<unsigned int>(i), '|'));
    }
    array.emplace_back(std::string(std::numeric_limits<std::uint16_t>::max() + 1, '|'));
    //test with large strings (e.g. requiring uint64 as size type) are not done
    test_json(json);
}
TEST_CASE("extended parser generated (binary)")
{
    std::cout << "extended parser generated (binary)        ";
    nlohmann::json json;
    auto& array = json["binary"];
    array = nlohmann::json::array();
    for (std::uint64_t i = 0; i < 512; ++i)
    {
        array.emplace_back(nlohmann::json::binary(std::vector<std::uint8_t>(static_cast<unsigned int>(i), 255)));
    }
    //add large binary
    std::vector<std::uint8_t> data(std::numeric_limits<std::uint16_t>::max() + 1, 255);
    array.emplace_back(nlohmann::json::binary(std::move(data)));
    test_json(json);
}
