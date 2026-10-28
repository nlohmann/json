//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Use cases of the nativejson-benchmark files, jeopardy and one twitter status with every C++ library in one binary:
// validate, sum, select, edit, minify, write (see README.md). A library may implement a use case in every reasonable
// way ("variants": other APIs, SAX, in-situ parsing, reused parsers). Before timing, every variant must produce the
// right result on the file (else it is printed as "excluded" and not timed), and it is probed with malformed input
// derived from the file, which gives its validation level: "full", "no UTF-8" or "partial" (printed in its cell).
// All variants of a use case run interleaved in every round, each timed call after an untimed one, and the best round
// is reported (same method as tests/benchmarks/json_view/bench_view.cpp).
//
// Input contract: the input is a const std::string holding the file with at least 64 bytes of spare capacity, so
// simdjson can use it without a copy. A variant that modifies its input copies it inside the timed call. Each timed
// call starts from the text and frees everything it built, except variants named "(reused)".
//
// Usage: bench_all <json_test_data dir> [rounds] [document] [use case]
#include <nlohmann/json_view.hpp>

#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <boost/json/basic_parser_impl.hpp>
#if !BENCH_NO_GLAZE
    #include <glaze/glaze.hpp>
    #include <glaze/json/lazy.hpp>
#endif
#include <rapidjson/document.h>
#include <rapidjson/encodedstream.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <simdjson.h>
#include <sonic/sonic.h>
#include <yyjson.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using nlohmann::json;
using nlohmann::json_document;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;
using nlohmann::json_view;
using nlohmann::ordered_json;

static volatile double g_sink;

struct stats
{
    double num = 0;
    std::size_t str = 0, nodes = 0;
};

// what a variant returns besides success: the stats (sum), the selected value (select), or the output text
// (edit, minify, write; only copied when out is set, i.e., when checking)
struct result
{
    stats st;
    double acc = 0;
    std::string* out = nullptr;
};

static bool emit(result& r, const char* p, std::size_t n)
{
    r.acc = static_cast<double>(n);
    if (r.out != nullptr)
    {
        r.out->assign(p, n);
    }
    return true;
}

static bool emit(result& r, std::string&& o)
{
    r.acc = static_cast<double>(o.size());
    if (r.out != nullptr)
    {
        *r.out = std::move(o);
    }
    return true;
}

// RapidJSON: correctly rounded floats, as every other library, and UTF-8 validation
constexpr unsigned rj_flags = rapidjson::kParseFullPrecisionFlag | rapidjson::kParseValidateEncodingFlag;

// Boost.JSON: correctly rounded floats (the default is number_precision::imprecise)
static boost::json::parse_options bj_opts()
{
    boost::json::parse_options o;
    o.numbers = boost::json::number_precision::precise;
    return o;
}
static const boost::json::parse_options bj_precise = bj_opts();

///////////////////////////////////////////////////////////////////////////////
// sum: walk a DOM, visit every value, convert every number, touch every string and key
///////////////////////////////////////////////////////////////////////////////

// ---- json::parse
static void walk(const json& j, stats& st)
{
    ++st.nodes;
    switch (j.type())
    {
        case json::value_t::object:
            for (const auto& kv : j.get_ref<const json::object_t&>())
            {
                st.str += kv.first.size();
                walk(kv.second, st);
            }
            break;
        case json::value_t::array:
            for (const auto& e : j.get_ref<const json::array_t&>())
            {
                walk(e, st);
            }
            break;
        case json::value_t::string:
            st.str += j.get_ref<const std::string&>().size();
            break;
        case json::value_t::number_integer:
            st.num += static_cast<double>(*j.get_ptr<const json::number_integer_t*>());
            break;
        case json::value_t::number_unsigned:
            st.num += static_cast<double>(*j.get_ptr<const json::number_unsigned_t*>());
            break;
        case json::value_t::number_float:
            st.num += *j.get_ptr<const json::number_float_t*>();
            break;
        default:
            break;
    }
}

// ---- json_view
static void walk(json_view v, stats& st)
{
    ++st.nodes;
    switch (v.type())
    {
        case json::value_t::object:
            for (auto it = v.begin(); it != v.end(); ++it)
            {
                st.str += it.key().size();
                walk(*it, st);
            }
            break;
        case json::value_t::array:
            for (const json_view e : v)
            {
                walk(e, st);
            }
            break;
        case json::value_t::string:
            st.str += v.get_string().size();
            break;
        case json::value_t::number_integer:
            st.num += static_cast<double>(v.get<std::int64_t>());
            break;
        case json::value_t::number_unsigned:
            st.num += static_cast<double>(v.get<std::uint64_t>());
            break;
        case json::value_t::number_float:
            st.num += v.get<double>();
            break;
        default:
            break;
    }
}

// ---- json::sax_parse: the same visit without a DOM, in document order
struct json_sum_sax
{
    stats* st;
    bool null()
    {
        ++st->nodes;
        return true;
    }
    bool boolean(bool /*b*/)
    {
        ++st->nodes;
        return true;
    }
    bool number_integer(json::number_integer_t i)
    {
        ++st->nodes;
        st->num += static_cast<double>(i);
        return true;
    }
    bool number_unsigned(json::number_unsigned_t u)
    {
        ++st->nodes;
        st->num += static_cast<double>(u);
        return true;
    }
    bool number_float(json::number_float_t f, const json::string_t& /*s*/)
    {
        ++st->nodes;
        st->num += f;
        return true;
    }
    bool string(json::string_t& s)
    {
        ++st->nodes;
        st->str += s.size();
        return true;
    }
    bool binary(json::binary_t& /*b*/)
    {
        return true;
    }
    bool start_object(std::size_t /*n*/)
    {
        ++st->nodes;
        return true;
    }
    bool key(json::string_t& k)
    {
        st->str += k.size();
        return true;
    }
    bool end_object()
    {
        return true;
    }
    bool start_array(std::size_t /*n*/)
    {
        ++st->nodes;
        return true;
    }
    bool end_array()
    {
        return true;
    }
    bool parse_error(std::size_t /*pos*/, const std::string& /*tok*/, const json::exception& /*ex*/)
    {
        return false;
    }
};

// ---- yyjson
static void walk(yyjson_val* v, stats& st)
{
    ++st.nodes;
    switch (yyjson_get_type(v))
    {
        case YYJSON_TYPE_OBJ:
        {
            std::size_t idx, max;
            yyjson_val* k, * val;
            yyjson_obj_foreach(v, idx, max, k, val)
            {
                st.str += yyjson_get_len(k);
                walk(val, st);
            }
            break;
        }
        case YYJSON_TYPE_ARR:
        {
            std::size_t idx, max;
            yyjson_val* val;
            yyjson_arr_foreach(v, idx, max, val) walk(val, st);
            break;
        }
        case YYJSON_TYPE_STR:
            st.str += yyjson_get_len(v);
            break;
        case YYJSON_TYPE_NUM:
            if (yyjson_is_sint(v))
            {
                st.num += static_cast<double>(yyjson_get_sint(v));
            }
            else if (yyjson_is_uint(v))
            {
                st.num += static_cast<double>(yyjson_get_uint(v));
            }
            else
            {
                st.num += yyjson_get_real(v);
            }
            break;
        default:
            break;
    }
}

// yyjson in situ: the input is copied into a padded, mutable buffer
struct yy_insitu
{
    char* buf = nullptr;
    yyjson_doc* doc = nullptr;
    explicit yy_insitu(const std::string& s)
        : buf(static_cast<char*>(std::malloc(s.size() + YYJSON_PADDING_SIZE)))
    {
        std::memcpy(buf, s.data(), s.size());
        std::memset(buf + s.size(), 0, YYJSON_PADDING_SIZE);
        doc = yyjson_read_opts(buf, s.size(), YYJSON_READ_INSITU, nullptr, nullptr);
    }
    yy_insitu(const yy_insitu&) = delete;
    yy_insitu& operator=(const yy_insitu&) = delete;
    ~yy_insitu()
    {
        yyjson_doc_free(doc);
        std::free(buf);
    }
};

// ---- simdjson DOM and On-Demand
static void walk(simdjson::dom::element e, stats& st)
{
    ++st.nodes;
    switch (e.type())
    {
        case simdjson::dom::element_type::OBJECT:
            for (auto f : simdjson::dom::object(e))
            {
                st.str += f.key.size();
                walk(f.value, st);
            }
            break;
        case simdjson::dom::element_type::ARRAY:
            for (auto c : simdjson::dom::array(e))
            {
                walk(c, st);
            }
            break;
        case simdjson::dom::element_type::STRING:
            st.str += std::string_view(e).size();
            break;
        case simdjson::dom::element_type::INT64:
            st.num += static_cast<double>(int64_t(e));
            break;
        case simdjson::dom::element_type::UINT64:
            st.num += static_cast<double>(uint64_t(e));
            break;
        case simdjson::dom::element_type::DOUBLE:
            st.num += double(e);
            break;
        default:
            break;
    }
}

static void walk_od(simdjson::ondemand::value v, stats& st)
{
    ++st.nodes;
    switch (v.type())
    {
        case simdjson::ondemand::json_type::object:
            for (auto f : v.get_object())
            {
                st.str += std::string_view(f.unescaped_key()).size();
                walk_od(f.value(), st);
            }
            break;
        case simdjson::ondemand::json_type::array:
            for (auto c : v.get_array())
            {
                walk_od(c.value(), st);
            }
            break;
        case simdjson::ondemand::json_type::string:
            st.str += std::string_view(v.get_string()).size();
            break;
        case simdjson::ondemand::json_type::number:
        {
            simdjson::ondemand::number n = v.get_number();
            switch (n.get_number_type())
            {
                case simdjson::ondemand::number_type::signed_integer:
                    st.num += static_cast<double>(n.get_int64());
                    break;
                case simdjson::ondemand::number_type::unsigned_integer:
                    st.num += static_cast<double>(n.get_uint64());
                    break;
                default:
                    st.num += n.get_double();
                    break;
            }
            break;
        }
        case simdjson::ondemand::json_type::boolean:
            (void)bool(v.get_bool());
            break;
        default:
            if (!v.is_null())
            {
                throw simdjson::simdjson_error(simdjson::INCORRECT_TYPE);
            }
            break;
    }
}

// ---- RapidJSON DOM and SAX
static void walk(const rapidjson::Value& v, stats& st)
{
    ++st.nodes;
    switch (v.GetType())
    {
        case rapidjson::kObjectType:
            for (auto m = v.MemberBegin(); m != v.MemberEnd(); ++m)
            {
                st.str += m->name.GetStringLength();
                walk(m->value, st);
            }
            break;
        case rapidjson::kArrayType:
            for (const auto& e : v.GetArray())
            {
                walk(e, st);
            }
            break;
        case rapidjson::kStringType:
            st.str += v.GetStringLength();
            break;
        case rapidjson::kNumberType:
            if (v.IsDouble())
            {
                st.num += v.GetDouble();
            }
            else if (v.IsInt64())
            {
                st.num += static_cast<double>(v.GetInt64());
            }
            else
            {
                st.num += static_cast<double>(v.GetUint64());
            }
            break;
        default:
            break;
    }
}

struct rj_sum : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, rj_sum>
{
    stats* st;
    explicit rj_sum(stats* s) : st(s) {}
    bool Null()
    {
        ++st->nodes;
        return true;
    }
    bool Bool(bool /*b*/)
    {
        ++st->nodes;
        return true;
    }
    bool Int(int i)
    {
        ++st->nodes;
        st->num += static_cast<double>(i);
        return true;
    }
    bool Uint(unsigned u)
    {
        ++st->nodes;
        st->num += static_cast<double>(u);
        return true;
    }
    bool Int64(std::int64_t i)
    {
        ++st->nodes;
        st->num += static_cast<double>(i);
        return true;
    }
    bool Uint64(std::uint64_t u)
    {
        ++st->nodes;
        st->num += static_cast<double>(u);
        return true;
    }
    bool Double(double d)
    {
        ++st->nodes;
        st->num += d;
        return true;
    }
    bool String(const char* /*s*/, rapidjson::SizeType n, bool /*copy*/)
    {
        ++st->nodes;
        st->str += n;
        return true;
    }
    bool Key(const char* /*s*/, rapidjson::SizeType n, bool /*copy*/)
    {
        st->str += n;
        return true;
    }
    bool StartObject()
    {
        ++st->nodes;
        return true;
    }
    bool EndObject(rapidjson::SizeType /*n*/)
    {
        return true;
    }
    bool StartArray()
    {
        ++st->nodes;
        return true;
    }
    bool EndArray(rapidjson::SizeType /*n*/)
    {
        return true;
    }
};

// RapidJSON's Reader on (data, size), as Document::Parse(data, size) does it
template<unsigned Flags, class Handler>
static bool rj_read(const std::string& s, Handler& h)
{
    rapidjson::MemoryStream ms(s.data(), s.size());
    rapidjson::EncodedInputStream<rapidjson::UTF8<>, rapidjson::MemoryStream> is(ms);
    rapidjson::Reader reader;
    return !reader.Parse<Flags>(is, h).IsError();
}

// RapidJSON's Writer writes a raw number (kParseNumbersAsStringsFlag) as a string: write its text instead
struct rj_raw_writer : rapidjson::Writer<rapidjson::StringBuffer>
{
    using Writer::Writer;
    bool RawNumber(const char* str, rapidjson::SizeType n, bool /*copy*/)
    {
        return RawValue(str, n, rapidjson::kNumberType);
    }
};

// ---- sonic-cpp
template<class N>
static void walk_sonic(const N& v, stats& st)
{
    ++st.nodes;
    if (v.IsObject())
    {
        for (auto m = v.MemberBegin(); m != v.MemberEnd(); ++m)
        {
            st.str += m->name.GetStringView().size();
            walk_sonic(m->value, st);
        }
    }
    else if (v.IsArray())
    {
        for (auto e = v.Begin(); e != v.End(); ++e)
        {
            walk_sonic(*e, st);
        }
    }
    else if (v.IsString())
    {
        st.str += v.GetStringView().size();
    }
    else if (v.IsNumber())
    {
        if (v.IsDouble())
        {
            st.num += v.GetDouble();
        }
        else if (v.IsUint64())
        {
            st.num += static_cast<double>(v.GetUint64());
        }
        else
        {
            st.num += static_cast<double>(v.GetInt64());
        }
    }
}

#if !BENCH_NO_GLAZE
// ---- Glaze generic_u64 (owning DOM) and lazy_json (on demand)
static void walk(const glz::generic_u64& j, stats& st)
{
    ++st.nodes;
    std::visit([&](const auto & x)
    {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, glz::generic_u64::object_t>)
        {
            for (const auto& [k, v] : x)
            {
                st.str += k.size();
                walk(v, st);
            }
        }
        else if constexpr (std::is_same_v<T, glz::generic_u64::array_t>)
        {
            for (const auto& e : x)
            {
                walk(e, st);
            }
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            st.str += x.size();
        }
        else if constexpr (std::is_same_v<T, double> || std::is_same_v<T, std::int64_t> || std::is_same_v<T, std::uint64_t>)
        {
            st.num += static_cast<double>(x);
        }
    }, j.data);
}

template<class V>
static void walk_lazy(const V& v, stats& st)
{
    ++st.nodes;
    if (v.is_object())
    {
        for (auto item : v)
        {
            st.str += item.key().size();
            walk_lazy(item, st);
        }
    }
    else if (v.is_array())
    {
        for (auto item : v)
        {
            walk_lazy(item, st);
        }
    }
    else if (v.is_string())
    {
        st.str += v.template get<std::string>().value().size();
    }
    else if (v.is_number())
    {
        const std::string_view raw = v.raw_json();
        if (raw.find_first_of(".eE") != std::string_view::npos)
        {
            st.num += v.template get<double>().value();
        }
        else if (raw[0] == '-')
        {
            st.num += static_cast<double>(v.template get<std::int64_t>().value());
        }
        else
        {
            st.num += static_cast<double>(v.template get<std::uint64_t>().value());
        }
    }
}
#endif

// ---- Boost.JSON DOM and basic_parser (SAX)
static void walk(const boost::json::value& v, stats& st)
{
    ++st.nodes;
    switch (v.kind())
    {
        case boost::json::kind::object:
            for (const auto& kv : v.get_object())
            {
                st.str += kv.key().size();
                walk(kv.value(), st);
            }
            break;
        case boost::json::kind::array:
            for (const auto& c : v.get_array())
            {
                walk(c, st);
            }
            break;
        case boost::json::kind::string:
            st.str += v.get_string().size();
            break;
        case boost::json::kind::int64:
            st.num += static_cast<double>(v.get_int64());
            break;
        case boost::json::kind::uint64:
            st.num += static_cast<double>(v.get_uint64());
            break;
        case boost::json::kind::double_:
            st.num += v.get_double();
            break;
        default:
            break;
    }
}

struct bj_null
{
    using ec_t = boost::system::error_code;
    using sv_t = boost::json::string_view;
    static constexpr std::size_t max_array_size = static_cast<std::size_t>(-1);
    static constexpr std::size_t max_object_size = static_cast<std::size_t>(-1);
    static constexpr std::size_t max_string_size = static_cast<std::size_t>(-1);
    static constexpr std::size_t max_key_size = static_cast<std::size_t>(-1);
    bool on_document_begin(ec_t& /*ec*/)
    {
        return true;
    }
    bool on_document_end(ec_t& /*ec*/)
    {
        return true;
    }
    bool on_array_begin(ec_t& /*ec*/)
    {
        return true;
    }
    bool on_array_end(std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_object_begin(ec_t& /*ec*/)
    {
        return true;
    }
    bool on_object_end(std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_string_part(sv_t /*s*/, std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_string(sv_t /*s*/, std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_key_part(sv_t /*s*/, std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_key(sv_t /*s*/, std::size_t /*n*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_number_part(sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_int64(std::int64_t /*i*/, sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_uint64(std::uint64_t /*u*/, sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_double(double /*d*/, sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_bool(bool /*b*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_null(ec_t& /*ec*/)
    {
        return true;
    }
    bool on_comment_part(sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
    bool on_comment(sv_t /*s*/, ec_t& /*ec*/)
    {
        return true;
    }
};

struct bj_sum : bj_null
{
    stats* st;
    explicit bj_sum(stats* s) : st(s) {}
    bool on_array_begin(ec_t& /*ec*/)
    {
        ++st->nodes;
        return true;
    }
    bool on_object_begin(ec_t& /*ec*/)
    {
        ++st->nodes;
        return true;
    }
    bool on_string(sv_t /*s*/, std::size_t n, ec_t& /*ec*/)
    {
        ++st->nodes;
        st->str += n;
        return true;
    }
    bool on_key(sv_t /*s*/, std::size_t n, ec_t& /*ec*/)
    {
        st->str += n;
        return true;
    }
    bool on_int64(std::int64_t i, sv_t /*s*/, ec_t& /*ec*/)
    {
        ++st->nodes;
        st->num += static_cast<double>(i);
        return true;
    }
    bool on_uint64(std::uint64_t u, sv_t /*s*/, ec_t& /*ec*/)
    {
        ++st->nodes;
        st->num += static_cast<double>(u);
        return true;
    }
    bool on_double(double d, sv_t /*s*/, ec_t& /*ec*/)
    {
        ++st->nodes;
        st->num += d;
        return true;
    }
    bool on_bool(bool /*b*/, ec_t& /*ec*/)
    {
        ++st->nodes;
        return true;
    }
    bool on_null(ec_t& /*ec*/)
    {
        ++st->nodes;
        return true;
    }
};

template<class Handler, class... Args>
static bool bj_sax(const std::string& s, Args&& ... args)
{
    boost::json::basic_parser<Handler> p(bj_precise, std::forward<Args>(args)...);
    boost::system::error_code ec;
    const std::size_t n = p.write_some(false, s.data(), s.size(), ec);
    return !ec && n == s.size();
}

///////////////////////////////////////////////////////////////////////////////
// select: read a few fields of every record (the fields of bench_view.cpp), one accessor per DOM
///////////////////////////////////////////////////////////////////////////////

struct acc_json
{
    using V = const json*;
    static V get(V v, const char* k)
    {
        return &(*v)[k];
    }
    static V at(V v, std::size_t i)
    {
        return &(*v)[i];
    }
    static std::uint64_t u64(V v)
    {
        return v->get<std::uint64_t>();
    }
    static std::int64_t i64(V v)
    {
        return v->get<std::int64_t>();
    }
    static std::string_view str(V v)
    {
        return v->get_ref<const std::string&>();
    }
    static std::size_t size(V v)
    {
        return v->size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (const json& e : *v)
        {
            f(&e);
        }
    }
};

struct acc_view
{
    using V = json_view;
    static V get(V v, const char* k)
    {
        return v[k];
    }
    static V at(V v, std::size_t i)
    {
        return v[i];
    }
    static std::uint64_t u64(V v)
    {
        return v.get<std::uint64_t>();
    }
    static std::int64_t i64(V v)
    {
        return v.get<std::int64_t>();
    }
    static std::string_view str(V v)
    {
        const auto s = v.get_string();
        return {s.data(), s.size()};
    }
    static std::size_t size(V v)
    {
        return v.size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (const json_view e : v)
        {
            f(e);
        }
    }
};

struct acc_yyjson
{
    using V = yyjson_val*;
    static V get(V v, const char* k)
    {
        return yyjson_obj_get(v, k);
    }
    static V at(V v, std::size_t i)
    {
        return yyjson_arr_get(v, i);
    }
    static std::uint64_t u64(V v)
    {
        return yyjson_get_uint(v);
    }
    static std::int64_t i64(V v)
    {
        return yyjson_get_sint(v);
    }
    static std::string_view str(V v)
    {
        return {yyjson_get_str(v), yyjson_get_len(v)};
    }
    static std::size_t size(V v)
    {
        return yyjson_is_arr(v) ? yyjson_arr_size(v) : yyjson_obj_size(v);
    }
    template<class F> static void each(V v, F&& f)
    {
        std::size_t idx, max;
        yyjson_val* e;
        yyjson_arr_foreach(v, idx, max, e)
        {
            f(e);
        }
    }
};

struct acc_simdjson
{
    using V = simdjson::dom::element;
    static V get(V v, const char* k)
    {
        return v[k].value();
    }
    static V at(V v, std::size_t i)
    {
        return v.at(i).value();
    }
    static std::uint64_t u64(V v)
    {
        return uint64_t(v);
    }
    static std::int64_t i64(V v)
    {
        return int64_t(v);
    }
    static std::string_view str(V v)
    {
        return std::string_view(v);
    }
    static std::size_t size(V v)
    {
        return v.is_array() ? simdjson::dom::array(v).size() : simdjson::dom::object(v).size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (V e : simdjson::dom::array(v))
        {
            f(e);
        }
    }
};

struct acc_rapidjson
{
    using V = const rapidjson::Value*;
    static V get(V v, const char* k)
    {
        return &(*v)[k];
    }
    static V at(V v, std::size_t i)
    {
        return &(*v)[static_cast<rapidjson::SizeType>(i)];
    }
    static std::uint64_t u64(V v)
    {
        return v->GetUint64();
    }
    static std::int64_t i64(V v)
    {
        return v->GetInt64();
    }
    static std::string_view str(V v)
    {
        return {v->GetString(), v->GetStringLength()};
    }
    static std::size_t size(V v)
    {
        return v->IsArray() ? v->Size() : v->MemberCount();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (const auto& e : v->GetArray())
        {
            f(&e);
        }
    }
};

struct acc_sonic
{
    using V = const sonic_json::Node*;
    static V get(V v, const char* k)
    {
        return &(*v)[k];
    }
    static V at(V v, std::size_t i)
    {
        return &(*v)[i];
    }
    static std::uint64_t u64(V v)
    {
        return v->GetUint64();
    }
    static std::int64_t i64(V v)
    {
        return v->GetInt64();
    }
    static std::string_view str(V v)
    {
        const auto s = v->GetStringView();
        return {s.data(), s.size()};
    }
    static std::size_t size(V v)
    {
        return v->Size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (auto e = v->Begin(); e != v->End(); ++e)
        {
            f(&*e);
        }
    }
};

struct acc_boost
{
    using V = const boost::json::value*;
    static V get(V v, const char* k)
    {
        return &v->get_object().at(k);
    }
    static V at(V v, std::size_t i)
    {
        return &v->get_array().at(i);
    }
    static std::uint64_t u64(V v)
    {
        return v->to_number<std::uint64_t>();
    }
    static std::int64_t i64(V v)
    {
        return v->to_number<std::int64_t>();
    }
    static std::string_view str(V v)
    {
        const auto& s = v->get_string();
        return {s.data(), s.size()};
    }
    static std::size_t size(V v)
    {
        return v->is_array() ? v->get_array().size() : v->get_object().size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (const auto& e : v->get_array())
        {
            f(&e);
        }
    }
};

#if !BENCH_NO_GLAZE
struct acc_glaze
{
    using V = const glz::generic_u64*;
    static V get(V v, const char* k)
    {
        return &(*v)[k];
    }
    static V at(V v, std::size_t i)
    {
        return &v->get_array()[i];
    }
    static std::uint64_t u64(V v)
    {
        return std::get<std::uint64_t>(v->data);
    }
    static std::int64_t i64(V v)
    {
        const auto* u = std::get_if<std::uint64_t>(&v->data);
        return u != nullptr ? static_cast<std::int64_t>(*u) : std::get<std::int64_t>(v->data);
    }
    static std::string_view str(V v)
    {
        return std::get<std::string>(v->data);
    }
    static std::size_t size(V v)
    {
        return v->is_array() ? v->get_array().size() : v->get_object().size();
    }
    template<class F> static void each(V v, F&& f)
    {
        for (const auto& e : v->get_array())
        {
            f(&e);
        }
    }
};
#endif

template<class A>
static double pick(const std::string& name, typename A::V r)
{
    using V = typename A::V;
    double acc = 0;
    auto status = [&](V s)
    {
        acc += static_cast<double>(A::u64(A::get(s, "id")));
        acc += static_cast<double>(A::str(A::get(A::get(s, "user"), "screen_name")).size());
        acc += static_cast<double>(A::i64(A::get(s, "retweet_count")));
    };
    if (name == "twitter")
    {
        A::each(A::get(r, "statuses"), status);
    }
    else if (name == "status")
    {
        status(r);
    }
    else if (name == "citm_catalog")
    {
        A::each(A::get(r, "performances"), [&](V p)
        {
            acc += static_cast<double>(A::u64(A::get(p, "id")) + A::u64(A::get(p, "eventId")) + A::size(A::get(p, "seatCategories")));
        });
        acc += static_cast<double>(A::size(A::get(r, "events")));
    }
    else if (name == "canada")
    {
        const V g = A::get(A::at(A::get(r, "features"), 0), "geometry");
        acc += static_cast<double>(A::str(A::get(r, "type")).size() + A::str(A::get(g, "type")).size() + A::size(A::get(g, "coordinates")));
    }
    else if (name == "jeopardy")
    {
        A::each(r, [&](V q)
        {
            acc += A::str(A::get(q, "round")) == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(A::str(A::get(q, "category")).size());
        });
    }
    return acc;
}

static double pick_od(const std::string& name, simdjson::ondemand::document& d)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](simdjson::ondemand::object s)
        {
            acc += static_cast<double>(uint64_t(s["id"]));
            acc += static_cast<double>(std::string_view(s["user"]["screen_name"]).size());
            acc += static_cast<double>(int64_t(s["retweet_count"]));
        };
        if (name == "twitter")
        {
            for (auto s : d["statuses"])
            {
                one(s.get_object());
            }
        }
        else
        {
            one(d.get_object());
        }
    }
    else if (name == "citm_catalog")
    {
        simdjson::ondemand::object ev = d["events"].get_object();
        acc += static_cast<double>(ev.count_fields());
        for (auto p : d["performances"])
        {
            simdjson::ondemand::object o = p.get_object();
            const auto a = uint64_t(o["eventId"]) + uint64_t(o["id"]);
            simdjson::ondemand::array sc = o["seatCategories"].get_array();
            acc += static_cast<double>(a + sc.count_elements());
        }
    }
    else if (name == "canada")
    {
        acc += static_cast<double>(std::string_view(d["type"]).size());
        auto g = d["features"].at(0)["geometry"];
        acc += static_cast<double>(std::string_view(g["type"]).size());
        simdjson::ondemand::array co = g["coordinates"].get_array();
        acc += static_cast<double>(co.count_elements());
    }
    else if (name == "jeopardy")
    {
        for (auto q : d)
        {
            simdjson::ondemand::object o = q.get_object();
            acc += static_cast<double>(std::string_view(o["category"]).size());
            acc += std::string_view(o["round"]) == "Final Jeopardy!" ? 1 : 0;
        }
    }
    return acc;
}

// nlohmann/json reading into structs with from_json(): the NLOHMANN_DEFINE_TYPE_* macros, from a json value
// (json::parse(s).get<T>()) and from a view (json_document::parse(s).root().get<T>()), into the fields that Glaze's
// and serde's structs declare; members that are only counted read into count_only
namespace nsel
{
struct count_only
{
    std::size_t n = 0;
};
template < typename J, typename std::enable_if < nlohmann::is_json_view<J>::value || std::is_same<J, json>::value, int >::type = 0 >
void from_json(const J& j, count_only& c)
{
    c.n = j.size();
}
struct user
{
    std::string screen_name;
};
struct status
{
    std::uint64_t id{};
    nsel::user user;
    std::int64_t retweet_count{};
};
struct twitter
{
    std::vector<status> statuses;
};
struct performance
{
    std::uint64_t id{};
    std::uint64_t eventId{};
    count_only seatCategories;
};
struct citm
{
    std::map<std::string, count_only> events;
    std::vector<performance> performances;
};
struct geometry
{
    std::string type;
    count_only coordinates;
};
struct feature
{
    nsel::geometry geometry;
};
struct canada
{
    std::string type;
    std::vector<feature> features;
};
struct question
{
    std::string category;
    std::string round;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(user, screen_name)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(status, id, user, retweet_count)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(twitter, statuses)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(performance, id, eventId, seatCategories)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(citm, events, performances)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(geometry, type, coordinates)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(feature, geometry)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(canada, type, features)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(question, category, round)
} // namespace nsel

template<class J>
static double pick_nlohmann_structs(const std::string& name, const J& j)
{
    double acc = 0;
    auto one = [&](const nsel::status & x)
    {
        acc += static_cast<double>(x.id);
        acc += static_cast<double>(x.user.screen_name.size());
        acc += static_cast<double>(x.retweet_count);
    };
    if (name == "twitter")
    {
        for (const auto& x : j.template get<nsel::twitter>().statuses)
        {
            one(x);
        }
    }
    else if (name == "status")
    {
        one(j.template get<nsel::status>());
    }
    else if (name == "citm_catalog")
    {
        const auto c = j.template get<nsel::citm>();
        for (const auto& p : c.performances)
        {
            acc += static_cast<double>(p.id + p.eventId + p.seatCategories.n);
        }
        acc += static_cast<double>(c.events.size());
    }
    else if (name == "canada")
    {
        const auto c = j.template get<nsel::canada>();
        acc += static_cast<double>(c.type.size() + c.features[0].geometry.type.size() + c.features[0].geometry.coordinates.n);
    }
    else if (name == "jeopardy")
    {
        for (const auto& x : j.template get<std::vector<nsel::question>>())
        {
            acc += x.round == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(x.category.size());
        }
    }
    return acc;
}

#if !BENCH_NO_GLAZE
// Glaze reading into structs that declare only the fields the selection uses; unknown keys are skipped
namespace sel
{
struct user
{
    std::string screen_name;
};
struct status
{
    std::uint64_t id{};
    sel::user user;
    std::int64_t retweet_count{};
};
struct twitter
{
    std::vector<status> statuses;
};
struct performance
{
    std::uint64_t id{};
    std::uint64_t eventId{};
    std::vector<glz::raw_json_view> seatCategories;
};
struct citm
{
    std::map<std::string, glz::raw_json_view> events;
    std::vector<performance> performances;
};
struct geometry
{
    std::string type;
    std::vector<glz::raw_json_view> coordinates;
};
struct feature
{
    sel::geometry geometry;
};
struct canada
{
    std::string type;
    std::vector<feature> features;
};
struct question
{
    std::string category;
    std::string round;
};
} // namespace sel

// validate_skipped: Glaze's option to validate the values it skips (an extension of glz::opts, hence the struct)
struct sel_opts_validated : glz::opts
{
    bool validate_skipped = true;
};
constexpr glz::opts sel_opts_fast{.error_on_unknown_keys = false};
constexpr sel_opts_validated sel_opts_full{{.error_on_unknown_keys = false}};

template<auto sel_opts>
static bool pick_glaze_structs(const std::string& name, const std::string& s, double& acc)
{
    acc = 0;
    auto one = [&](const sel::status & x)
    {
        acc += static_cast<double>(x.id);
        acc += static_cast<double>(x.user.screen_name.size());
        acc += static_cast<double>(x.retweet_count);
    };
    if (name == "twitter")
    {
        sel::twitter t;
        if (glz::read<sel_opts>(t, s))
        {
            return false;
        }
        for (const auto& x : t.statuses)
        {
            one(x);
        }
    }
    else if (name == "status")
    {
        sel::status x;
        if (glz::read<sel_opts>(x, s))
        {
            return false;
        }
        one(x);
    }
    else if (name == "citm_catalog")
    {
        sel::citm c;
        if (glz::read<sel_opts>(c, s))
        {
            return false;
        }
        for (const auto& p : c.performances)
        {
            acc += static_cast<double>(p.id + p.eventId + p.seatCategories.size());
        }
        acc += static_cast<double>(c.events.size());
    }
    else if (name == "canada")
    {
        sel::canada c;
        if (glz::read<sel_opts>(c, s))
        {
            return false;
        }
        acc += static_cast<double>(c.type.size() + c.features[0].geometry.type.size() + c.features[0].geometry.coordinates.size());
    }
    else if (name == "jeopardy")
    {
        std::vector<sel::question> q;
        if (glz::read<sel_opts>(q, s))
        {
            return false;
        }
        for (const auto& x : q)
        {
            acc += x.round == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(x.category.size());
        }
    }
    return true;
}

template<class D>
static double pick_glaze_lazy(const std::string& name, const D& d)
{
    double acc = 0;
    auto one = [&](const auto & x)
    {
        acc += static_cast<double>(x["id"].template get<std::uint64_t>().value());
        acc += static_cast<double>(x["user"]["screen_name"].template get<std::string>().value().size());
        acc += static_cast<double>(x["retweet_count"].template get<std::int64_t>().value());
    };
    if (name == "twitter")
    {
        for (auto x : d["statuses"])
        {
            one(x);
        }
    }
    else if (name == "status")
    {
        one(d.root());
    }
    else if (name == "citm_catalog")
    {
        for (auto p : d["performances"])
        {
            acc += static_cast<double>(p["id"].template get<std::uint64_t>().value() + p["eventId"].template get<std::uint64_t>().value() + p["seatCategories"].size());
        }
        acc += static_cast<double>(d["events"].size());
    }
    else if (name == "canada")
    {
        auto g = d["features"][0]["geometry"];
        acc += static_cast<double>(d["type"].template get<std::string>().value().size() + g["type"].template get<std::string>().value().size() + g["coordinates"].size());
    }
    else if (name == "jeopardy")
    {
        for (auto q : d.root())
        {
            acc += q["round"].template get<std::string>().value() == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(q["category"].template get<std::string>().value().size());
        }
    }
    return acc;
}
#endif

///////////////////////////////////////////////////////////////////////////////
// edit: change some values of every record and write the document as compact JSON
//   twitter (and status): for every status: retweet_count + 1, erase "entities", add "seen": true
//   citm_catalog: for every performance: start + 1, erase "seatMapImage", add "seen": true
//   canada: features[0].properties.name = "Kanada"; append [0.5,0.25] to coordinates[0] of every feature
//   jeopardy: for every record: value = null, erase "air_date", add "seen": true
///////////////////////////////////////////////////////////////////////////////

// basic_json: the reference for every other library, and the json/ordered_json variants
template<class J>
static void edit(const std::string& name, J& r)
{
    auto status = [](J & s)
    {
        s["retweet_count"] = s["retweet_count"].template get<std::int64_t>() + 1;
        s.erase("entities");
        s["seen"] = true;
    };
    if (name == "twitter")
    {
        for (J& s : r["statuses"])
        {
            status(s);
        }
    }
    else if (name == "status")
    {
        status(r);
    }
    else if (name == "citm_catalog")
    {
        for (J& p : r["performances"])
        {
            p["start"] = p["start"].template get<std::int64_t>() + 1;
            p.erase("seatMapImage");
            p["seen"] = true;
        }
    }
    else if (name == "canada")
    {
        r["features"][0]["properties"]["name"] = "Kanada";
        for (J& f : r["features"])
        {
            f["geometry"]["coordinates"][0].push_back(J::array({0.5, 0.25}));
        }
    }
    else if (name == "jeopardy")
    {
        for (J& q : r)
        {
            q["value"] = nullptr;
            q.erase("air_date");
            q["seen"] = true;
        }
    }
}

static bool edit_document(const std::string& name, const std::string& s, result& res, bool source_numbers)
{
    json_editable_document d = json_editable_document::parse(s);
    const json_editable_view r = d.root();
    auto status = [&](json_editable_view st)
    {
        d.set(st, "retweet_count", st["retweet_count"].get<std::int64_t>() + 1);
        d.erase(st, "entities");
        d.set(st, "seen", true);
    };
    if (name == "twitter")
    {
        for (const json_editable_view st : r["statuses"])
        {
            status(st);
        }
    }
    else if (name == "status")
    {
        status(r);
    }
    else if (name == "citm_catalog")
    {
        for (const json_editable_view p : r["performances"])
        {
            d.set(p, "start", p["start"].get<std::int64_t>() + 1);
            d.erase(p, "seatMapImage");
            d.set(p, "seen", true);
        }
    }
    else if (name == "canada")
    {
        d.set(r["features"][0]["properties"], "name", "Kanada");
        for (const json_editable_view f : r["features"])
        {
            d.push_back(f["geometry"]["coordinates"][0], json::array({0.5, 0.25}));
        }
    }
    else if (name == "jeopardy")
    {
        for (const json_editable_view q : r)
        {
            d.set(q, "value", nullptr);
            d.erase(q, "air_date");
            d.set(q, "seen", true);
        }
    }
    return emit(res, source_numbers ? r.dump(-1, ' ', false, json_editable_view::number_format::source) : r.dump());
}

static std::int64_t yy_int(const yyjson_mut_val* v)
{
    return yyjson_mut_is_uint(v) ? static_cast<std::int64_t>(yyjson_mut_get_uint(v)) : yyjson_mut_get_sint(v);
}

static bool edit_yyjson(const std::string& name, yyjson_doc* idoc, result& res)
{
    if (idoc == nullptr)
    {
        return false;
    }
    yyjson_mut_doc* d = yyjson_doc_mut_copy(idoc, nullptr);
    yyjson_mut_val* r = yyjson_mut_doc_get_root(d);
    auto get = [](yyjson_mut_val * o, const char* k)
    {
        return yyjson_mut_obj_get(o, k);
    };
    auto status = [&](yyjson_mut_val * st)
    {
        yyjson_mut_val* rc = get(st, "retweet_count");
        yyjson_mut_set_sint(rc, yy_int(rc) + 1);
        yyjson_mut_obj_remove_key(st, "entities");
        yyjson_mut_obj_add_bool(d, st, "seen", true);
    };
    std::size_t idx, max;
    yyjson_mut_val* e;
    if (name == "twitter")
    {
        yyjson_mut_arr_foreach(get(r, "statuses"), idx, max, e)
        {
            status(e);
        }
    }
    else if (name == "status")
    {
        status(r);
    }
    else if (name == "citm_catalog")
    {
        yyjson_mut_arr_foreach(get(r, "performances"), idx, max, e)
        {
            yyjson_mut_val* start = get(e, "start");
            yyjson_mut_set_sint(start, yy_int(start) + 1);
            yyjson_mut_obj_remove_key(e, "seatMapImage");
            yyjson_mut_obj_add_bool(d, e, "seen", true);
        }
    }
    else if (name == "canada")
    {
        static const double point[2] = {0.5, 0.25};
        yyjson_mut_val* features = get(r, "features");
        yyjson_mut_set_str(get(get(yyjson_mut_arr_get(features, 0), "properties"), "name"), "Kanada");
        yyjson_mut_arr_foreach(features, idx, max, e)
        {
            yyjson_mut_arr_append(yyjson_mut_arr_get(get(get(e, "geometry"), "coordinates"), 0), yyjson_mut_arr_with_real(d, point, 2));
        }
    }
    else if (name == "jeopardy")
    {
        yyjson_mut_arr_foreach(r, idx, max, e)
        {
            yyjson_mut_set_null(get(e, "value"));
            yyjson_mut_obj_remove_key(e, "air_date");
            yyjson_mut_obj_add_bool(d, e, "seen", true);
        }
    }
    std::size_t n = 0;
    char* o = yyjson_mut_write(d, 0, &n);
    const bool ok = o != nullptr && emit(res, o, n);
    std::free(o);
    yyjson_mut_doc_free(d);
    return ok;
}

static bool edit_rapidjson(const std::string& name, rapidjson::Document& d, result& res)
{
    auto& a = d.GetAllocator();
    auto status = [&](rapidjson::Value & st)
    {
        auto& rc = st["retweet_count"];
        rc.SetInt64(rc.GetInt64() + 1);
        st.RemoveMember("entities");
        st.AddMember("seen", true, a);
    };
    if (name == "twitter")
    {
        for (auto& st : d["statuses"].GetArray())
        {
            status(st);
        }
    }
    else if (name == "status")
    {
        status(d);
    }
    else if (name == "citm_catalog")
    {
        for (auto& p : d["performances"].GetArray())
        {
            auto& start = p["start"];
            start.SetInt64(start.GetInt64() + 1);
            p.RemoveMember("seatMapImage");
            p.AddMember("seen", true, a);
        }
    }
    else if (name == "canada")
    {
        d["features"][0u]["properties"]["name"].SetString("Kanada");
        for (auto& f : d["features"].GetArray())
        {
            rapidjson::Value point(rapidjson::kArrayType);
            point.PushBack(0.5, a).PushBack(0.25, a);
            f["geometry"]["coordinates"][0u].PushBack(point, a);
        }
    }
    else if (name == "jeopardy")
    {
        for (auto& q : d.GetArray())
        {
            q["value"].SetNull();
            q.RemoveMember("air_date");
            q.AddMember("seen", true, a);
        }
    }
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> w(sb);
    return d.Accept(w) && emit(res, sb.GetString(), sb.GetSize());
}

static bool edit_sonic(const std::string& name, const std::string& s, result& res)
{
    sonic_json::Document d;
    d.Parse(s.data(), s.size());
    if (d.HasParseError())
    {
        return false;
    }
    auto& a = d.GetAllocator();
    auto status = [&](sonic_json::Node & st)
    {
        auto& rc = st["retweet_count"];
        rc.SetInt64(rc.GetInt64() + 1);
        st.RemoveMember("entities");
        st.AddMember("seen", sonic_json::Node(true), a);
    };
    if (name == "twitter")
    {
        auto& sts = d["statuses"];
        for (auto it = sts.Begin(); it != sts.End(); ++it)
        {
            status(*it);
        }
    }
    else if (name == "status")
    {
        status(d);
    }
    else if (name == "citm_catalog")
    {
        auto& ps = d["performances"];
        for (auto it = ps.Begin(); it != ps.End(); ++it)
        {
            auto& start = (*it)["start"];
            start.SetInt64(start.GetInt64() + 1);
            it->RemoveMember("seatMapImage");
            it->AddMember("seen", sonic_json::Node(true), a);
        }
    }
    else if (name == "canada")
    {
        auto& fs = d["features"];
        fs[std::size_t{0}]["properties"]["name"].SetString("Kanada", 6, a);
        for (auto it = fs.Begin(); it != fs.End(); ++it)
        {
            sonic_json::Node point(sonic_json::kArray);
            point.PushBack(sonic_json::Node(0.5), a);
            point.PushBack(sonic_json::Node(0.25), a);
            (*it)["geometry"]["coordinates"][std::size_t{0}].PushBack(std::move(point), a);
        }
    }
    else if (name == "jeopardy")
    {
        for (auto it = d.Begin(); it != d.End(); ++it)
        {
            (*it)["value"].SetNull();
            it->RemoveMember("air_date");
            it->AddMember("seen", sonic_json::Node(true), a);
        }
    }
    sonic_json::WriteBuffer wb;
    return d.Serialize(wb) == sonic_json::kErrorNone && emit(res, wb.ToString(), wb.Size());
}

#if !BENCH_NO_GLAZE
static void glaze_inc(glz::generic_u64& v)
{
    if (auto* u = std::get_if<std::uint64_t>(&v.data))
    {
        ++*u;
    }
    else
    {
        ++std::get<std::int64_t>(v.data);
    }
}

static bool edit_glaze(const std::string& name, const std::string& s, result& res)
{
    glz::generic_u64 j;
    if (glz::read_json(j, s))
    {
        return false;
    }
    auto status = [](glz::generic_u64 & st)
    {
        glaze_inc(st["retweet_count"]);
        st.get_object().erase("entities");
        st["seen"].data = true;
    };
    if (name == "twitter")
    {
        for (auto& st : j["statuses"].get_array())
        {
            status(st);
        }
    }
    else if (name == "status")
    {
        status(j);
    }
    else if (name == "citm_catalog")
    {
        for (auto& p : j["performances"].get_array())
        {
            glaze_inc(p["start"]);
            p.get_object().erase("seatMapImage");
            p["seen"].data = true;
        }
    }
    else if (name == "canada")
    {
        j["features"][0]["properties"]["name"].data = std::string("Kanada");
        for (auto& f : j["features"].get_array())
        {
            glz::generic_u64 point;
            point.data = glz::generic_u64::array_t(2);
            point.get_array()[0].data = 0.5;
            point.get_array()[1].data = 0.25;
            f["geometry"]["coordinates"][0].get_array().push_back(std::move(point));
        }
    }
    else if (name == "jeopardy")
    {
        for (auto& q : j.get_array())
        {
            q["value"].data = nullptr;
            q.get_object().erase("air_date");
            q["seen"].data = true;
        }
    }
    std::string o;
    return !glz::write_json(j, o) && emit(res, std::move(o));
}
#endif

static bool edit_boost(const std::string& name, const std::string& s, result& res)
{
    boost::json::monotonic_resource mr;
    boost::system::error_code ec;
    boost::json::value v = boost::json::parse(s, ec, &mr, bj_precise);
    if (ec)
    {
        return false;
    }
    auto status = [](boost::json::object & o)
    {
        boost::json::value& rc = o["retweet_count"];
        rc = rc.to_number<std::int64_t>() + 1;
        o.erase("entities");
        o["seen"] = true;
    };
    if (name == "twitter")
    {
        for (auto& st : v.as_object()["statuses"].as_array())
        {
            status(st.as_object());
        }
    }
    else if (name == "status")
    {
        status(v.as_object());
    }
    else if (name == "citm_catalog")
    {
        for (auto& p : v.as_object()["performances"].as_array())
        {
            auto& o = p.as_object();
            boost::json::value& start = o["start"];
            start = start.to_number<std::int64_t>() + 1;
            o.erase("seatMapImage");
            o["seen"] = true;
        }
    }
    else if (name == "canada")
    {
        auto& fs = v.as_object()["features"].as_array();
        fs.at(0).as_object()["properties"].as_object()["name"] = "Kanada";
        for (auto& f : fs)
        {
            auto& ring = f.as_object()["geometry"].as_object()["coordinates"].as_array().at(0).as_array();
            ring.push_back(boost::json::array({0.5, 0.25}, ring.storage()));
        }
    }
    else if (name == "jeopardy")
    {
        for (auto& q : v.as_array())
        {
            auto& o = q.as_object();
            o["value"] = nullptr;
            o.erase("air_date");
            o["seen"] = true;
        }
    }
    return emit(res, boost::json::serialize(v));
}

///////////////////////////////////////////////////////////////////////////////
// variants
///////////////////////////////////////////////////////////////////////////////

struct variant
{
    std::string name;   // "<library>: <variant>"
    std::function<bool(const std::string&, result&)> fn;
    bool any_order = false;   // sum: visits objects in key order, so its sum may differ in the last bits
};

struct context
{
    std::string name;   // document
    json_document& reused;
    simdjson::dom::parser& sj;
    simdjson::ondemand::parser& od;
};

static std::vector<variant> validate_variants(context& c)
{
    return
    {
        {"nlohmann json_document: accept", [](const std::string & s, result&) { return json_document::accept(s); }},
        {"nlohmann json_document: parse", [](const std::string & s, result & r) { auto d = json_document::parse(s); r.acc = static_cast<double>(d.node_count()); return true; }},
        {"nlohmann json_document: read (reused)", [&c](const std::string & s, result & r) { c.reused.read(s); r.acc = static_cast<double>(c.reused.node_count()); return true; }},
        {"nlohmann json: accept", [](const std::string & s, result&) { return json::accept(s); }},
        {"nlohmann json: parse", [](const std::string & s, result & r) { json j = json::parse(s); r.acc = static_cast<double>(j.size()); return true; }},
        {"yyjson: read", [](const std::string & s, result&) { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); const bool ok = d != nullptr; yyjson_doc_free(d); return ok; }},
        {"yyjson: insitu (copy)", [](const std::string & s, result&) { yy_insitu d(s); return d.doc != nullptr; }},
        {"simdjson: DOM", [](const std::string & s, result&) { simdjson::dom::parser p; return !p.parse(s).error(); }},
        {"simdjson: DOM (reused)", [&c](const std::string & s, result&) { return !c.sj.parse(s).error(); }},
        {"sonic-cpp: Document", [](const std::string & s, result&) { sonic_json::Document d; d.Parse(s.data(), s.size()); return !d.HasParseError(); }},
#if !BENCH_NO_GLAZE
        {"Glaze: validate_json", [](const std::string & s, result&) { return !glz::validate_json(s); }},
        {"Glaze: generic", [](const std::string & s, result&) { glz::generic_u64 j; return !glz::read_json(j, s); }},
#endif
        {"Boost.JSON: SAX", [](const std::string & s, result&) { return bj_sax<bj_null>(s); }},
        {"Boost.JSON: parse", [](const std::string & s, result&) { boost::json::monotonic_resource mr; boost::system::error_code ec; auto v = boost::json::parse(s, ec, &mr, bj_precise); return !ec; }},
    };
}

static std::vector<variant> sum_variants(context& c)
{
    return
    {
        {"nlohmann json_document: parse", [](const std::string & s, result & r) { auto d = json_document::parse(s); walk(d.root(), r.st); return true; }},
        {"nlohmann json_document: read (reused)", [&c](const std::string & s, result & r) { c.reused.read(s); walk(c.reused.root(), r.st); return true; }},
        {"nlohmann json: parse", [](const std::string & s, result & r) { json j = json::parse(s); walk(j, r.st); return true; }, true},
        {"nlohmann json: sax", [](const std::string & s, result & r) { json_sum_sax h{&r.st}; return json::sax_parse(s, &h); }},
        {"yyjson: read", [](const std::string & s, result & r) { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); if (d == nullptr) { return false; } walk(yyjson_doc_get_root(d), r.st); yyjson_doc_free(d); return true; }},
        {"yyjson: insitu (copy)", [](const std::string & s, result & r) { yy_insitu d(s); if (d.doc == nullptr) { return false; } walk(yyjson_doc_get_root(d.doc), r.st); return true; }},
        {"simdjson: DOM", [](const std::string & s, result & r) { simdjson::dom::parser p; auto e = p.parse(s); if (e.error()) { return false; } walk(e.value_unsafe(), r.st); return true; }},
        {"simdjson: DOM (reused)", [&c](const std::string & s, result & r) { auto e = c.sj.parse(s); if (e.error()) { return false; } walk(e.value_unsafe(), r.st); return true; }},
        {"simdjson: On-Demand", [](const std::string & s, result & r) { simdjson::ondemand::parser p; auto d = p.iterate(s).value(); walk_od(d.get_value().value(), r.st); return d.at_end(); }},
        {"simdjson: On-Demand (reused)", [&c](const std::string & s, result & r) { auto d = c.od.iterate(s).value(); walk_od(d.get_value().value(), r.st); return d.at_end(); }},
        {"sonic-cpp: Document", [](const std::string & s, result & r) { sonic_json::Document d; d.Parse(s.data(), s.size()); if (d.HasParseError()) { return false; } walk_sonic(d, r.st); return true; }},
#if !BENCH_NO_GLAZE
        {"Glaze: generic", [](const std::string & s, result & r) { glz::generic_u64 j; if (glz::read_json(j, s)) { return false; } walk(j, r.st); return true; }},
        {"Glaze: lazy_json", [](const std::string & s, result & r) { auto l = glz::lazy_json(s); if (!l) { return false; } walk_lazy(l->root(), r.st); return true; }},
#endif
        {"Boost.JSON: parse", [](const std::string & s, result & r) { boost::json::monotonic_resource mr; boost::system::error_code ec; auto v = boost::json::parse(s, ec, &mr, bj_precise); if (ec) { return false; } walk(v, r.st); return true; }},
        {"Boost.JSON: SAX", [](const std::string & s, result & r) { return bj_sax<bj_sum>(s, &r.st); }},
    };
}

static std::vector<variant> select_variants(context& c)
{
    const std::string n = c.name;
    return
    {
        {"nlohmann json_document: parse", [n](const std::string & s, result & r) { auto d = json_document::parse(s); r.acc = pick<acc_view>(n, d.root()); return true; }},
        {"nlohmann json_document: read (reused)", [&c, n](const std::string & s, result & r) { c.reused.read(s); r.acc = pick<acc_view>(n, c.reused.root()); return true; }},
        {"nlohmann json: parse", [n](const std::string & s, result & r) { json j = json::parse(s); r.acc = pick<acc_json>(n, &j); return true; }},
        {"nlohmann json_document: structs (from_json)", [n](const std::string & s, result & r) { auto d = json_document::parse(s); r.acc = pick_nlohmann_structs(n, d.root()); return true; }},
        {"nlohmann json: structs (from_json)", [n](const std::string & s, result & r) { r.acc = pick_nlohmann_structs(n, json::parse(s)); return true; }},
        {"yyjson: read", [n](const std::string & s, result & r) { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); if (d == nullptr) { return false; } r.acc = pick<acc_yyjson>(n, yyjson_doc_get_root(d)); yyjson_doc_free(d); return true; }},
        {"yyjson: insitu (copy)", [n](const std::string & s, result & r) { yy_insitu d(s); if (d.doc == nullptr) { return false; } r.acc = pick<acc_yyjson>(n, yyjson_doc_get_root(d.doc)); return true; }},
        {"simdjson: DOM", [n](const std::string & s, result & r) { simdjson::dom::parser p; auto e = p.parse(s); if (e.error()) { return false; } r.acc = pick<acc_simdjson>(n, e.value_unsafe()); return true; }},
        {"simdjson: DOM (reused)", [&c, n](const std::string & s, result & r) { auto e = c.sj.parse(s); if (e.error()) { return false; } r.acc = pick<acc_simdjson>(n, e.value_unsafe()); return true; }},
        {"simdjson: On-Demand", [n](const std::string & s, result & r) { simdjson::ondemand::parser p; auto d = p.iterate(s).value(); r.acc = pick_od(n, d); return true; }},
        {"simdjson: On-Demand (reused)", [&c, n](const std::string & s, result & r) { auto d = c.od.iterate(s).value(); r.acc = pick_od(n, d); return true; }},
        {"sonic-cpp: Document", [n](const std::string & s, result & r) { sonic_json::Document d; d.Parse(s.data(), s.size()); if (d.HasParseError()) { return false; } r.acc = pick<acc_sonic>(n, &d); return true; }},
#if !BENCH_NO_GLAZE
        {"Glaze: structs", [n](const std::string & s, result & r) { return pick_glaze_structs<sel_opts_fast>(n, s, r.acc); }},
        {"Glaze: structs (validate_skipped)", [n](const std::string & s, result & r) { return pick_glaze_structs<sel_opts_full>(n, s, r.acc); }},
        {"Glaze: generic", [n](const std::string & s, result & r) { glz::generic_u64 j; if (glz::read_json(j, s)) { return false; } r.acc = pick<acc_glaze>(n, &j); return true; }},
        {"Glaze: lazy_json", [n](const std::string & s, result & r) { auto l = glz::lazy_json(s); if (!l) { return false; } r.acc = pick_glaze_lazy(n, *l); return true; }},
#endif
        {"Boost.JSON: parse", [n](const std::string & s, result & r) { boost::json::monotonic_resource mr; boost::system::error_code ec; auto v = boost::json::parse(s, ec, &mr, bj_precise); if (ec) { return false; } r.acc = pick<acc_boost>(n, &v); return true; }},
    };
}

static std::vector<variant> edit_variants(context& c)
{
    const std::string n = c.name;
    return
    {
        {"nlohmann json_document: editable", [n](const std::string & s, result & r) { return edit_document(n, s, r, false); }},
        {"nlohmann json_document: editable (source numbers)", [n](const std::string & s, result & r) { return edit_document(n, s, r, true); }},
        {"nlohmann json: parse", [n](const std::string & s, result & r) { json j = json::parse(s); edit(n, j); return emit(r, j.dump()); }},
        {"nlohmann json: ordered_json", [n](const std::string & s, result & r) { ordered_json j = ordered_json::parse(s); edit(n, j); return emit(r, j.dump()); }},
        {"yyjson: mut copy", [n](const std::string & s, result & r) { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); const bool ok = edit_yyjson(n, d, r); yyjson_doc_free(d); return ok; }},
        {"yyjson: insitu (copy) + mut copy", [n](const std::string & s, result & r) { yy_insitu d(s); return edit_yyjson(n, d.doc, r); }},
        {"sonic-cpp: Document", [n](const std::string & s, result & r) { return edit_sonic(n, s, r); }},
#if !BENCH_NO_GLAZE
        {"Glaze: generic", [n](const std::string & s, result & r) { return edit_glaze(n, s, r); }},
#endif
        {"Boost.JSON: parse", [n](const std::string & s, result & r) { return edit_boost(n, s, r); }},
    };
}

static std::vector<variant> minify_variants(context& c)
{
    return
    {
        {"nlohmann json_document: parse + dump", [](const std::string & s, result & r) { auto d = json_document::parse(s); return emit(r, d.root().dump()); }},
        {"nlohmann json_document: parse + dump (source numbers)", [](const std::string & s, result & r) { auto d = json_document::parse(s); return emit(r, d.root().dump(-1, ' ', false, json_view::number_format::source)); }},
        {"nlohmann json_document: read + dump (reused)", [&c](const std::string & s, result & r) { c.reused.read(s); return emit(r, c.reused.root().dump()); }},
        {"nlohmann json: parse + dump", [](const std::string & s, result & r) { json j = json::parse(s); return emit(r, j.dump()); }},
        {"yyjson: read + write", [](const std::string & s, result & r) { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); if (d == nullptr) { return false; } std::size_t n = 0; char* o = yyjson_write(d, 0, &n); const bool ok = o != nullptr && emit(r, o, n); std::free(o); yyjson_doc_free(d); return ok; }},
        {"yyjson: insitu (copy) + write", [](const std::string & s, result & r) { yy_insitu d(s); if (d.doc == nullptr) { return false; } std::size_t n = 0; char* o = yyjson_write(d.doc, 0, &n); const bool ok = o != nullptr && emit(r, o, n); std::free(o); return ok; }},
        {"simdjson: DOM + to_string", [](const std::string & s, result & r) { simdjson::dom::parser p; auto e = p.parse(s); if (e.error()) { return false; } return emit(r, simdjson::to_string(e.value_unsafe())); }},
        {"simdjson: DOM (reused) + to_string", [&c](const std::string & s, result & r) { auto e = c.sj.parse(s); if (e.error()) { return false; } return emit(r, simdjson::to_string(e.value_unsafe())); }},
        {"simdjson: minify", [](const std::string & s, result & r) { std::unique_ptr<char[]> o(new char[s.size() + simdjson::SIMDJSON_PADDING]); std::size_t n = 0; if (simdjson::minify(s.data(), s.size(), o.get(), n)) { return false; } return emit(r, o.get(), n); }},
        {"sonic-cpp: Document + Serialize", [](const std::string & s, result & r) { sonic_json::Document d; d.Parse(s.data(), s.size()); if (d.HasParseError()) { return false; } sonic_json::WriteBuffer wb; return d.Serialize(wb) == sonic_json::kErrorNone && emit(r, wb.ToString(), wb.Size()); }},
#if !BENCH_NO_GLAZE
        {"Glaze: generic", [](const std::string & s, result & r) { glz::generic_u64 j; if (glz::read_json(j, s)) { return false; } std::string o; return !glz::write_json(j, o) && emit(r, std::move(o)); }},
        // minify_json takes a resizable input but only reads it
        {"Glaze: minify_json", [](const std::string & s, result & r) { std::string o; return !glz::minify_json(const_cast<std::string&>(s), o) && emit(r, std::move(o)); }},
#endif
        {"Boost.JSON: parse + serialize", [](const std::string & s, result & r) { boost::json::monotonic_resource mr; boost::system::error_code ec; auto v = boost::json::parse(s, ec, &mr, bj_precise); if (ec) { return false; } return emit(r, boost::json::serialize(v)); }},
    };
}

// RapidJSON, once with UTF-8 validation (kParseValidateEncodingFlag) and once without; both with
// kParseFullPrecisionFlag, without which floats are not correctly rounded and sum/edit/minify give wrong results
constexpr unsigned rj_fast = rapidjson::kParseFullPrecisionFlag;

template<unsigned F>
static void add_rapidjson(std::vector<variant>& vs, const std::string& uc, const std::string& n, const char* sfx)
{
    if (uc == "validate")
    {
        vs.push_back({std::string("RapidJSON: SAX") + sfx, [](const std::string & s, result&) { rapidjson::BaseReaderHandler<> h; return rj_read<F>(s, h); }});
        vs.push_back({std::string("RapidJSON: Document") + sfx, [](const std::string & s, result&) { rapidjson::Document d; d.Parse<F>(s.data(), s.size()); return !d.HasParseError(); }});
        vs.push_back({std::string("RapidJSON: insitu (copy)") + sfx, [](const std::string & s, result&) { std::string b = s; rapidjson::Document d; d.ParseInsitu<F>(&b[0]); return !d.HasParseError(); }});
    }
    else if (uc == "sum")
    {
        vs.push_back({std::string("RapidJSON: Document") + sfx, [](const std::string & s, result & r) { rapidjson::Document d; d.Parse<F>(s.data(), s.size()); if (d.HasParseError()) { return false; } walk(d, r.st); return true; }});
        vs.push_back({std::string("RapidJSON: SAX") + sfx, [](const std::string & s, result & r) { rj_sum h(&r.st); return rj_read<F>(s, h); }});
        vs.push_back({std::string("RapidJSON: insitu (copy)") + sfx, [](const std::string & s, result & r) { std::string b = s; rapidjson::Document d; d.ParseInsitu<F>(&b[0]); if (d.HasParseError()) { return false; } walk(d, r.st); return true; }});
    }
    else if (uc == "select")
    {
        vs.push_back({std::string("RapidJSON: Document") + sfx, [n](const std::string & s, result & r) { rapidjson::Document d; d.Parse<F>(s.data(), s.size()); if (d.HasParseError()) { return false; } r.acc = pick<acc_rapidjson>(n, &d); return true; }});
        vs.push_back({std::string("RapidJSON: insitu (copy)") + sfx, [n](const std::string & s, result & r) { std::string b = s; rapidjson::Document d; d.ParseInsitu<F>(&b[0]); if (d.HasParseError()) { return false; } r.acc = pick<acc_rapidjson>(n, &d); return true; }});
    }
    else if (uc == "edit")
    {
        vs.push_back({std::string("RapidJSON: Document") + sfx, [n](const std::string & s, result & r) { rapidjson::Document d; d.Parse<F>(s.data(), s.size()); return !d.HasParseError() && edit_rapidjson(n, d, r); }});
        vs.push_back({std::string("RapidJSON: insitu (copy)") + sfx, [n](const std::string & s, result & r) { std::string b = s; rapidjson::Document d; d.ParseInsitu<F>(&b[0]); return !d.HasParseError() && edit_rapidjson(n, d, r); }});
    }
    else if (uc == "minify")
    {
        vs.push_back({std::string("RapidJSON: Document + Writer") + sfx, [](const std::string & s, result & r) { rapidjson::Document d; d.Parse<F>(s.data(), s.size()); if (d.HasParseError()) { return false; } rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> w(sb); return d.Accept(w) && emit(r, sb.GetString(), sb.GetSize()); }});
        vs.push_back({std::string("RapidJSON: SAX to Writer") + sfx, [](const std::string & s, result & r) { rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> w(sb); return rj_read<F>(s, w) && emit(r, sb.GetString(), sb.GetSize()); }});
        vs.push_back({std::string("RapidJSON: SAX to Writer (raw numbers)") + sfx, [](const std::string & s, result & r) { rapidjson::StringBuffer sb; rj_raw_writer w(sb); return rj_read<F | rapidjson::kParseNumbersAsStringsFlag>(s, w) && emit(r, sb.GetString(), sb.GetSize()); }});
    }
    (void)n;
}

// write: each library's document is parsed once, outside the timer; the input argument is ignored
static std::vector<variant> write_variants(const std::string& s)
{
    auto view = std::make_shared<const json_document>(json_document::parse(s));
    auto j = std::make_shared<const json>(json::parse(s));
    std::shared_ptr<yyjson_doc> yy(yyjson_read(s.data(), s.size(), 0), yyjson_doc_free);
    auto sjp = std::make_shared<simdjson::dom::parser>();
    const simdjson::dom::element sje = sjp->parse(s).value();
    auto rj = std::make_shared<rapidjson::Document>();
    rj->Parse<rj_flags>(s.data(), s.size());
    auto so = std::make_shared<sonic_json::Document>();
    so->Parse(s.data(), s.size());
#if !BENCH_NO_GLAZE
    auto gl = std::make_shared<glz::generic_u64>();
    (void)glz::read_json(*gl, s);
#endif
    auto bj = std::make_shared<const boost::json::value>(boost::json::parse(s, boost::json::make_shared_resource<boost::json::monotonic_resource>(), bj_precise));
    return
    {
        {"nlohmann json_document: dump", [view](const std::string&, result & r) { return emit(r, view->root().dump()); }},
        {"nlohmann json_document: dump (source numbers)", [view](const std::string&, result & r) { return emit(r, view->root().dump(-1, ' ', false, json_view::number_format::source)); }},
        {"nlohmann json: dump", [j](const std::string&, result & r) { return emit(r, j->dump()); }},
        {"yyjson: write", [yy](const std::string&, result & r) { std::size_t n = 0; char* o = yyjson_write(yy.get(), 0, &n); const bool ok = o != nullptr && emit(r, o, n); std::free(o); return ok; }},
        {"simdjson: to_string", [sjp, sje](const std::string&, result & r) { return emit(r, simdjson::to_string(sje)); }},
        {"RapidJSON: Writer", [rj](const std::string&, result & r) { rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> w(sb); return rj->Accept(w) && emit(r, sb.GetString(), sb.GetSize()); }},
        {"sonic-cpp: Serialize", [so](const std::string&, result & r) { sonic_json::WriteBuffer wb; return so->Serialize(wb) == sonic_json::kErrorNone && emit(r, wb.ToString(), wb.Size()); }},
#if !BENCH_NO_GLAZE
        {"Glaze: generic", [gl](const std::string&, result & r) { std::string o; return !glz::write_json(*gl, o) && emit(r, std::move(o)); }},
#endif
        {"Boost.JSON: serialize", [bj](const std::string&, result & r) { return emit(r, boost::json::serialize(*bj)); }},
    };
}

///////////////////////////////////////////////////////////////////////////////
// driver
///////////////////////////////////////////////////////////////////////////////

static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// the input contract: at least 64 bytes of spare capacity
static std::string padded(const std::string& s)
{
    std::string r;
    r.reserve(s.size() + 64);
    r.assign(s);
    return r;
}

struct bad_input
{
    std::string what, text;
    bool utf8;   // the 0xFF probe; the others are structural errors
};

// malformed inputs derived from a valid document: truncated by one byte (after trailing whitespace), a stray comma
// before the first '}' outside a string, and a 0xFF byte right after the opening quote of the first string value (not
// a key, so that a library that accepts the byte still finds the keys the use cases look up) in the second half of the
// document, or of the last string value if the second half has none (canada.json)
static std::vector<bad_input> malformed(const std::string& s)
{
    std::size_t first_close = std::string::npos, mid_quote = std::string::npos, last_quote = std::string::npos;
    bool in_string = false;
    std::vector<char> stack;   // the open containers
    char prev = 0;             // the last structural character outside strings
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        const char ch = s[i];
        if (in_string)
        {
            if (ch == '\\')
            {
                ++i;
            }
            else if (ch == '"')
            {
                in_string = false;
            }
        }
        else if (ch == '"')
        {
            in_string = true;
            const bool value = prev == ':' || (!stack.empty() && stack.back() == '[' && (prev == '[' || prev == ','));
            if (value)
            {
                last_quote = i;
                if (mid_quote == std::string::npos && i >= s.size() / 2)
                {
                    mid_quote = i;
                }
            }
            prev = '"';
        }
        else if (ch == '{' || ch == '[')
        {
            stack.push_back(ch);
            prev = ch;
        }
        else if (ch == '}' || ch == ']')
        {
            if (ch == '}' && first_close == std::string::npos)
            {
                first_close = i;
            }
            if (!stack.empty())
            {
                stack.pop_back();
            }
            prev = ch;
        }
        else if (ch == ':' || ch == ',')
        {
            prev = ch;
        }
    }
    std::vector<bad_input> out;
    std::string t = s;
    while (!t.empty() && (t.back() == ' ' || t.back() == '\n' || t.back() == '\r' || t.back() == '\t'))
    {
        t.pop_back();
    }
    t.pop_back();
    out.push_back({"truncated input", padded(t), false});
    t = s;
    t.insert(first_close, ",");
    out.push_back({"a stray comma before '}'", padded(t), false});
    t = s;
    t.insert((mid_quote != std::string::npos ? mid_quote : last_quote) + 1, "\xFF");
    out.push_back({"invalid UTF-8 (0xFF in a string)", padded(t), true});
    return out;
}

static bool run(const variant& v, const std::string& in, result& r)
{
    try
    {
        return v.fn(in, r);
    }
    catch (...)
    {
        return false;
    }
}

// runs a variant in a child process, so that a crash cannot take the benchmark down: on a malformed input (e.g.,
// sonic-cpp accepts a key holding an invalid byte, and the edit then misses that key) or on the valid input
enum class verdict { rejected, accepted, crashed };
static verdict run_isolated(const variant& v, const std::string& in)
{
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0)
    {
        result r;
        std::string o;
        r.out = &o;
        _exit(run(v, in, r) ? 1 : 0);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
    {
        std::perror("fork/waitpid");
        std::exit(1);
    }
    return WIFEXITED(status) ? (WEXITSTATUS(status) == 1 ? verdict::accepted : verdict::rejected) : verdict::crashed;
}

static bool same_text(const std::string& out, const json& expected)
{
    try
    {
        return json::parse(out) == expected;
    }
    catch (...)
    {
        return false;
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <json_test_data dir> [rounds] [document] [use case]\n", argv[0]);
        return 1;
    }
    const std::string T = std::string(argv[1]) + "/";
    const int rounds = argc > 2 ? std::max(1, std::atoi(argv[2])) : 30;
    const std::string only = argc > 3 ? argv[3] : "";        // only this document; "" for all
    const std::string only_uc = argc > 4 ? argv[4] : "";     // only this use case
    struct doc
    {
        std::string name, text;
        int batch;
    };
    std::vector<doc> docs;
    for (const char* f :
            {"nativejson-benchmark/twitter.json", "nativejson-benchmark/citm_catalog.json", "nativejson-benchmark/canada.json", "jeopardy/jeopardy.json"
            })
    {
        std::string n = std::string(f).substr(std::string(f).find('/') + 1);
        docs.push_back({n.substr(0, n.size() - 5), padded(slurp(T + f)), 1});
    }
    docs.push_back({"status", padded(json::parse(docs[0].text)["statuses"][0].dump()), 200});

    json_document reused;   // read() reuses its memory, as simdjson's parsers do
    simdjson::dom::parser sj;
    simdjson::ondemand::parser od;
    std::size_t excluded_total = 0;
    for (const auto& dc : docs)
    {
        if (!only.empty() && dc.name != only)
        {
            continue;
        }
        const std::string& s = dc.text;
        if (s.capacity() - s.size() < 64)
        {
            std::printf("WARNING: %s has less than 64 bytes of spare capacity\n", dc.name.c_str());
        }
        const std::vector<bad_input> bad = malformed(s);
        context ctx{dc.name, reused, sj, od};
        for (const char* const ucp : {"validate", "sum", "select", "edit", "minify", "write"})
        {
            const std::string uc = ucp;
            if (!only_uc.empty() && uc != only_uc)
            {
                continue;
            }
            std::vector<variant> all = uc == "validate" ? validate_variants(ctx) : uc == "sum" ? sum_variants(ctx) : uc == "select" ? select_variants(ctx)
                                       : uc == "edit" ? edit_variants(ctx) : uc == "minify" ? minify_variants(ctx) : write_variants(s);
            if (uc != "write")
            {
                add_rapidjson<rj_flags>(all, uc, dc.name, "");
                add_rapidjson<rj_fast>(all, uc, dc.name, " (no encoding check)");
            }

            // the reference result, from json_document (sum, select) or json (edit, minify, write)
            stats ref_st;
            double ref_acc = 0;
            json ref_json;
            if (uc == "sum")
            {
                const auto d = json_document::parse(s);
                walk(d.root(), ref_st);
                std::printf("check %-13s %-9s reference: nodes %zu str %zu num %.17g\n", dc.name.c_str(), uc.c_str(), ref_st.nodes, ref_st.str, ref_st.num);
            }
            else if (uc == "select")
            {
                const auto d = json_document::parse(s);
                ref_acc = pick<acc_view>(dc.name, d.root());
                std::printf("check %-13s %-9s reference: %.17g\n", dc.name.c_str(), uc.c_str(), ref_acc);
            }
            else if (uc != "validate")
            {
                ref_json = json::parse(s);
                if (uc == "edit")
                {
                    edit(dc.name, ref_json);
                }
            }

            std::vector<variant> vs;
            std::vector<std::string> levels;
            for (auto& v : all)
            {
                std::string why;
                std::string out;
                result r;
                r.out = &out;
                char buf[200];
                if (run_isolated(v, s) == verdict::crashed)
                {
                    why = "crashes on the valid input";
                }
                else if (!run(v, s, r))
                {
                    why = "rejects the valid input";
                }
                else if (uc == "sum" && !(r.st.nodes == ref_st.nodes && r.st.str == ref_st.str
                                          && (v.any_order ? std::fabs(r.st.num - ref_st.num) <= 1e-9 * std::fabs(ref_st.num) : r.st.num == ref_st.num)))
                {
                    std::snprintf(buf, sizeof(buf), "wrong result (nodes %zu str %zu num %.17g)", r.st.nodes, r.st.str, r.st.num);
                    why = buf;
                }
                else if (uc == "select" && r.acc != ref_acc)
                {
                    std::snprintf(buf, sizeof(buf), "wrong result (%.17g)", r.acc);
                    why = buf;
                }
                else if ((uc == "edit" || uc == "minify" || uc == "write") && !same_text(out, ref_json))
                {
                    why = "the output does not read back as the expected document";
                }
                if (why.empty())
                {
                    // the validation level from the malformed-input probes: "full" rejects all of them, "no UTF-8"
                    // accepts only the 0xFF byte, "partial" accepts (or crashes on) a structural error or crashes
                    // on any probe; write has no input to validate ("n/a")
                    std::string level = "n/a";
                    if (uc != "write")
                    {
                        std::string notes;
                        bool structural = false, utf8 = false;
                        for (const auto& b : bad)
                        {
                            const verdict vd = run_isolated(v, b.text);
                            if (vd == verdict::rejected)
                            {
                                continue;
                            }
                            notes += std::string(notes.empty() ? "" : "; ") + (vd == verdict::accepted ? "accepts " : "crashes on ") + b.what;
                            (b.utf8 && vd == verdict::accepted ? utf8 : structural) = true;
                        }
                        level = structural ? "partial" : utf8 ? "no UTF-8" : "full";
                        if (!notes.empty())
                        {
                            std::printf("level: %s %s | %s | %s | %s\n", dc.name.c_str(), uc.c_str(), v.name.c_str(), level.c_str(), notes.c_str());
                        }
                    }
                    vs.push_back(std::move(v));
                    levels.push_back(level);
                }
                else
                {
                    ++excluded_total;
                    std::printf("excluded: %s %s | %s | %s\n", dc.name.c_str(), uc.c_str(), v.name.c_str(), why.c_str());
                }
            }
            std::printf("check %-13s %-9s %zu of %zu variants give the right result\n", dc.name.c_str(), uc.c_str(), vs.size(), all.size());
            std::fflush(stdout);
            if (vs.empty())
            {
                continue;
            }

            std::vector<double> best(vs.size(), 1e300);
            const int r = s.size() > 10000000 ? std::min(rounds, std::max(3, rounds / 5)) : rounds;
            for (int i = 0; i < r; ++i)
            {
                for (std::size_t k = 0; k < vs.size(); ++k)
                {
                    result res;
                    run(vs[k], s, res);   // untimed: the previous variant's leftovers are cleaned up here
                    g_sink = res.st.num + res.acc;
                    const auto t0 = std::chrono::steady_clock::now();
                    for (int b = 0; b < dc.batch; ++b)
                    {
                        result rt;
                        g_sink = run(vs[k], s, rt) ? rt.st.num + rt.acc : -1;
                    }
                    best[k] = std::min(best[k], std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / dc.batch);
                }
            }
            std::printf("%-13s %-9s", dc.name.c_str(), uc.c_str());
            for (std::size_t k = 0; k < vs.size(); ++k)
            {
                std::printf(" | %s [%s] %.1fus (%.2fx)", vs[k].name.c_str(), levels[k].c_str(), best[k] / 1e3, best[k] / best[0]);
            }
            std::printf("\n");
            std::fflush(stdout);
        }
    }
    std::printf("done: %zu variant(s) excluded\n", excluded_total);
}
