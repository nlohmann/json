


#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;


//This struct emulate an Input Stream, once a "char" is readed from it it is lost
struct EmulateStream
{
    using difference_type = std::ptrdiff_t;
    using value_type = char;
    using pointer = const char*;
    using reference = const char&;
    using iterator_category = std::input_iterator_tag;

    // Like a pop_left() -> consume one char from the underlying buffer
    static char ConsumeChar(std::string* str)
    {
        const char c = str->front();
        str->erase(0, 1);

        return c;
    }

    EmulateStream()
        :
        target{nullptr}
    {}

    EmulateStream(std::string* target_)
        :
        target{target_},
        c{ConsumeChar(target_)}
    {}

    EmulateStream& operator++()
    {
        c = ConsumeChar(target);

        return *this;
    }

    bool operator!=(const EmulateStream& rhs) const
    {
        return rhs.target != target;
    }

    reference operator*() const
    {
        return c;
    }

    std::string* target;
    char c;

};

EmulateStream CreateBegin(std::string& tgt)
{
    return EmulateStream{&tgt};
}

EmulateStream CreateEnd(const std::string& tgt)
{
    return {};
}



TEST_CASE("consume only needed")
{

    nlohmann::detail::json_sax_acceptor<json> sax_parser;

    const std::string json_A = R"({ "key_A" : "value_A" })";
    const std::string json_B = R"({ "key_B" : "value_B" })";

    std::string json_concat_AB = json_A + json_B;

    CHECK(
        json::sax_parse(
            CreateBegin(json_concat_AB),
            CreateEnd(json_concat_AB),
            &sax_parser,
            nlohmann::detail::input_format_t::json,
            false
        )
        == true
    );


    CHECK(json_concat_AB == json_B);


    CHECK(
        json::sax_parse(
            CreateBegin(json_concat_AB),
            CreateEnd(json_concat_AB),
            &sax_parser,
            nlohmann::detail::input_format_t::json,
            false
        )
        == true
    );


    CHECK(json_concat_AB == "");
    CHECK(json_concat_AB.size() == 0);


    CHECK(
        json::sax_parse(
            CreateBegin(json_concat_AB),
            CreateEnd(json_concat_AB),
            &sax_parser,
            nlohmann::detail::input_format_t::json,
            false
        )
        == false
    );

}