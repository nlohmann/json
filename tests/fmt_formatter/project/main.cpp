#include <cassert>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

// A fmt::formatter<nlohmann::json> specialization mirroring std::formatter<basic_json>
// (see docs/mkdocs/docs/api/basic_json/std_formatter.md), for use with fmt versions that
// no longer pick up format_as() (fmt >= 11.1.0), or to get the same "{:#}"/width/
// fill-and-align spec support with any fmt version.
// --8<-- [start:formatter_recipe]
template <>
struct fmt::formatter<nlohmann::json>
{
    // -1 means compact output (dump()); any value >= 0 means pretty-printed
    // output with that many spaces (or indent_char) per level.
    int indent = -1;
    char indent_char = ' ';

    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator
    {
        auto it = ctx.begin();
        const auto end = ctx.end();
        constexpr auto is_align = [](char c)
        {
            return c == '<' || c == '>' || c == '^';
        };

        // [[fill] align] - repurposed here to pick a custom indent character
        if (it != end && it + 1 != end && is_align(it[1]))
        {
            indent_char = *it;
            it += 2;
        }
        else if (it != end && is_align(*it))
        {
            ++it;
        }

        // ['#'] - "alternate form", used here to request pretty-printing with a
        // default indent of 4 (overridden by an explicit width below, if given)
        if (it != end && *it == '#')
        {
            indent = 4;
            ++it;
        }

        // [width] - repurposed here to pick the indent size; a width without '#'
        // implies pretty-printing since an indent otherwise has no meaning
        if (it != end && *it >= '1' && *it <= '9')
        {
            indent = 0;
            while (it != end && *it >= '0' && *it <= '9')
            {
                indent = (indent * 10) + (*it - '0');
                ++it;
            }
        }

        if (it != end && *it != '}')
        {
            throw fmt::format_error("invalid format args for nlohmann::json");
        }

        return it;
    }

    auto format(const nlohmann::json& j, format_context& ctx) const
    {
        const auto dumped = j.dump(indent, indent_char);
        return fmt::format_to(ctx.out(), "{}", dumped);
    }
};
// --8<-- [end:formatter_recipe]

int main()
{
    const nlohmann::json j = {{"foo", 1}, {"bar", {1, 2, 3}}};

    assert(fmt::format("{}", j) == j.dump());
    assert(fmt::format("{:#}", j) == j.dump(4));
    assert(fmt::format("{:2}", j) == j.dump(2));
    assert(fmt::format("{:#2}", j) == j.dump(2));
    assert(fmt::format("{:.>#}", j) == j.dump(4, '.'));

    bool threw = false;
    try
    {
        (void)fmt::vformat("{:x}", fmt::make_format_args(j));
    }
    catch (const fmt::format_error&)
    {
        threw = true;
    }
    assert(threw);
}
