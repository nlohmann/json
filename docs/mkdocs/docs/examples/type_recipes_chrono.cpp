#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// the name of a period; extend the list for the periods you use
template <typename Period> const char* unit_name();
template <> const char* unit_name<std::nano>()
{
    return "ns";
}
template <> const char* unit_name<std::micro>()
{
    return "us";
}
template <> const char* unit_name<std::milli>()
{
    return "ms";
}
template <> const char* unit_name<std::ratio<1>>()
{
    return "s";
}
template <> const char* unit_name<std::ratio<60>>()
{
    return "min";
}
template <> const char* unit_name<std::ratio<3600>>()
{
    return "h";
}

namespace nlohmann
{
template <typename Rep, typename Period>
struct adl_serializer<std::chrono::duration<Rep, Period>>
{
    static void to_json(json& j, const std::chrono::duration<Rep, Period>& d)
    {
        j = {{"unit", unit_name<Period>()}, {"value", d.count()}};
    }

    static void from_json(const json& j, std::chrono::duration<Rep, Period>& d)
    {
        if (j.at("unit").get<std::string>() != unit_name<Period>())
        {
            throw std::invalid_argument("unexpected unit " + j.at("unit").dump());
        }
        d = std::chrono::duration<Rep, Period>(j.at("value").get<Rep>());
    }
};

template <typename Duration>
struct adl_serializer<std::chrono::time_point<std::chrono::system_clock, Duration>>
{
    static void to_json(json& j, const std::chrono::time_point<std::chrono::system_clock, Duration>& t)
    {
        j = t.time_since_epoch();
    }

    static void from_json(const json& j, std::chrono::time_point<std::chrono::system_clock, Duration>& t)
    {
        t = std::chrono::time_point<std::chrono::system_clock, Duration>(j.get<Duration>());
    }
};
} // namespace nlohmann

int main()
{
    using namespace std::chrono;

    std::cout << std::boolalpha;

    // the unit is part of the JSON value
    const json timeout = milliseconds(1500);
    std::cout << "duration: " << timeout << '\n';
    std::cout << "as milliseconds: " << timeout.get<milliseconds>().count() << '\n';

    // reading with a different unit is rejected
    try
    {
        timeout.get<seconds>();
    }
    catch (const std::invalid_argument& e)
    {
        std::cout << "error: " << e.what() << '\n';
    }

    // a system_clock time point is the time since the Unix epoch
    const time_point<system_clock, milliseconds> t(milliseconds(1700000000123));
    const json stamp = t;
    std::cout << "time point: " << stamp << '\n';

    const auto back = stamp.get<time_point<system_clock, milliseconds>>();
    std::cout << "round trip: " << (back == t) << '\n';
}
