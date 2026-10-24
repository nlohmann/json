#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace nlohmann
{
template <typename Rep, typename Period>
struct adl_serializer<std::chrono::duration<Rep, Period>>
{
    static void to_json(json& j, const std::chrono::duration<Rep, Period>& d)
    {
        j = d.count();
    }

    static void from_json(const json& j, std::chrono::duration<Rep, Period>& d)
    {
        d = std::chrono::duration<Rep, Period>(j.get<Rep>());
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

    // the unit is not part of the JSON value
    const json timeout = milliseconds(1500);
    std::cout << "duration: " << timeout << '\n';
    std::cout << "as milliseconds: " << timeout.get<milliseconds>().count() << '\n';

    // a system_clock time point is the time since the Unix epoch
    const time_point<system_clock, milliseconds> t(milliseconds(1700000000123));
    const json stamp = t;
    std::cout << "time point: " << stamp << '\n';

    const auto back = stamp.get<time_point<system_clock, milliseconds>>();
    std::cout << "round trip: " << (back == t) << '\n';
}
