// Standalone compile test for issue #4041
// Tests that zero-member NLOHMANN_DEFINE_TYPE_* macros compile and work correctly.
#include <cassert>
#include <string>
#include <nlohmann/json.hpp>

// --- Intrusive (friend functions inside the class) ---
struct EmptyIntrusive
{
    bool operator==(const EmptyIntrusive&) const { return true; }
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(EmptyIntrusive)
};

struct EmptyIntrusiveWithDefault
{
    bool operator==(const EmptyIntrusiveWithDefault&) const { return true; }
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(EmptyIntrusiveWithDefault)
};

struct EmptyIntrusiveOnlySerialize
{
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE(EmptyIntrusiveOnlySerialize)
};

// --- Non-intrusive (free functions in the same namespace) ---
struct EmptyNonIntrusive
{
    bool operator==(const EmptyNonIntrusive&) const { return true; }
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EmptyNonIntrusive)

struct EmptyNonIntrusiveWithDefault
{
    bool operator==(const EmptyNonIntrusiveWithDefault&) const { return true; }
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(EmptyNonIntrusiveWithDefault)

struct EmptyNonIntrusiveOnlySerialize {};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(EmptyNonIntrusiveOnlySerialize)

int main()
{
    // to_json produces {}
    assert(nlohmann::json(EmptyIntrusive{}).dump() == "{}");
    assert(nlohmann::json(EmptyIntrusiveWithDefault{}).dump() == "{}");
    assert(nlohmann::json(EmptyIntrusiveOnlySerialize{}).dump() == "{}");
    assert(nlohmann::json(EmptyNonIntrusive{}).dump() == "{}");
    assert(nlohmann::json(EmptyNonIntrusiveWithDefault{}).dump() == "{}");
    assert(nlohmann::json(EmptyNonIntrusiveOnlySerialize{}).dump() == "{}");

    // from_json round-trips successfully
    nlohmann::json j = nlohmann::json::object();
    auto e1 = j.get<EmptyIntrusive>();              (void)e1;
    auto e2 = j.get<EmptyIntrusiveWithDefault>();   (void)e2;
    auto e3 = j.get<EmptyNonIntrusive>();           (void)e3;
    auto e4 = j.get<EmptyNonIntrusiveWithDefault>(); (void)e4;

    return 0;
}
