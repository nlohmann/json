#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#ifdef JSON_HAS_CPP_17

DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wuseless-cast")

#include <memory>
#include <vector>
#include <utility>

using std::nullopt;
using std::in_place;
using nlohmann::optional;

using opt_int = optional<int>;
using opt_vec = optional<std::vector<int>>;
using opt_ptr = optional<std::unique_ptr<int>>;

using std_opt_int = std::optional<int>;
using std_opt_vec = std::optional<std::vector<int>>;
using std_opt_ptr = std::optional<std::unique_ptr<int>>;

// NOLINTBEGIN(bugprone-unchecked-optional-access,bugprone-use-after-move,hicpp-invalid-access-moved,clang-analyzer-cplusplus.Move)

TEST_CASE("nlohmann::optional comparison")
{
    CHECK(opt_int() == nullopt);
    CHECK(nullopt == opt_int());
    CHECK(opt_int() == opt_int(nullopt));
    CHECK(opt_int(0) == opt_int(0));
    CHECK_FALSE(opt_int(0) == nullopt);
    CHECK_FALSE(nullopt == opt_int(0));
    CHECK_FALSE(opt_int(0) == opt_int(1));

    CHECK(opt_int() == std_opt_int());
    CHECK(opt_int(0) == std_opt_int(0));
    CHECK_FALSE(opt_int(0) == std_opt_int(1));

    CHECK(std_opt_int() == opt_int());
    CHECK(std_opt_int(0) == opt_int(0));
    CHECK_FALSE(std_opt_int(0) == opt_int(1));

    CHECK(opt_int(0) != nullopt);
    CHECK(nullopt != opt_int(0));
    CHECK(opt_int(0) != opt_int(1));
    CHECK_FALSE(opt_int() != nullopt);
    CHECK_FALSE(nullopt != opt_int());
    CHECK_FALSE(opt_int() != opt_int(nullopt));
    CHECK_FALSE(opt_int(0) != opt_int(0));

    CHECK_FALSE(opt_int() != std_opt_int());
    CHECK_FALSE(opt_int(0) != std_opt_int(0));
    CHECK(opt_int(0) != std_opt_int(1));

    CHECK_FALSE(std_opt_int() != opt_int());
    CHECK_FALSE(std_opt_int(0) != opt_int(0));
    CHECK(std_opt_int(0) != opt_int(1));

    CHECK(opt_int(0) > nullopt);
    CHECK(opt_int(1) > opt_int(0));
    CHECK_FALSE(nullopt > opt_int(0));
    CHECK_FALSE(opt_int(0) > opt_int(1));

    CHECK(opt_int(0) > std_opt_int());
    CHECK(std_opt_int(0) > opt_int());

    CHECK(opt_int(0) >= nullopt);
    CHECK(opt_int(1) >= opt_int(0));
    CHECK_FALSE(nullopt >= opt_int(0));
    CHECK_FALSE(opt_int(0) >= opt_int(1));

    CHECK(opt_int(0) >= std_opt_int());
    CHECK(std_opt_int(0) >= opt_int());

    CHECK(nullopt < opt_int(0));
    CHECK(opt_int(0) < opt_int(1));
    CHECK_FALSE(opt_int(0) < nullopt);
    CHECK_FALSE(opt_int(1) < opt_int(0));

    CHECK_FALSE(opt_int(0) < std_opt_int());
    CHECK_FALSE(std_opt_int(0) < opt_int());

    CHECK(nullopt <= opt_int(0));
    CHECK(opt_int(0) <= opt_int(1));
    CHECK_FALSE(opt_int(0) <= nullopt);
    CHECK_FALSE(opt_int(1) <= opt_int(0));

    CHECK_FALSE(opt_int(0) <= std_opt_int());
    CHECK_FALSE(std_opt_int(0) <= opt_int());
}

TEST_CASE("nlohmann::optional constructors")
{
    struct S1
    {
        operator int() noexcept
        {
            return 0;
        }
    };
    struct S2 : S1
    {
        operator opt_int() noexcept
        {
            return nullopt;
        }
    };

    CHECK(opt_int(S1()) == opt_int(0));
    CHECK(opt_int(S2()) == nullopt);

    CHECK(opt_int(S1()) == std_opt_int(S1()));
    CHECK(opt_int(S2()) != std_opt_int(S2()));

    CHECK(opt_int(std_opt_int(0)) == opt_int(0));
    CHECK(std_opt_int(opt_int(0)) == opt_int(0));

    CHECK(opt_int(in_place) == std_opt_int(in_place));
    CHECK(opt_vec(in_place) == std_opt_vec(in_place));
    CHECK(opt_ptr(in_place) == std_opt_ptr(in_place));

    CHECK(opt_vec(in_place, 5)->size() == 5);
    CHECK(opt_vec(in_place, {1, 2, 3}) == std_opt_vec(in_place, {1, 2, 3}));
    CHECK(**opt_ptr(in_place, new int{42}) == **std_opt_ptr(in_place, new int{42}));

    std::vector<int> vec{1, 2, 3};
    CHECK(*opt_vec(in_place, vec.begin(), vec.end()) == vec);

    CHECK(opt_vec({1, 2, 3})->size() == 3);
}

TEST_CASE("nlohmann::optional copy")
{
    opt_int opt1 = 111;
    std_opt_int opt2 = 222;

    SECTION("1")
    {
        opt1 = std::as_const(opt2);
        CHECK(*opt1 == 222);
        CHECK(*opt_int(std::as_const(opt1).base()) == 222);
    }

    SECTION("2")
    {
        opt2 = std::as_const(opt1).base();
        CHECK(*opt2 == 111);
        CHECK(*opt_int(std::as_const(opt2)) == 111);
    }
}

TEST_CASE("nlohmann::optional move")
{
    opt_ptr opt1(new int(111));
    std_opt_ptr opt2(new int(222));

    SECTION("1")
    {
        opt1 = std::move(opt2);
        CHECK(*opt2 == nullptr);
        CHECK(**opt1 == 222);
        CHECK(**opt_ptr(std::move(opt1)) == 222);
    }

    SECTION("2")
    {
        opt2 = std::move(opt1);
        CHECK(*opt1 == nullptr);
        CHECK(**opt2 == 111);
        CHECK(**opt_ptr(std::move(opt2)) == 111);
    }
}

// NOLINTEND(bugprone-unchecked-optional-access,bugprone-use-after-move,hicpp-invalid-access-moved,clang-analyzer-cplusplus.Move)

DOCTEST_GCC_SUPPRESS_WARNING_POP

#endif  // JSON_HAS_CPP_17
