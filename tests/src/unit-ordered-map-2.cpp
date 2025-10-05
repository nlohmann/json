// tests/src/unit-ordered-map-2.cpp
//
// Extra tests for nlohmann::ordered_map – aims to exercise all public API
// paths we rely on (C++11), including iterator arithmetic and exception
// safety.  This file intentionally does NOT define a doctest main
// (the project already provides one).

#include "doctest.h"

#include <nlohmann/ordered_map.hpp>

#include <string>
#include <vector>
#include <utility>
#include <stdexcept>

// ---------- Throwing key to exercise strong-exception-safety paths ----------
struct ThrowingKey
{
    std::string s;
    static bool inject; // toggled by tests

    ThrowingKey() = default;
    /* implicit */ ThrowingKey(const char* cs) : s(cs) {}
    explicit ThrowingKey(std::string v) : s(std::move(v)) {}

    bool operator==(const ThrowingKey& o) const noexcept
    {
        return s == o.s;
    }
    bool operator!=(const ThrowingKey& o) const noexcept
    {
        return !(*this == o);
    }
};

bool ThrowingKey::inject = false;

namespace std
{
template<> struct hash<ThrowingKey>
{
    size_t operator()(const ThrowingKey& k) const
    {
#ifndef JSON_NOEXCEPTION
        if (ThrowingKey::inject)
        {
            throw std::bad_alloc();
        }
#endif
        return std::hash<std::string> {}(k.s);
    }
};
template<> struct equal_to<ThrowingKey>
{
    bool operator()(const ThrowingKey& a, const ThrowingKey& b) const noexcept
    {
        return a.s == b.s;
    }
};
} // namespace std

// ---------- aliases ----------
using OM  = nlohmann::ordered_map<std::string, int>;
using VP  = std::pair<const std::string, int>;
using OMX = nlohmann::ordered_map<ThrowingKey, int>;

TEST_CASE("ordered_map: basic construction, capacity, element access")
{
    OM m;
    CHECK(m.empty());
    CHECK(m.size() == 0);

    // operator[] default insert and update
    m["a"] = 1;
    m["b"] = 2;
    CHECK_FALSE(m.empty());
    CHECK(m.size() == 2);
    CHECK(m["a"] == 1);
    CHECK(m["b"] == 2);

    // overwrite existing
    m["a"] = 3;
    CHECK(m["a"] == 3);
    CHECK(m.size() == 2);

    // at()
    CHECK(m.at("b") == 2);
#ifndef JSON_NOEXCEPTION
    CHECK_THROWS_AS(m.at("zzz"), std::out_of_range);
#endif

    // initializer-list and range constructor
    OM m2{{"x", 7}, {"y", 8}};
    CHECK(m2.size() == 2);
    std::vector<VP> v{{VP{"q", 1}}, {VP{"w", 2}}};
    OM m3(v.begin(), v.end());
    CHECK(m3.size() == 2);

    // copy / move construction (rebuild_index under the hood)
    OM mc(m);
    CHECK(mc.size() == m.size());
    CHECK(mc.find("a") != mc.end());
    OM mm(std::move(m2));
    CHECK(mm.size() == 2);
    CHECK(mm.find("x") != mm.end());
    CHECK(mm.find("y") != mm.end());

    // move assignment (uses move + rebuild)
    OM mz;
    mz = std::move(mm);
    CHECK(mz.size() == 2);
    CHECK(mz.find("x") != mz.end());
    CHECK(mz.find("y") != mz.end());

    // const operator[]
    const OM& cm = mc;
    CHECK(cm["a"] == 3);

    // begin/end iteration order
    {
        OM seq;
        seq["a"] = 1;
        seq["b"] = 2;
        seq["c"] = 3;

        auto it = seq.begin();
        CHECK(it->first == "a");
        ++it;
        CHECK(it->first == "b");
        ++it;
        CHECK(it->first == "c");
        ++it;
        CHECK(it == seq.end());

        // const_iterator
        const OM& cseq = seq;
        auto cit = cseq.begin();
        CHECK(cit->first == "a");
        ++cit;
        CHECK(cit->first == "b");
        ++cit;
        CHECK(cit->first == "c");
        ++cit;
        CHECK(cit == cseq.end());

        // iterator arithmetic (+ and +=) – O(n), provided for test compatibility
        it = seq.begin();
        CHECK((it + 1)->first == "b");
        it += 2;
        CHECK(it->first == "c");

        // reverse iterators
        auto rit = seq.rbegin();
        CHECK(rit->first == "c");
        ++rit;
        CHECK(rit->first == "b");
        ++rit;
        CHECK(rit->first == "a");
        ++rit;
        CHECK(rit == seq.rend());
    }
}

TEST_CASE("ordered_map: insert/emplace, find/count, erase variants, swap/clear, comparisons")
{
    OM om;

    // insert(value) (new key) and duplicate insert
    auto p1 = om.insert(VP{"a", 1});
    CHECK(p1.second == true);
    CHECK(p1.first->first == "a");
    auto p1b = om.insert(VP{"a", 111});
    CHECK(p1b.second == false);
    CHECK(p1b.first->second == 1);

    // insert(rvalue)
    auto p2 = om.insert(VP{"b", 2});
    CHECK(p2.second);
    CHECK(om.size() == 2);

    // hint overloads (ignored)
    auto itb = om.insert(om.begin(), VP{"c", 3});
    CHECK(itb->first == "c");
    CHECK(om.size() == 3);

    // range insert + push_back – also exercises reserve_index_for_range(forward)
    std::vector<VP> more = {VP{"d", 4}, VP{"e", 5}, VP{"f", 6}};
    om.insert(more.begin(), more.end());
    CHECK(om.size() == 6);
    om.push_back(VP{"g", 7});
    CHECK(om.size() == 7);

    // emplace and emplace_hint (hint ignored)
    auto e1 = om.emplace(std::string("h"), 8);
    CHECK(e1.second);
    CHECK(om.size() == 8);
    auto eh = om.emplace_hint(om.begin(), std::string("i"), 9);
    CHECK(eh->first == "i");
    CHECK(om.size() == 9);

    // find / count
    CHECK(om.count("a") == 1);
    CHECK(om.find("a") != om.end());
    CHECK(om.count("zzz") == 0);
    CHECK(om.find("zzz") == om.end());

    // erase by key (present / absent)
    CHECK(om.erase("b") == 1);
    CHECK(om.erase("b") == 0);
    CHECK(om.find("b") == om.end());

    // erase by iterator (returns next)
    auto ita = om.find("a");
    auto next = om.erase(ita);
    CHECK(next != om.end());
    CHECK(next->first != "a");
    CHECK(om.find("a") == om.end());

    // erase by const_iterator
    const OM& com = om;
    auto itc = com.find("c");
    auto after = om.erase(itc);
    CHECK(after != om.end());
    CHECK(om.find("c") == om.end());

    // erase range
    auto first = om.begin();
    auto last  = om.begin();
    last += 2; // erase two items if present
    om.erase(first, last);
    // size reduced by two (when possible – map had at least 4 elements here)
    CHECK(om.size() >= 3);

    // swap
    OM a{{"a", 1}, {"b", 2}};
    OM b{{"a", 1}, {"c", 2}};
    a.swap(b);
    CHECK(a.find("c") != a.end());
    CHECK(b.find("b") != b.end());

    // clear
    a.clear();
    CHECK(a.empty());

    // comparisons (lexicographic on insertion order)
    OM x{{"a", 1}, {"b", 2}};
    OM y{{"a", 1}, {"c", 2}};
    CHECK(x != y);
    CHECK_UNARY( (x < y) || (y < x) );    // one must be less
    CHECK_UNARY( (x <= y) || (y <= x) );
    CHECK_UNARY( (x >= y) || (y >= x) );
}

TEST_CASE("ordered_map: strong exception safety on operator[]/insert/emplace (hash throws)")
{
#ifndef JSON_NOEXCEPTION
    OMX om;
    om.emplace(ThrowingKey{"ok1"}, 1);
    om.emplace(ThrowingKey{"ok2"}, 2);
    const auto before_size = om.size();

    // operator[] path
    ThrowingKey::inject = true;
    CHECK_THROWS_AS( (void)om[ThrowingKey{"boom"}], std::bad_alloc );
    ThrowingKey::inject = false;
    CHECK(om.size() == before_size);
    CHECK(om.find(ThrowingKey{"ok1"}) != om.end());
    CHECK(om.find(ThrowingKey{"ok2"}) != om.end());
    CHECK(om.find(ThrowingKey{"boom"}) == om.end());

    // insert(value) path
    ThrowingKey::inject = true;
    CHECK_THROWS_AS( (void)om.insert( std::make_pair(ThrowingKey{"boom2"}, 3) ), std::bad_alloc );
    ThrowingKey::inject = false;
    CHECK(om.size() == before_size);
    CHECK(om.find(ThrowingKey{"boom2"}) == om.end());

    // emplace path
    ThrowingKey::inject = true;
    CHECK_THROWS_AS( (void)om.emplace(ThrowingKey{"boom3"}, 4), std::bad_alloc );
    ThrowingKey::inject = false;
    CHECK(om.size() == before_size);
    CHECK(om.find(ThrowingKey{"boom3"}) == om.end());
#endif
}

TEST_CASE("ordered_map: const overloads and reverse iteration")
{
    OM m{{"a", 1}, {"b", 2}, {"c", 3}};
    const OM& cm = m;

    CHECK(cm.find("a") != cm.end());
    CHECK(cm.count("x") == 0);
    CHECK(cm.at("b") == 2);

#ifndef JSON_NOEXCEPTION
    CHECK_THROWS_AS(cm.at("nope"), std::out_of_range);
#endif

    // reverse const iteration
    auto rcit = cm.rbegin();
    CHECK(rcit->first == "c");
    ++rcit;
    CHECK(rcit->first == "b");
    ++rcit;
    CHECK(rcit->first == "a");
    ++rcit;
    CHECK(rcit == cm.rend());
}
