#include "catch.hpp"

#include "json.hpp"

using nlohmann::json;

enum test
{
};

struct pod {};
struct pod_bis {};

void to_json(json&, pod) noexcept;
void to_json(json&, pod_bis);
void from_json(const json&, pod) noexcept;
void from_json(const json&, pod_bis);
static json j;

static_assert(noexcept(json{}), "");
static_assert(noexcept(nlohmann::to_json(j, 2)), "");
static_assert(noexcept(nlohmann::to_json(j, 2.5)), "");
static_assert(noexcept(nlohmann::to_json(j, true)), "");
static_assert(noexcept(nlohmann::to_json(j, test{})), "");
static_assert(noexcept(nlohmann::to_json(j, pod{})), "");
static_assert(not noexcept(nlohmann::to_json(j, pod_bis{})), "");
static_assert(noexcept(json(2)), "");
static_assert(noexcept(json(test{})), "");
static_assert(noexcept(json(pod{})), "");
static_assert(noexcept(j.get<pod>()), "");
static_assert(not noexcept(j.get<pod_bis>()), "");
static_assert(noexcept(json(pod{})), "");
