#pragma once

#include <string>
#include <vector>
#include <nlohmann/detail/value_t.hpp>

namespace nlohmann
{
namespace detail
{

template<typename BasicJsonType>
class diagnostics_t
{
  public:
    diagnostics_t() noexcept = default;
    diagnostics_t(const BasicJsonType& j) noexcept
        : m_j(&j)
    {}

    std::string diagnostics() const
    {
#if JSON_DIAGNOSTICS
        if (m_j == nullptr)
        {
            return "";
        }

        std::vector<std::string> tokens;
        for (const auto* current = m_j; current->m_parent != nullptr; current = current->m_parent)
        {
            switch (current->m_parent->type())
            {
                case value_t::array:
                {
                    for (std::size_t i = 0; i < current->m_parent->m_value.array->size(); ++i)
                    {
                        if (current->m_parent->m_value.array->operator[](i) == *current)
                        {
                            tokens.emplace_back(std::to_string(i));
                            continue;
                        }
                    }
                    break;
                }

                case value_t::object:
                {
                    for (const auto& element : *current->m_parent->m_value.object)
                    {
                        if (element.second == *current)
                        {
                            tokens.emplace_back(element.first.c_str());
                            continue;
                        }
                    }
                    break;
                }

                default:
                    break;
            }
        }

        if (tokens.empty())
        {
            return "";
        }

        return "(" + std::accumulate(tokens.rbegin(), tokens.rend(), std::string{},
                                     [](const std::string & a, const std::string & b)
        {
            return a + "/" + b;
        }) + ") ";
#else
        return "";
#endif
    }

  private:
    const BasicJsonType* m_j = static_cast<const BasicJsonType*>(nullptr);
};

} // namespace detail
} // namespace nlohmann
