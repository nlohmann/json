#pragma once

#include <string>
#include <vector>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/detail/string_escape.hpp>

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
                        if (&current->m_parent->m_value.array->operator[](i) == current)
                        {
                            tokens.emplace_back(std::to_string(i));
                            break;
                        }
                    }
                    break;
                }

                case value_t::object:
                {
                    for (const auto& element : *current->m_parent->m_value.object)
                    {
                        if (&element.second == current)
                        {
                            tokens.emplace_back(element.first.c_str());
                            break;
                        }
                    }
                    break;
                }

                default:   // LCOV_EXCL_LINE
                    break; // LCOV_EXCL_LINE
            }
        }

        if (tokens.empty())
        {
            return ""; // LCOV_EXCL_LINE
        }

        return "(" + std::accumulate(tokens.rbegin(), tokens.rend(), std::string{},
                                     [](const std::string & a, const std::string & b)
        {
            return a + "/" + detail::escape(b);
        }) + ") ";
#else
        return "";
#endif
    }

  private:
    const BasicJsonType* m_j = nullptr;
};

} // namespace detail
} // namespace nlohmann
