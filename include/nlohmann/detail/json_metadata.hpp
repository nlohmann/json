#pragma once

namespace nlohmann
{
namespace detail
{
template<class MetaDataType>
class json_metadata
{
  public:
    using metadata_t = MetaDataType;
    metadata_t& metadata()
    {
        return m_metadata;
    }
    const metadata_t& metadata() const
    {
        return m_metadata;
    }
  private:
    metadata_t m_metadata = {};
};

template<>
class json_metadata<void>
{
    //no metadata
};
}  // namespace detail
}  // namespace nlohmann
