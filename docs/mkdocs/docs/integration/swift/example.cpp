// MyLibrary must contain at least one .cpp file, or SwiftPM/Xcode will
// not build a usable "json" library to link against (see nlohmann/json#4650)
#include <json.hpp>

nlohmann::json example()
{
    return nlohmann::json::meta();
}
