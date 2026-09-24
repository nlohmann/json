add_requires("nlohmann_json")

add_rules("mode.debug", "mode.release")
target("xm")
    set_kind("binary")
    add_files("example.cpp")
    add_packages("nlohmann_json")
    set_languages("cxx11")
