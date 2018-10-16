from conans import ConanFile, CMake, tools
from conans.tools import load
import re

def get_version():
    try:
        content = load("CMakeLists.txt")
        version = re.search(b"project\(nlohmann_json VERSION (.*) LANGUAGES CXX\)", content).group(1)
        return version.strip()
    except Exception as e:
        return None

class JsonConan(ConanFile):
    name = "json"
    version = get_version()
    license = "MIT"
    url = "https://github.com/nlohmann/json/"
    description = "JSON for Modern C++"
    author = "Niels Lohmann (mail@nlohmann.me)"
    generators = "cmake"
    exports_sources = "include/*"
    no_copy_source = True
    scm = {
        "type": "git",
        "url": "auto",
        "revision": "auto"
    }

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def source(self):
        self.run("git clone https://github.com/nlohmann/json/")
        self.run("cd json")
        tools.replace_in_file("CMakeLists.txt",
                              "project(nlohmann_json VERSION {version} LANGUAGES CXX)".format(version=self.version),
                              '''PROJECT(nlohmann_json VERSION {version} LANGUAGES CXX)
include(${{CMAKE_BINARY_DIR}}/conanbuildinfo.cmake)
conan_basic_setup()'''.format(version=self.version))

    def package(self):
        self.copy("include/*.hpp")

    def package_id(self):
        self.info.header_only()
