#!/usr/bin/env python
from conans import ConanFile, CMake


class CatchConan(ConanFile):
    name = "catch2"
    description = "A modern, C++-native, framework for unit-tests, TDD and BDD"
    topics = ("conan", "catch2", "unit-test", "tdd", "bdd")
    url = "https://github.com/catchorg/Catch2"
    homepage = url
    license = "BSL-1.0"

    exports = "LICENSE.txt"
    exports_sources = ("src/*", "CMakeLists.txt", "CMake/*", "extras/*")

    settings = "os", "compiler", "build_type", "arch"

    options = {"with_main": [True, False]}
    default_options = {"with_main": True}

    def _configure_cmake(self):
        cmake = CMake(self)
        cmake.definitions["BUILD_TESTING"] = "OFF"
        cmake.definitions["CATCH_INSTALL_DOCS"] = "OFF"
        cmake.definitions["CATCH_INSTALL_HELPERS"] = "ON"
        cmake.configure(build_folder="build")
        return cmake

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()

    def package(self):
        self.copy(pattern="LICENSE.txt", dst="licenses")
        cmake = self._configure_cmake()
        cmake.install()

    def package_id(self):
        del self.info.options.with_main

    def package_info(self):
        self.cpp_info.libs = [
            'Catch2Main', 'Catch2'] if self.options.with_main else ['Catch2']
        self.cpp_info.names["cmake_find_package"] = "Catch2"
        self.cpp_info.names["cmake_find_package_multi"] = "Catch2"
