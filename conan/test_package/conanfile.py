from conans import ConanFile, CMake
import os

version = "2.1.1"
channel = os.getenv("CONAN_CHANNEL", "stable")
username = os.getenv("CONAN_USERNAME", "nlohmann")


class JsonForModernCppTestConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = "jsonformoderncpp/%s@%s/%s" % (version, username, channel)
    generators = "cmake"

    def build(self):
        cmake = CMake(self.settings)
        # Current dir is "test_package/build/<build_id>" and CMakeLists.txt is in "test_package"
        cmake.configure(self, source_dir=self.conanfile_directory, build_dir="./")
        cmake.build(self)

    def test(self):
        os.chdir("bin")
        self.run(".%sexample" % os.sep)