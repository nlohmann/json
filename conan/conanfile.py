from conans import ConanFile
from conans.tools import download

class JsonForModernCppConan(ConanFile):
    name = "jsonformoderncpp"
    version = "2.1.1"
    license = "MIT"
    url = "https://github.com/nlohmann/json"
    author = "Niels Lohmann (mail@nlohmann.me)"
    settings = None
    options = {"path": "ANY"}
    default_options = "path="

    def source(self):
        download("https://github.com/nlohmann/json/releases/download/v%s/json.hpp" % self.version, "json.hpp")

    def package(self):
        header_dir = "include"
        if self.options.path != "":
            header_dir += "/" + str(self.options.path)
        self.copy("*.hpp", dst=header_dir)