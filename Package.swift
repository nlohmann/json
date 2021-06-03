// swift-tools-version:5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "json",
    platforms: [
        .iOS(.v9), .macOS(.v10_10), .tvOS(.v9), .watchOS(.v2)
    ],
    products: [
        .library(
            name: "json",
            targets: ["json"]),
    ],
    targets: [
        .target(
            name: "json",
            dependencies: [],
            path: ".",
            exclude:
                [
                    "appveyor.yml",
                    "benchmarks",
                    "cmake",
                    "ChangeLog.md",
                    "doc",
                    "include",
                    "test",
                    "third_party",
                    "CMakeLists.txt",
                    "CODE_OF_CONDUCT.md",
                    "LICENSE.MIT",
                    "Makefile",
                    "meson.build",
                    "nlohmann_json.natvis",
                    "README.md",
                    "wsjcpp.yml",
                ],
            sources:
                [
                    "_SwiftPackageManagerFile.cpp"
                ],
            publicHeadersPath: "./single_include/")
    ],
    
    cxxLanguageStandard: .cxx11
)
