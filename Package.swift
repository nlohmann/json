// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "nlohmann-json",
     platforms: [
        .iOS(.v11), .macOS(.v10_13), .tvOS(.v11), .watchOS(.v4)
    ],
    products: [
        .library(name: "nlohmann-json", targets: ["nlohmann-json"])
    ],
    targets: [
        .target(
            name: "nlohmann-json",
            path: "single_include/nlohmann",
            publicHeadersPath: "."
        )
    ],
    cxxLanguageStandard: .cxx11
)
