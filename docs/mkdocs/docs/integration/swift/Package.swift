// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyPackage",
    dependencies: [
        .package(url: "https://github.com/nlohmann/json.git", from: "3.12.0")
    ],
    targets: [
        // the C++ target that uses nlohmann/json
        .target(
            name: "MyLibrary",
            dependencies: [
                .product(name: "json", package: "json")
            ],
            // works around missing public headers in MyLibrary; not related to nlohmann/json
            publicHeadersPath: "."
        )
    ]
)
