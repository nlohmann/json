// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "json_example",
    dependencies: [
        .package(url: "https://github.com/nlohmann/json", from: "3.12.0")
    ],
    targets: [
        .executableTarget(
            name: "json_example",
            dependencies: [
                .product(name: "json", package: "json")
            ]
        )
    ]
)
