// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KeychainTypes",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "KeychainTypes",
            targets: ["KeychainTypes"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.3.0"),
        .package(url: "https://github.com/OperatorFoundation/Datable", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/SwiftHexTools", branch: "main")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "KeychainTypes",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                "Datable",
                "SwiftHexTools",
            ]
        ),
        .testTarget(
            name: "KeychainTypesTests",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                "KeychainTypes",
                "SwiftHexTools",
            ]),
    ],
    swiftLanguageVersions: [.v5]
)
