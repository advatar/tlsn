// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "TLSNotaryMobile",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "TLSNotaryMobile", targets: ["TLSNotaryMobile"]),
    ],
    targets: [
        .binaryTarget(
            name: "TLSNMobileFFI",
            path: "Artifacts/TLSNMobile.xcframework"
        ),
        .target(
            name: "TLSNotaryMobile",
            dependencies: ["TLSNMobileFFI"]
        ),
        .testTarget(
            name: "TLSNotaryMobileTests",
            dependencies: ["TLSNotaryMobile"]
        ),
    ]
)
