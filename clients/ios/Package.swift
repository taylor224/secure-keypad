// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecureKeypad",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(name: "SecureKeypad", targets: ["SecureKeypad"]),
    ],
    targets: [
        .target(
            name: "SecureKeypad",
            path: "Sources/SecureKeypad"
        ),
        .testTarget(
            name: "SecureKeypadTests",
            dependencies: ["SecureKeypad"],
            path: "Tests/SecureKeypadTests",
            resources: [.copy("vectors")]
        ),
    ]
)
