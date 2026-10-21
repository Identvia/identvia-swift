// swift-tools-version:5.9
import PackageDescription

let crypto: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
    .product(name: "_CryptoExtras", package: "swift-crypto"),
]

let package = Package(
    name: "Identvia",
    platforms: [.iOS(.v15), .macOS(.v12), .visionOS(.v1)],
    products: [
        // Apple apps: ASWebAuthenticationSession + Keychain + SwiftUI button, on top of the core.
        .library(name: "Identvia", targets: ["Identvia"]),
        // Platform-neutral OIDC core (PKCE, discovery, ID token validation, refresh rotation). Builds on Linux.
        .library(name: "IdentviaCore", targets: ["IdentviaCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(name: "IdentviaCore", dependencies: crypto),
        .target(name: "Identvia", dependencies: ["IdentviaCore"]),
        .testTarget(name: "IdentviaCoreTests", dependencies: ["IdentviaCore"] + crypto),
    ]
)
