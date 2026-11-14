# NSZ to NSP for iOS

A native SwiftUI utility that converts a PFS0-based Nintendo Switch NSZ archive into an NSP entirely on the device. Select an NSZ from Files, run the conversion, then use the iOS share sheet to save the resulting NSP.

## What it does

- Uses the iOS document picker and security-scoped file access.
- Parses PFS0 entries and rebuilds the NSP directory with adjusted NCA names and sizes.
- Copies uncompressed archive entries directly and reconstructs NCZ entries from their 16 KiB NCA header, NCZSECTN section records, and streaming Zstandard payload.
- Re-encrypts section types 3 and 4 with the embedded AES-CTR section metadata.
- Supports ordinary Zstandard NCZ payloads and NCZBLOCK version 2, type 1 payloads, including stored-raw blocks.
- Processes archive data with bounded buffers (1 MiB file chunks and 128 KiB Zstandard input reads); it does not load the archive or an NCA into memory.
- Writes the converted NSP to an app temporary folder. Share or save it from the standard iOS share sheet.

The converter does not download files, contact a service, provide title keys, or bypass the device's signing requirements. It validates container bounds and decompression sizes, but it is not a substitute for an independent content-integrity check. Convert only files you own or are authorized to use.

## Build and test on macOS

Requirements: Xcode with an iOS SDK, Swift Package Manager, and XcodeGen.

    brew install xcodegen
    xcodegen generate --spec project.yml
    xcodebuild test -project NSZtoNSP.xcodeproj -scheme NSZtoNSP -destination 'platform=iOS Simulator,name=iPhone 16'

Open NSZtoNSP.xcodeproj in Xcode to run on a device. The project pins the SwiftZSTD package revision used for streaming Zstandard support.

## Unsigned IPA for SideStore

The GitHub Actions workflow runs on a macOS runner, executes the iOS simulator tests, builds the device app with code signing disabled, and packages it as an unsigned IPA containing Payload/NSZtoNSP.app. Download the NSZtoNSP-unsigned-IPA artifact from the workflow run and import it into SideStore for signing and installation. The artifact is not signed and does not include a provisioning profile.

## Format references

The NCZ section table and block layout follow the published NSZ format description: https://github.com/nicoboss/nsz/blob/master/docs/formats.md. The implementation in this repository is written in Swift; the reference is used for format interoperability.

## Third-party code

The app uses the SwiftZSTD package and its bundled Zstandard library. Third-party license notices are in THIRD-PARTY-NOTICES.md.
