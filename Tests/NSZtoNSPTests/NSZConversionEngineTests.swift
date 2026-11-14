import Foundation
import SwiftZSTD
import XCTest
@testable import NSZtoNSP

final class NSZConversionEngineTests: XCTestCase {
    func testStreamingZstdConversionRebuildsNCAAndCopiesPlainEntry() throws {
        let header = makeNCAHeader()
        let body = Data((0..<257).map { UInt8(($0 * 17) & 0xff) })
        let compressed = try ZSTDProcessor().compressBuffer(body, compressionLevel: 3)
        let ncz = makeNCZ(header: header, body: body, payload: compressed)
        let plain = Data("plain-nca-data".utf8)
        let output = try convert(makePFS0([("content.ncz", ncz), ("meta.nca", plain)]))
        XCTAssertEqual(output["content.nca"], header + body)
        XCTAssertEqual(output["meta.nca"], plain)
    }

    func testNCZBlockCompressedPayloadIsReconstructed() throws {
        let header = makeNCAHeader()
        let body = Data(repeating: 0xa5, count: 16_384)
        let compressed = try ZSTDProcessor().compressBuffer(body, compressionLevel: 3)
        XCTAssertLessThan(compressed.count, body.count)
        let ncz = makeNCZ(header: header, body: body, payload: compressed, blockExponent: 14)
        let output = try convert(makePFS0([("block.ncz", ncz)]))
        XCTAssertEqual(output["block.nca"], header + body)
    }

    func testRawNCZBlockAndAESCTRSectionReconstruction() throws {
        let header = makeNCAHeader()
        var state: UInt32 = 0x12345678
        let body = Data((0..<16_384).map { _ -> UInt8 in
            state ^= state << 13
            state ^= state >> 17
            state ^= state << 5
            return UInt8(truncatingIfNeeded: state)
        })
        let key = Data(repeating: 0, count: 16)
        let counter = Data(repeating: 0, count: 16)
        let section = NCZSection(offset: 0x4000, size: UInt64(body.count), cryptoType: 3, key: key, counter: counter)
        let encryptedBody = try AESCTRTransform(section: section).transform(body)
        let ncz = makeNCZ(header: header, body: body, payload: encryptedBody, cryptoType: 3, key: key, counter: counter, blockExponent: 14)
        let output = try convert(makePFS0([("encrypted.ncz", ncz)]))
        XCTAssertEqual(output["encrypted.nca"], header + body)
    }

    func testAES128CTRUsesBigEndianCounter() throws {
        let section = NCZSection(
            offset: 0,
            size: 16,
            cryptoType: 3,
            key: Data(repeating: 0, count: 16),
            counter: Data(repeating: 0, count: 16)
        )
        let actual = try AESCTRTransform(section: section).transform(Data(repeating: 0, count: 16))
        let expected = Data([0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e])
        XCTAssertEqual(actual, expected)
    }

    private func convert(_ archive: Data) throws -> [String: Data] {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let input = folder.appendingPathComponent("sample.nsz")
        let output = folder.appendingPathComponent("sample.nsp")
        try archive.write(to: input)
        try NSZConversionEngine.convert(inputURL: input, outputURL: output)
        return try readPFS0(Data(contentsOf: output))
    }

    private func makeNCAHeader() -> Data {
        var header = Data(repeating: 0, count: 0x4000)
        header[0] = 0x4e
        header[1] = 0x43
        header[2] = 0x41
        header[3] = 0x33
        return header
    }

    private func makeNCZ(
        header: Data,
        body: Data,
        payload: Data,
        cryptoType: UInt64 = 1,
        key: Data = Data(repeating: 0, count: 16),
        counter: Data = Data(repeating: 0, count: 16),
        blockExponent: UInt8? = nil
    ) -> Data {
        var result = header
        result.append(Data("NCZSECTN".utf8))
        appendLETest(UInt64(1), to: &result)
        appendLETest(UInt64(0x4000), to: &result)
        appendLETest(UInt64(body.count), to: &result)
        appendLETest(cryptoType, to: &result)
        appendLETest(UInt64(0), to: &result)
        result.append(key)
        result.append(counter)
        if let blockExponent {
            result.append(Data("NCZBLOCK".utf8))
            result.append(2)
            result.append(1)
            result.append(0)
            result.append(blockExponent)
            appendLETest(UInt32(1), to: &result)
            appendLETest(UInt64(body.count), to: &result)
            appendLETest(UInt32(payload.count), to: &result)
        }
        result.append(payload)
        return result
    }

    private func makePFS0(_ files: [(String, Data)]) -> Data {
        var strings = Data()
        var nameOffsets: [UInt32] = []
        for (name, _) in files {
            nameOffsets.append(UInt32(strings.count))
            strings.append(Data(name.utf8))
            strings.append(0)
        }
        var result = Data("PFS0".utf8)
        appendLETest(UInt32(files.count), to: &result)
        appendLETest(UInt32(strings.count), to: &result)
        appendLETest(UInt32(0), to: &result)
        var offset: UInt64 = 0
        for (index, file) in files.enumerated() {
            appendLETest(offset, to: &result)
            appendLETest(UInt64(file.1.count), to: &result)
            appendLETest(nameOffsets[index], to: &result)
            appendLETest(UInt32(0), to: &result)
            offset += UInt64(file.1.count)
        }
        result.append(strings)
        for file in files { result.append(file.1) }
        return result
    }

    private func readPFS0(_ data: Data) throws -> [String: Data] {
        guard data.count >= 16, String(data: data.prefix(4), encoding: .utf8) == "PFS0" else {
            throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid output PFS0"])
        }
        let count = Int(readUInt32Test(data, at: 4))
        let tableSize = Int(readUInt32Test(data, at: 8))
        let tableStart = 16 + count * 24
        let dataStart = tableStart + tableSize
        var files: [String: Data] = [:]
        for index in 0..<count {
            let record = 16 + index * 24
            let offset = Int(readUInt64Test(data, at: record))
            let size = Int(readUInt64Test(data, at: record + 8))
            let nameOffset = tableStart + Int(readUInt32Test(data, at: record + 16))
            var nameEnd = nameOffset
            while nameEnd < dataStart && data[nameEnd] != 0 { nameEnd += 1 }
            guard nameEnd < dataStart, dataStart + offset + size <= data.count,
                  let name = String(data: data[nameOffset..<nameEnd], encoding: .utf8) else {
                throw NSError(domain: "test", code: 2, userInfo: [NSLocalizedDescriptionKey: "invalid output entry"])
            }
            files[name] = data.subdata(in: (dataStart + offset)..<(dataStart + offset + size))
        }
        return files
    }
}

private func appendLETest<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}

private func readUInt32Test(_ data: Data, at offset: Int) -> UInt32 {
    UInt32(data[offset]) | (UInt32(data[offset + 1]) << 8) | (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
}

private func readUInt64Test(_ data: Data, at offset: Int) -> UInt64 {
    UInt64(readUInt32Test(data, at: offset)) | (UInt64(readUInt32Test(data, at: offset + 4)) << 32)
}
