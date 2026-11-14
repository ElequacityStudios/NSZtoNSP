import CommonCrypto
import Foundation
import zstdlib

enum NSZConversionError: LocalizedError {
    case notPFS0
    case malformed(String)
    case unsupported(String)
    case truncated
    case zstandard(String)
    case cryptography(Int32)
    case output(String)

    var errorDescription: String? {
        switch self {
        case .notPFS0:
            return "This file is not a valid PFS0-based NSZ archive."
        case .malformed(let detail):
            return "The archive is malformed: \(detail)"
        case .unsupported(let detail):
            return "This archive format is not supported: \(detail)"
        case .truncated:
            return "The archive ended before all declared data was available."
        case .zstandard(let detail):
            return "Zstandard decompression failed: \(detail)"
        case .cryptography(let status):
            return "AES-CTR reconstruction failed (CommonCrypto status \(status))."
        case .output(let detail):
            return "Could not write the NSP file: \(detail)"
        }
    }
}

private struct PFS0Entry {
    let name: String
    let sourceOffset: UInt64
    let inputSize: UInt64
    let outputName: String
    let ncz: NCZMetadata?

    var outputSize: UInt64 { ncz?.outputSize ?? inputSize }
}

struct NCZSection {
    let offset: UInt64
    let size: UInt64
    let cryptoType: UInt64
    let key: Data
    let counter: Data
}

private struct NCZBlockMetadata {
    let exponent: UInt8
    let decompressedSize: UInt64
    let compressedSizes: [UInt32]
    let payloadOffset: UInt64
}

private struct NCZMetadata {
    let sections: [NCZSection]
    let prefixSize: UInt64
    let bodySize: UInt64
    let outputSize: UInt64
    let payloadOffset: UInt64
    let payloadSize: UInt64
    let blocks: NCZBlockMetadata?
}

private func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
    guard count >= 0 else { throw NSZConversionError.malformed("negative read length") }
    var result = Data()
    result.reserveCapacity(count)
    while result.count < count {
        let part = try handle.read(upToCount: count - result.count) ?? Data()
        guard !part.isEmpty else { throw NSZConversionError.truncated }
        result.append(part)
    }
    return result
}

private func readUInt8(_ handle: FileHandle) throws -> UInt8 {
    let data = try readExactly(handle, count: 1)
    return data[0]
}

private func readUInt32LE(_ handle: FileHandle) throws -> UInt32 {
    let b = try readExactly(handle, count: 4)
    return UInt32(b[0]) | (UInt32(b[1]) << 8) | (UInt32(b[2]) << 16) | (UInt32(b[3]) << 24)
}

private func readUInt64LE(_ handle: FileHandle) throws -> UInt64 {
    let b = try readExactly(handle, count: 8)
    var value: UInt64 = 0
    for index in 0..<8 {
        value |= UInt64(b[index]) << (index * 8)
    }
    return value
}

private func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}

private func checkedAdd(_ lhs: UInt64, _ rhs: UInt64, context: String) throws -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw NSZConversionError.malformed("integer overflow while reading \(context)") }
    return value
}

private protocol NCZPayloadReader: AnyObject {
    func read(maximum: Int) throws -> Data
    func finish() throws
}

private final class ZstdStreamReader {
    private struct Step {
        let consumed: Int
        let produced: Int
        let code: Int
    }

    private let handle: FileHandle
    private var sourceOffset: UInt64
    private var sourceRemaining: UInt64
    private var input = Data()
    private var inputOffset = 0
    private let context: OpaquePointer
    private var lastFrameComplete = false
    private var finished = false

    init(handle: FileHandle, offset: UInt64, length: UInt64) throws {
        self.handle = handle
        self.sourceOffset = offset
        self.sourceRemaining = length
        guard let stream = ZSTD_createDStream() else {
            throw NSZConversionError.zstandard("could not allocate a decompression stream")
        }
        let status = ZSTD_initDStream(stream)
        if ZSTD_isError(status) != 0 {
            let message = String(cString: ZSTD_getErrorName(status))
            ZSTD_freeDStream(stream)
            throw NSZConversionError.zstandard(message)
        }
        self.context = stream
    }

    deinit {
        ZSTD_freeDStream(context)
    }

    func read(maximum: Int) throws -> Data {
        guard maximum > 0 else { return Data() }
        if finished { return Data() }
        var output = Data(count: maximum)
        var producedTotal = 0

        try output.withUnsafeMutableBytes { outputBytes in
            guard let outputBase = outputBytes.baseAddress else {
                throw NSZConversionError.zstandard("could not allocate an output buffer")
            }
            while producedTotal == 0 {
                if inputOffset >= input.count {
                    if sourceRemaining == 0 {
                        if lastFrameComplete {
                            finished = true
                            break
                        }
                        throw NSZConversionError.truncated
                    }
                    let amount = Int(min(sourceRemaining, UInt64(128 * 1024)))
                    try handle.seek(toOffset: sourceOffset)
                    input = try readExactly(handle, count: amount)
                    sourceOffset = try checkedAdd(sourceOffset, UInt64(input.count), context: "Zstandard input")
                    sourceRemaining -= UInt64(input.count)
                    inputOffset = 0
                }

                let step: Step = try input.withUnsafeBytes { inputBytes in
                    guard let inputBase = inputBytes.baseAddress else {
                        throw NSZConversionError.zstandard("could not read compressed input")
                    }
                    var inBuffer = ZSTD_inBuffer()
                    inBuffer.src = inputBase
                    inBuffer.size = input.count
                    inBuffer.pos = inputOffset

                    var outBuffer = ZSTD_outBuffer()
                    outBuffer.dst = outputBase
                    outBuffer.size = maximum
                    outBuffer.pos = 0
                    let code = ZSTD_decompressStream(context, &outBuffer, &inBuffer)
                    if ZSTD_isError(code) != 0 {
                        throw NSZConversionError.zstandard(String(cString: ZSTD_getErrorName(code)))
                    }
                    return Step(consumed: inBuffer.pos, produced: outBuffer.pos, code: code)
                }

                inputOffset = step.consumed
                producedTotal = step.produced
                if step.code == 0 && inputOffset == input.count && sourceRemaining == 0 {
                    lastFrameComplete = true
                }
                if producedTotal == 0 && step.consumed == 0 {
                    if step.code == 0 && (inputOffset < input.count || sourceRemaining > 0) {
                        continue
                    }
                    if lastFrameComplete {
                        finished = true
                        break
                    }
                    throw NSZConversionError.zstandard("decompressor made no progress")
                }
            }
        }
        return Data(output.prefix(producedTotal))
    }

    func finish() throws {
        let extra = try read(maximum: 1)
        guard extra.isEmpty else {
            throw NSZConversionError.malformed("Zstandard data expands beyond the declared NCZ section size")
        }
        guard finished else {
            throw NSZConversionError.truncated
        }
    }
}

private final class StreamPayloadReader: NCZPayloadReader {
    private let decoder: ZstdStreamReader
    private var outputRemaining: UInt64

    init(handle: FileHandle, metadata: NCZMetadata) throws {
        self.decoder = try ZstdStreamReader(handle: handle, offset: metadata.payloadOffset, length: metadata.payloadSize)
        self.outputRemaining = metadata.bodySize
    }

    func read(maximum: Int) throws -> Data {
        guard maximum > 0, outputRemaining > 0 else { return Data() }
        let wanted = Int(min(outputRemaining, UInt64(maximum)))
        let data = try decoder.read(maximum: wanted)
        guard !data.isEmpty else { throw NSZConversionError.truncated }
        outputRemaining -= UInt64(data.count)
        return data
    }

    func finish() throws {
        guard outputRemaining == 0 else { throw NSZConversionError.truncated }
        try decoder.finish()
    }
}

private final class BlockPayloadReader: NCZPayloadReader {
    private let handle: FileHandle
    private let blocks: NCZBlockMetadata
    private let blockSize: UInt64
    private var nextBlockOffset: UInt64
    private var blockIndex = 0
    private var hasCurrentBlock = false
    private var currentInputOffset: UInt64 = 0
    private var currentOutputRemaining: UInt64 = 0
    private var currentDecoder: ZstdStreamReader?
    private var outputRemaining: UInt64

    init(handle: FileHandle, metadata: NCZMetadata, blocks: NCZBlockMetadata) throws {
        self.handle = handle
        self.blocks = blocks
        self.blockSize = UInt64(1) << Int(blocks.exponent)
        self.nextBlockOffset = blocks.payloadOffset
        self.outputRemaining = metadata.bodySize
    }

    private func beginBlock() throws {
        guard blockIndex < blocks.compressedSizes.count else { return }
        let outputOffset = UInt64(blockIndex) * blockSize
        let expectedSize = min(blockSize, blocks.decompressedSize - outputOffset)
        let compressedSize = UInt64(blocks.compressedSizes[blockIndex])
        guard compressedSize > 0, compressedSize <= expectedSize else {
            throw NSZConversionError.malformed("invalid NCZBLOCK block size")
        }
        currentInputOffset = nextBlockOffset
        nextBlockOffset = try checkedAdd(nextBlockOffset, compressedSize, context: "NCZBLOCK data")
        currentOutputRemaining = expectedSize
        if compressedSize < expectedSize {
            currentDecoder = try ZstdStreamReader(handle: handle, offset: currentInputOffset, length: compressedSize)
        } else {
            currentDecoder = nil
        }
    }

    func read(maximum: Int) throws -> Data {
        guard maximum > 0, outputRemaining > 0 else { return Data() }
        var result = Data()
        result.reserveCapacity(min(maximum, 1024 * 1024))
        while result.count < maximum && outputRemaining > 0 {
            if !hasCurrentBlock {
                guard blockIndex < blocks.compressedSizes.count else { throw NSZConversionError.truncated }
                try beginBlock()
                hasCurrentBlock = true
            } else if currentOutputRemaining == 0 {
                if let decoder = currentDecoder { try decoder.finish() }
                currentDecoder = nil
                blockIndex += 1
                hasCurrentBlock = false
                continue
            }

            let amount = Int(min(currentOutputRemaining, UInt64(maximum - result.count)))
            let part: Data
            if let decoder = currentDecoder {
                part = try decoder.read(maximum: amount)
            } else {
                try handle.seek(toOffset: currentInputOffset)
                part = try readExactly(handle, count: amount)
                currentInputOffset = try checkedAdd(currentInputOffset, UInt64(part.count), context: "raw NCZBLOCK data")
            }
            guard !part.isEmpty else { throw NSZConversionError.truncated }
            result.append(part)
            currentOutputRemaining -= UInt64(part.count)
            outputRemaining -= UInt64(part.count)
        }
        return result
    }

    func finish() throws {
        guard outputRemaining == 0 else { throw NSZConversionError.truncated }
        if let decoder = currentDecoder { try decoder.finish() }
        guard blockIndex == blocks.compressedSizes.count - 1, currentOutputRemaining == 0 else {
            throw NSZConversionError.malformed("NCZBLOCK contains unused blocks")
        }
        guard nextBlockOffset == blocks.payloadOffset + blocks.compressedSizes.reduce(UInt64(0), { $0 + UInt64($1) }) else {
            throw NSZConversionError.malformed("NCZBLOCK offsets do not match the declared payload")
        }
    }
}

final class AESCTRTransform {
    private var cryptor: CCCryptorRef?

    init(section: NCZSection) throws {
        guard section.key.count == kCCKeySizeAES128, section.counter.count == 16 else {
            throw NSZConversionError.malformed("NCZ section has an invalid AES key or counter")
        }
        var iv = Data(section.counter.prefix(8))
        var blockNumber = (section.offset >> 4).bigEndian
        withUnsafeBytes(of: &blockNumber) { iv.append(contentsOf: $0) }

        var created: CCCryptorRef?
        let status = iv.withUnsafeBytes { ivBytes in
            section.key.withUnsafeBytes { keyBytes in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    section.key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &created
                )
            }
        }
        guard status == kCCSuccess, let created else { throw NSZConversionError.cryptography(status) }
        self.cryptor = created

        let skip = Int(section.offset & 0x0f)
        if skip > 0 {
            do {
                _ = try transform(Data(repeating: 0, count: skip))
            } catch {
                CCCryptorRelease(created)
                self.cryptor = nil
                throw error
            }
        }
    }

    deinit {
        if let cryptor { CCCryptorRelease(cryptor) }
    }

    func transform(_ input: Data) throws -> Data {
        guard let cryptor else { throw NSZConversionError.cryptography(Int32(kCCParamError)) }
        var output = Data(count: input.count)
        var moved = 0
        let status = input.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { destination in
                CCCryptorUpdate(cryptor, source.baseAddress, input.count, destination.baseAddress, output.count, &moved)
            }
        }
        guard status == kCCSuccess, moved == output.count else { throw NSZConversionError.cryptography(status) }
        return output
    }
}

enum NSZConversionEngine {
    private static let ncaHeaderSize: UInt64 = 0x4000
    private static let ioChunkSize = 1024 * 1024

    static func convert(
        inputURL: URL,
        outputURL: URL,
        progress: @Sendable (UInt64, UInt64) -> Void = { _, _ in }
    ) throws {
        guard inputURL.standardizedFileURL != outputURL.standardizedFileURL else {
            throw NSZConversionError.output("source and destination must be different files")
        }
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var result: Result<Void, Error>?
        coordinator.coordinate(readingItemAt: inputURL, options: [], error: &coordinationError) { coordinatedURL in
            result = Result {
                try convertCoordinated(inputURL: coordinatedURL, outputURL: outputURL, progress: progress)
            }
        }
        if let coordinationError { throw coordinationError }
        guard let result else { throw NSZConversionError.output("could not access the selected input file") }
        try result.get()
    }

    private static func convertCoordinated(
        inputURL: URL,
        outputURL: URL,
        progress: @Sendable (UInt64, UInt64) -> Void
    ) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if manager.fileExists(atPath: outputURL.path) { try manager.removeItem(at: outputURL) }

        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }
        let fileSize = try input.seekToEnd()
        try input.seek(toOffset: 0)
        let sourceEntries = try inspectPFS0(handle: input, fileSize: fileSize)
        let outputHeader = try makePFS0Header(entries: sourceEntries.entries, stringTableSize: sourceEntries.stringTableSize)
        let headerSize = UInt64(outputHeader.count)
        let payloadSize = try sourceEntries.entries.reduce(UInt64(0)) { partial, entry in
            try checkedAdd(partial, entry.outputSize, context: "NSP output size")
        }
        let totalSize = try checkedAdd(headerSize, payloadSize, context: "NSP output size")

        guard manager.createFile(atPath: outputURL.path, contents: nil) else {
            throw NSZConversionError.output("could not create the destination file")
        }
        let output = try FileHandle(forWritingTo: outputURL)
        var completed: UInt64 = 0
        do {
            try output.write(contentsOf: outputHeader)
            completed = UInt64(outputHeader.count)
            progress(completed, totalSize)

            for entry in sourceEntries.entries {
                if let ncz = entry.ncz {
                    try reconstructNCZ(entry: entry, metadata: ncz, input: input, output: output) { amount in
                        completed = try checkedAdd(completed, amount, context: "conversion progress")
                        progress(completed, totalSize)
                    }
                } else {
                    try copyRange(handle: input, offset: entry.sourceOffset, size: entry.inputSize, to: output) { amount in
                        completed = try checkedAdd(completed, amount, context: "conversion progress")
                        progress(completed, totalSize)
                    }
                }
            }
            try output.close()
            progress(totalSize, totalSize)
        } catch {
            try? output.close()
            try? manager.removeItem(at: outputURL)
            throw error
        }
    }

    private struct PFS0Archive {
        let entries: [PFS0Entry]
        let stringTableSize: UInt32
    }

    private static func inspectPFS0(handle: FileHandle, fileSize: UInt64) throws -> PFS0Archive {
        try handle.seek(toOffset: 0)
        guard try readExactly(handle, count: 4) == Data("PFS0".utf8) else { throw NSZConversionError.notPFS0 }
        let count = try readUInt32LE(handle)
        let stringTableSize = try readUInt32LE(handle)
        _ = try readUInt32LE(handle)
        guard count > 0, count <= 10_000 else {
            throw NSZConversionError.malformed("file count is outside the supported range")
        }
        guard stringTableSize <= 16 * 1024 * 1024 else {
            throw NSZConversionError.malformed("PFS0 string table is unreasonably large")
        }
        let headerSize = UInt64(16) + UInt64(count) * 0x18 + UInt64(stringTableSize)
        guard headerSize <= fileSize else { throw NSZConversionError.truncated }

        struct RawEntry {
            let offset: UInt64
            let size: UInt64
            let nameOffset: UInt32
        }
        var rawEntries: [RawEntry] = []
        rawEntries.reserveCapacity(Int(count))
        for _ in 0..<count {
            let offset = try readUInt64LE(handle)
            let size = try readUInt64LE(handle)
            let nameOffset = try readUInt32LE(handle)
            _ = try readUInt32LE(handle)
            rawEntries.append(RawEntry(offset: offset, size: size, nameOffset: nameOffset))
        }
        let names = try readExactly(handle, count: Int(stringTableSize))
        var entries: [PFS0Entry] = []
        entries.reserveCapacity(rawEntries.count)

        for raw in rawEntries {
            guard raw.nameOffset < stringTableSize else {
                throw NSZConversionError.malformed("PFS0 filename offset is outside the string table")
            }
            let start = Int(raw.nameOffset)
            var end = start
            while end < names.count && names[end] != 0 { end += 1 }
            guard end < names.count, end > start,
                  let name = String(data: names.subdata(in: start..<end), encoding: .utf8),
                  !name.contains("/"), !name.contains("\\") else {
                throw NSZConversionError.malformed("PFS0 contains an invalid filename")
            }
            let sourceOffset = try checkedAdd(headerSize, raw.offset, context: "PFS0 file offset")
            let sourceEnd = try checkedAdd(sourceOffset, raw.size, context: "PFS0 file size")
            guard sourceEnd <= fileSize else { throw NSZConversionError.truncated }
            let outputName = ncaName(for: name)
            let entryStart = PFS0Entry(name: name, sourceOffset: sourceOffset, inputSize: raw.size, outputName: outputName, ncz: nil)
            let metadata: NCZMetadata?
            if name.lowercased().hasSuffix(".ncz") {
                metadata = try inspectNCZ(handle: handle, entry: entryStart, fileSize: fileSize)
            } else {
                metadata = nil
            }
            entries.append(PFS0Entry(name: name, sourceOffset: sourceOffset, inputSize: raw.size, outputName: outputName, ncz: metadata))
        }

        let sorted = entries.sorted { $0.sourceOffset < $1.sourceOffset }
        var previousEnd = headerSize
        for entry in sorted {
            guard entry.sourceOffset >= previousEnd else {
                throw NSZConversionError.malformed("PFS0 file ranges overlap")
            }
            previousEnd = try checkedAdd(entry.sourceOffset, entry.inputSize, context: "PFS0 file range")
        }
        return PFS0Archive(entries: entries, stringTableSize: stringTableSize)
    }

    private static func ncaName(for name: String) -> String {
        guard name.lowercased().hasSuffix(".ncz") else { return name }
        let stem = String(name.dropLast(4))
        let oldExtension = String(name.suffix(3))
        return stem + (oldExtension == oldExtension.uppercased() ? ".NCA" : ".nca")
    }

    private static func inspectNCZ(handle: FileHandle, entry: PFS0Entry, fileSize: UInt64) throws -> NCZMetadata {
        guard entry.inputSize >= ncaHeaderSize + 16 else {
            throw NSZConversionError.malformed("NCZ entry is too small")
        }
        let entryEnd = try checkedAdd(entry.sourceOffset, entry.inputSize, context: "NCZ file range")
        try handle.seek(toOffset: try checkedAdd(entry.sourceOffset, ncaHeaderSize, context: "NCZ header"))
        guard try readExactly(handle, count: 8) == Data("NCZSECTN".utf8) else {
            throw NSZConversionError.malformed("NCZSECTN header is missing")
        }
        let sectionCount = try readUInt64LE(handle)
        guard sectionCount > 0, sectionCount <= 1024 else {
            throw NSZConversionError.malformed("NCZ section count is outside the supported range")
        }
        var sections: [NCZSection] = []
        sections.reserveCapacity(Int(sectionCount))
        var sectionsSize: UInt64 = 0
        for _ in 0..<sectionCount {
            let offset = try readUInt64LE(handle)
            let size = try readUInt64LE(handle)
            let cryptoType = try readUInt64LE(handle)
            _ = try readUInt64LE(handle)
            let key = try readExactly(handle, count: 16)
            let counter = try readExactly(handle, count: 16)
            guard size > 0, offset >= ncaHeaderSize else {
                throw NSZConversionError.malformed("NCZ section has an invalid offset or size")
            }
            _ = try checkedAdd(offset, size, context: "NCZ section range")
            sectionsSize = try checkedAdd(sectionsSize, size, context: "NCZ section size")
            sections.append(NCZSection(offset: offset, size: size, cryptoType: cryptoType, key: key, counter: counter))
        }
        guard let first = sections.first else { throw NSZConversionError.malformed("NCZ has no sections") }
        let prefixSize = first.offset - ncaHeaderSize
        let bodySize = try checkedAdd(prefixSize, sectionsSize, context: "NCZ decompressed size")
        let outputSize = try checkedAdd(ncaHeaderSize, bodySize, context: "NCA output size")
        let metadataOffset = try handle.offset()
        guard try checkedAdd(metadataOffset, 8, context: "NCZ payload marker") <= entryEnd else { throw NSZConversionError.truncated }
        let marker = try readExactly(handle, count: 8)
        var blocks: NCZBlockMetadata?
        let payloadOffset: UInt64
        if marker == Data("NCZBLOCK".utf8) {
            let version = try readUInt8(handle)
            let type = try readUInt8(handle)
            _ = try readUInt8(handle)
            let exponent = try readUInt8(handle)
            guard version == 2, type == 1 else {
                throw NSZConversionError.unsupported("NCZBLOCK version \(version), type \(type)")
            }
            guard (14...32).contains(Int(exponent)) else {
                throw NSZConversionError.malformed("NCZBLOCK exponent must be between 14 and 32")
            }
            let count = try readUInt32LE(handle)
            let decompressedSize = try readUInt64LE(handle)
            let blockSize = UInt64(1) << Int(exponent)
            let expectedCount = bodySize / blockSize + (bodySize % blockSize == 0 ? 0 : 1)
            guard decompressedSize == bodySize, count > 0, UInt64(count) == expectedCount, count <= 8_000_000 else {
                throw NSZConversionError.malformed("NCZBLOCK dimensions do not match the section table")
            }
            var compressedSizes: [UInt32] = []
            compressedSizes.reserveCapacity(Int(count))
            var totalCompressed: UInt64 = 0
            for _ in 0..<count {
                let size = try readUInt32LE(handle)
                guard size > 0 else { throw NSZConversionError.malformed("NCZBLOCK contains an empty block") }
                compressedSizes.append(size)
                totalCompressed = try checkedAdd(totalCompressed, UInt64(size), context: "NCZBLOCK compressed sizes")
            }
            payloadOffset = try handle.offset()
            let payloadSize = entryEnd - payloadOffset
            guard totalCompressed == payloadSize, payloadOffset <= fileSize else {
                throw NSZConversionError.malformed("NCZBLOCK payload size does not match its block table")
            }
            blocks = NCZBlockMetadata(exponent: exponent, decompressedSize: decompressedSize, compressedSizes: compressedSizes, payloadOffset: payloadOffset)
        } else {
            payloadOffset = metadataOffset
        }
        guard payloadOffset <= entryEnd else { throw NSZConversionError.truncated }
        return NCZMetadata(
            sections: sections,
            prefixSize: prefixSize,
            bodySize: bodySize,
            outputSize: outputSize,
            payloadOffset: payloadOffset,
            payloadSize: entryEnd - payloadOffset,
            blocks: blocks
        )
    }

    private static func makePFS0Header(entries: [PFS0Entry], stringTableSize: UInt32) throws -> Data {
        var table = Data()
        var nameOffsets: [UInt32] = []
        nameOffsets.reserveCapacity(entries.count)
        for entry in entries {
            let bytes = Data(entry.outputName.utf8)
            guard !bytes.contains(0), table.count <= Int(UInt32.max),
                  UInt64(table.count) < UInt64(stringTableSize) else {
                throw NSZConversionError.malformed("output filenames exceed the PFS0 string table")
            }
            nameOffsets.append(UInt32(table.count))
            table.append(bytes)
            table.append(0)
        }
        guard table.count <= Int(stringTableSize) else {
            throw NSZConversionError.malformed("output filenames exceed the PFS0 string table")
        }
        table.append(Data(repeating: 0, count: Int(stringTableSize) - table.count))

        var header = Data("PFS0".utf8)
        appendLE(UInt32(entries.count), to: &header)
        appendLE(stringTableSize, to: &header)
        appendLE(UInt32(0), to: &header)
        var dataOffset: UInt64 = 0
        for (index, entry) in entries.enumerated() {
            appendLE(dataOffset, to: &header)
            appendLE(entry.outputSize, to: &header)
            appendLE(nameOffsets[index], to: &header)
            appendLE(UInt32(0), to: &header)
            dataOffset = try checkedAdd(dataOffset, entry.outputSize, context: "PFS0 output offsets")
        }
        header.append(table)
        return header
    }

    private static func reconstructNCZ(
        entry: PFS0Entry,
        metadata: NCZMetadata,
        input: FileHandle,
        output: FileHandle,
        didWrite: (UInt64) throws -> Void
    ) throws {
        try input.seek(toOffset: entry.sourceOffset)
        let ncaHeader = try readExactly(input, count: Int(ncaHeaderSize))
        try output.write(contentsOf: ncaHeader)
        try didWrite(UInt64(ncaHeader.count))

        let payload: NCZPayloadReader
        if let blocks = metadata.blocks {
            payload = try BlockPayloadReader(handle: input, metadata: metadata, blocks: blocks)
        } else {
            payload = try StreamPayloadReader(handle: input, metadata: metadata)
        }

        if metadata.prefixSize > 0 {
            try writePayload(payload, count: metadata.prefixSize, to: output, didWrite: didWrite)
        }
        for section in metadata.sections {
            let cipher: AESCTRTransform? = (section.cryptoType == 3 || section.cryptoType == 4)
                ? try AESCTRTransform(section: section)
                : nil
            var remaining = section.size
            while remaining > 0 {
                let amount = Int(min(remaining, UInt64(ioChunkSize)))
                let chunk = try readPayload(payload, count: amount)
                let outputData: Data
                if let cipher { outputData = try cipher.transform(chunk) } else { outputData = chunk }
                try output.write(contentsOf: outputData)
                remaining -= UInt64(chunk.count)
                try didWrite(UInt64(outputData.count))
            }
        }
        try payload.finish()
    }

    private static func writePayload(
        _ payload: NCZPayloadReader,
        count: UInt64,
        to output: FileHandle,
        didWrite: (UInt64) throws -> Void
    ) throws {
        var remaining = count
        while remaining > 0 {
            let amount = Int(min(remaining, UInt64(ioChunkSize)))
            let data = try readPayload(payload, count: amount)
            try output.write(contentsOf: data)
            remaining -= UInt64(data.count)
            try didWrite(UInt64(data.count))
        }
    }

    private static func readPayload(_ payload: NCZPayloadReader, count: Int) throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            let part = try payload.read(maximum: count - result.count)
            guard !part.isEmpty else { throw NSZConversionError.truncated }
            result.append(part)
        }
        return result
    }

    private static func copyRange(
        handle: FileHandle,
        offset: UInt64,
        size: UInt64,
        to output: FileHandle,
        didWrite: (UInt64) throws -> Void
    ) throws {
        try handle.seek(toOffset: offset)
        var remaining = size
        while remaining > 0 {
            let amount = Int(min(remaining, UInt64(ioChunkSize)))
            let data = try readExactly(handle, count: amount)
            try output.write(contentsOf: data)
            remaining -= UInt64(data.count)
            try didWrite(UInt64(data.count))
        }
    }
}
