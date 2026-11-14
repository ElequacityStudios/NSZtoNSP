import Foundation
import Combine

private final class ProgressThrottle: @unchecked Sendable {
    private let lock = NSLock()
    private var lastReported: UInt64 = 0

    func shouldReport(_ completed: UInt64, total: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if completed == total || completed == 0 || completed - min(completed, lastReported) >= 8 * 1024 * 1024 {
            lastReported = completed
            return true
        }
        return false
    }
}

@MainActor
final class ConversionViewModel: ObservableObject {
    @Published private(set) var selectedURL: URL?
    @Published private(set) var selectedFileSizeText = "NSZ archive"
    @Published private(set) var outputURL: URL?
    @Published private(set) var progress = 0.0
    @Published private(set) var isConverting = false
    @Published var errorMessage: String?

    func select(_ url: URL) {
        guard url.pathExtension.lowercased() == "nsz" else {
            showError("Choose an NSZ file to convert.")
            return
        }
        selectedURL = url
        outputURL = nil
        progress = 0
        errorMessage = nil
        if let values = try? url.resourceValues(forKeys: [.fileSizeKey]), let size = values.fileSize {
            selectedFileSizeText = ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
        } else {
            selectedFileSizeText = "NSZ archive"
        }
    }

    func startConversion() {
        guard let sourceURL = selectedURL, !isConverting else { return }
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("NSZtoNSP-\(UUID().uuidString)", isDirectory: true)
        let outputURL = folder.appendingPathComponent(sourceURL.deletingPathExtension().lastPathComponent + ".nsp")
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        } catch {
            showError("Could not create a temporary output folder: \(error.localizedDescription)")
            return
        }

        let accessed = sourceURL.startAccessingSecurityScopedResource()
        isConverting = true
        progress = 0
        errorMessage = nil
        self.outputURL = nil
        let throttle = ProgressThrottle()

        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                try NSZConversionEngine.convert(inputURL: sourceURL, outputURL: outputURL) { [weak self] completed, total in
                    guard throttle.shouldReport(completed, total: total) else { return }
                    let value = total == 0 ? 0 : min(1, Double(completed) / Double(total))
                    Task { @MainActor [weak self] in self?.progress = value }
                }
                if accessed { sourceURL.stopAccessingSecurityScopedResource() }
                await self?.conversionSucceeded(at: outputURL)
            } catch {
                if accessed { sourceURL.stopAccessingSecurityScopedResource() }
                let message = error.localizedDescription
                await self?.conversionFailed(message)
            }
        }
    }

    func showError(_ message: String) {
        errorMessage = message
    }

    func clearError() {
        errorMessage = nil
    }

    private func conversionSucceeded(at url: URL) {
        outputURL = url
        progress = 1
        isConverting = false
    }

    private func conversionFailed(_ message: String) {
        isConverting = false
        errorMessage = message
    }
}
