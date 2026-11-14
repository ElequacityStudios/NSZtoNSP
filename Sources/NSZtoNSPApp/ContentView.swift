import SwiftUI
import UniformTypeIdentifiers

extension UTType {
    static let nszArchive = UTType(exportedAs: "com.elequacitystudios.nsz", conformingTo: .data)
}

struct ContentView: View {
    @StateObject private var model = ConversionViewModel()
    @State private var showingImporter = false

    private let background = Color(red: 0.035, green: 0.055, blue: 0.09)
    private let panel = Color(red: 0.075, green: 0.105, blue: 0.15)
    private let accent = Color(red: 0.43, green: 0.91, blue: 0.66)

    var body: some View {
        ZStack {
            background.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 26) {
                    header
                    converterCard
                    privacyNote
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
                .padding(.bottom, 36)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
            }
        }
        .preferredColorScheme(.dark)
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.nszArchive],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { model.select(url) }
            case .failure(let error):
                model.showError(error.localizedDescription)
            }
        }
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.clearError() } }
            ),
            actions: { Button("OK", role: .cancel) { model.clearError() } },
            message: { Text(model.errorMessage ?? "") }
        )
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.system(size: 13, weight: .bold))
                Text("ON-DEVICE CONVERTER")
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .tracking(1.6)
            }
            .foregroundStyle(accent)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(accent.opacity(0.1), in: Capsule())

            Text("NSZ → NSP")
                .font(.system(size: 42, weight: .bold, design: .rounded))
                .tracking(-1.5)
                .foregroundStyle(.white)

            Text("Rebuild your compressed archive as an NSP package, right on your iPhone.")
                .font(.system(size: 16))
                .foregroundStyle(.white.opacity(0.68))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var converterCard: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Label("Convert a file", systemImage: "doc.zipper")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(.white)
                Spacer()
                Image(systemName: "iphone")
                    .foregroundStyle(accent.opacity(0.9))
            }

            Button {
                showingImporter = true
            } label: {
                Label(model.selectedURL == nil ? "Choose an NSZ file" : "Choose a different file", systemImage: "folder")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
            }
            .buttonStyle(.bordered)
            .tint(accent)
            .disabled(model.isConverting)

            if let selectedURL = model.selectedURL {
                HStack(spacing: 12) {
                    Image(systemName: "doc.zipper")
                        .font(.system(size: 20))
                        .foregroundStyle(accent)
                        .frame(width: 42, height: 42)
                        .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(selectedURL.lastPathComponent)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(model.selectedFileSizeText)
                            .font(.system(size: 12))
                            .foregroundStyle(.white.opacity(0.55))
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(accent)
                }
                .padding(13)
                .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 15))

                if model.isConverting {
                    VStack(alignment: .leading, spacing: 9) {
                        HStack {
                            Text("Reconstructing NSP")
                            Spacer()
                            Text("\(Int(model.progress * 100))%")
                                .monospacedDigit()
                        }
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.white.opacity(0.8))
                        ProgressView(value: model.progress)
                            .tint(accent)
                        Text("Large files are processed in small chunks; keep the app open.")
                            .font(.system(size: 12))
                            .foregroundStyle(.white.opacity(0.48))
                    }
                } else if let outputURL = model.outputURL {
                    VStack(alignment: .leading, spacing: 11) {
                        Label("NSP ready", systemImage: "checkmark.circle.fill")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(accent)
                        ShareLink(item: outputURL) {
                            Label("Save or share NSP", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(accent)
                        .foregroundStyle(background)
                    }
                } else {
                    Button {
                        model.startConversion()
                    } label: {
                        Label("Convert to NSP", systemImage: "arrow.right.circle.fill")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(accent)
                    .foregroundStyle(background)
                }
            } else {
                Text("Select a .nsz archive from Files to get started.")
                    .font(.system(size: 13))
                    .foregroundStyle(.white.opacity(0.55))
                    .padding(.top, 2)
            }
        }
        .padding(20)
        .background(panel, in: RoundedRectangle(cornerRadius: 22))
        .overlay {
            RoundedRectangle(cornerRadius: 22)
                .stroke(Color.white.opacity(0.07), lineWidth: 1)
        }
    }

    private var privacyNote: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "lock.shield")
                .foregroundStyle(accent)
            VStack(alignment: .leading, spacing: 4) {
                Text("Your file stays on this device")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.88))
                Text("No sign-in or network upload. Section crypto metadata is read from the archive, and file data is streamed in small chunks.")
                    .font(.system(size: 12))
                    .foregroundStyle(.white.opacity(0.52))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 4)
    }
}
