// XCSSET Guard — a small macOS front end for xcsset-guard.sh.
//
// Scans run as you (no password). Fixing selected items runs the bundled script
// once with administrator rights via the standard macOS password prompt.
// Build with ../build-app.sh (no Xcode project needed).

import SwiftUI
import AppKit

// MARK: - Model types

enum Phase { case idle, scanning, fixing, done }
enum CheckState { case running, ok, warn, info }

struct Check: Identifiable {
    let id: Int
    let title: String
    var state: CheckState = .running
    var notes: [String] = []
}

struct Finding: Identifiable, Hashable {
    let id: Int
    let kind: String
    let path: String
    let reason: String

    /// Kinds the script can fix itself; everything else needs a human decision.
    static let fixableKinds: Set<String> = ["proc", "file", "app", "rc", "launchd", "hook", "update", "zip", "pref", "xprotect"]
    var fixable: Bool { Finding.fixableKinds.contains(kind) }

    var kindLabel: String {
        switch kind {
        case "proc": return "Process"
        case "file": return "Dropped file"
        case "app": return "Fake app"
        case "rc": return "Shell startup file"
        case "launchd": return "Background job"
        case "hook": return "Git hook"
        case "pbx": return "Xcode project"
        case "zip": return "Zipped Xcode project"
        case "update": return "Update setting"
        case "xprotect": return "XProtect"
        case "pref": return "Preference file"
        case "sig": return "Tampered app"
        case "browser": return "Hijacked browser"
        case "dock": return "Dock icon"
        case "net": return "Network connection"
        case "githist": return "Git history"
        case "access": return "Not scanned"
        case "c2": return "Network"
        default: return kind
        }
    }

    var fixDescription: String {
        switch kind {
        case "proc": return "Stop the process"
        case "rc": return "Back up, then remove the malware line"
        case "launchd": return "Unload and move to quarantine"
        case "update": return "Turn back on"
        case "xprotect": return "Download the latest malware definitions"
        case "pref": return "Move to quarantine and reload preferences"
        case "pbx": return "Fix manually: revert with git or restore a clean copy"
        case "sig": return "Fix manually: delete it and reinstall from the official site"
        case "browser": return "Fix manually: quit it, reinstall it, change saved passwords"
        case "dock": return "Fix manually: drag it out of the Dock"
        case "githist": return "Fix manually: delete or rewrite the infected branch, locally and on GitHub"
        case "net": return "Fix manually: quit it if you don't recognize it, or block it with a firewall like LuLu"
        case "c2": return "Fix manually: see Details"
        case "access": return "Give XCSSET Guard Full Disk Access, then scan again"
        default: return "Move to quarantine"
        }
    }
}

// MARK: - Process runner

enum Runner {
    /// Runs a command, streaming combined stdout/stderr to `onOutput` on the main queue.
    static func run(_ exe: String, _ args: [String], env: [String: String] = [:],
                    onOutput: @escaping (String) -> Void,
                    completion: @escaping (Int32) -> Void) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        if !env.isEmpty { p.environment = ProcessInfo.processInfo.environment.merging(env) { _, new in new } }
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        DispatchQueue.global(qos: .userInitiated).async {
            do { try p.run() } catch {
                DispatchQueue.main.async { onOutput("Could not start \(exe): \(error)\n"); completion(-1) }
                return
            }
            let h = pipe.fileHandleForReading
            while true {
                let d = h.availableData
                if d.isEmpty { break }
                let s = String(decoding: d, as: UTF8.self)
                DispatchQueue.main.async { onOutput(s) }
            }
            p.waitUntilExit()
            let code = p.terminationStatus
            DispatchQueue.main.async { completion(code) }
        }
    }
}

// MARK: - View model

final class GuardModel: ObservableObject {
    @Published var phase: Phase = .idle
    @Published var checks: [Check] = []
    @Published var findings: [Finding] = []
    @Published var selected: Set<Int> = []
    @Published var log = ""
    @Published var fixLog = ""
    @Published var banner: (text: String, good: Bool)? = nil
    @Published var logWindow = "30m"   // the log search is the slowest step (~100 server names)
    @Published var scanRoot = FileManager.default.homeDirectoryForCurrentUser
    @Published var lastScan: Date? = nil
    // UI state (kept here: @State needs a compiler plugin that ships only with full Xcode)
    @Published var confirmFix = false
    @Published var showDetails = false

    private var buffer = ""
    private var inChecks = false

    let scriptPath = Bundle.main.path(forResource: "xcsset-guard", ofType: "sh") ?? ""
    let home = FileManager.default.homeDirectoryForCurrentUser.path

    var busy: Bool { phase == .scanning || phase == .fixing }
    var selectedFixable: [Finding] { findings.filter { $0.fixable && selected.contains($0.id) } }
    /// Folders macOS wouldn't let the scan read. While any exist, the scan is incomplete.
    var blockedFolders: [Finding] { findings.filter { $0.kind == "access" } }
    var threats: [Finding] { findings.filter { $0.kind != "access" } }

    func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    func pretty(_ path: String) -> String {
        path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    private func tempFile(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("xcsset-guard-\(name)-\(UUID().uuidString).tsv")
    }

    // MARK: Scan

    func scan() {
        guard !busy else { return }
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            banner = ("The scanner script is missing from the app bundle. Rebuild with build-app.sh.", false)
            return
        }
        phase = .scanning
        checks = []; findings = []; selected = []; log = ""; buffer = ""; inChecks = false
        let report = tempFile("report")
        let args = [scriptPath, "--report", report.path, "--log-window", logWindow, "--root", scanRoot.path]
        // Tells the script to name this app (not Terminal) when asking for Full Disk Access.
        Runner.run("/bin/bash", args, env: ["XCSSET_GUARD_APP": "1"],
                   onOutput: { [weak self] in self?.ingest($0) }) { [weak self] _ in
            guard let self else { return }
            if !self.buffer.isEmpty { self.parse(self.buffer); self.buffer = "" }
            self.finishCurrentCheck()
            self.loadReport(report)
            try? FileManager.default.removeItem(at: report)
            self.selected = Set(self.findings.filter(\.fixable).map(\.id))
            self.lastScan = Date()
            self.phase = .done
        }
    }

    private func ingest(_ chunk: String) {
        log += chunk
        buffer += chunk
        while let r = buffer.range(of: "\n") {
            let line = String(buffer[..<r.lowerBound])
            buffer.removeSubrange(..<r.upperBound)
            parse(line)
        }
    }

    private func finishCurrentCheck() {
        if let i = checks.indices.last, checks[i].state == .running { checks[i].state = .ok }
    }

    private func parse(_ line: String) {
        if line.hasPrefix("== ") {
            finishCurrentCheck()
            let t = line.dropFirst(3)
            if let dot = t.firstIndex(of: "."), Int(t[..<dot]) != nil {
                let title = t[t.index(after: dot)...].trimmingCharacters(in: .whitespaces)
                checks.append(Check(id: checks.count, title: pretty(title)))
                inChecks = true
            } else {
                inChecks = false
            }
            return
        }
        guard inChecks, let i = checks.indices.last else { return }
        if line.hasPrefix("   !!") {
            checks[i].state = .warn
        } else if line.hasPrefix("   ok  ") {
            let note = String(line.dropFirst(7))
            if checks[i].state == .running { checks[i].state = .ok }
            if note != "none" { checks[i].notes.append(note) }
        } else if line.hasPrefix("   --  ") {
            checks[i].notes.append(String(line.dropFirst(7)))
            if checks[i].state == .running || checks[i].state == .ok { checks[i].state = .info }
        }
    }

    private func loadReport(_ url: URL) {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        var out: [Finding] = []
        for (n, line) in text.split(separator: "\n").enumerated() {
            let parts = line.split(separator: "\t", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count == 3 else { continue }
            out.append(Finding(id: n, kind: String(parts[0]), path: String(parts[1]), reason: String(parts[2])))
        }
        findings = out
    }

    // MARK: Fix

    func fixSelected() {
        let chosen = selectedFixable
        guard !busy, !chosen.isEmpty else { return }
        let file = tempFile("apply")
        let body = chosen.map { "\($0.kind)\t\($0.path)\t\($0.reason)" }.joined(separator: "\n") + "\n"
        do { try body.write(to: file, atomically: true, encoding: .utf8) } catch {
            banner = ("Could not prepare the fix list: \(error.localizedDescription)", false); return
        }
        phase = .fixing
        banner = nil
        fixLog = ""
        // Arguments go through `quoted form of`, so paths can't break out of the shell command.
        let osa = [
            "-e", "on run argv",
            "-e", "do shell script \"/bin/bash \" & quoted form of item 1 of argv & \" --apply \" & quoted form of item 2 of argv & \" --user \" & quoted form of item 3 of argv & \" 2>&1\" with prompt \"XCSSET Guard needs your password to fix the selected items.\" with administrator privileges",
            "-e", "end run",
            scriptPath, file.path, NSUserName(),
        ]
        Runner.run("/usr/bin/osascript", osa, onOutput: { [weak self] s in
            self?.fixLog += s.replacingOccurrences(of: "\r", with: "\n")
        }) { [weak self] code in
            guard let self else { return }
            try? FileManager.default.removeItem(at: file)
            if code == 0 {
                self.banner = ("Fixed \(chosen.count) item(s). Anything removed is in ~/xcsset-quarantine. Restart your Mac when you're done.", true)
                self.phase = .done
                self.scan()   // re-scan to confirm
            } else if self.fixLog.contains("-128") {
                self.banner = ("Cancelled. Nothing was changed.", false)
                self.phase = .done
            } else {
                self.banner = ("The fix didn't complete. Open Details to see why.", false)
                self.phase = .done
            }
        }
    }

    func openQuarantine() {
        let q = URL(fileURLWithPath: home).appendingPathComponent("xcsset-quarantine")
        if FileManager.default.fileExists(atPath: q.path) {
            NSWorkspace.shared.open(q)
        } else {
            banner = ("The quarantine folder is empty: nothing has been moved yet.", true)
        }
    }

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = scanRoot
        panel.prompt = "Choose"
        panel.message = "Choose where to look for infected Git hooks and Xcode projects."
        if panel.runModal() == .OK, let url = panel.url { scanRoot = url }
    }
}

// MARK: - Views

struct ContentView: View {
    @EnvironmentObject var model: GuardModel

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            controls
            Divider()
            if let b = model.banner { bannerView(b) }
            if model.phase == .done && !model.blockedFolders.isEmpty { accessBanner }
            if model.phase == .idle {
                idleView
            } else {
                results
            }
            Divider()
            footer
        }
        .frame(minWidth: 680, minHeight: 600)
        .onAppear {
            // `open -a "XCSSET Guard" --args --scan` starts a scan right away.
            if CommandLine.arguments.contains("--scan") { model.scan() }
        }
        .confirmationDialog("Fix \(model.selectedFixable.count) selected item(s)?",
                            isPresented: $model.confirmFix, titleVisibility: .visible) {
            Button("Fix") { model.fixSelected() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Files are moved to ~/xcsset-quarantine, not deleted, so you can restore them. macOS will ask for your password.")
        }
    }

    // Header with overall status
    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: headerSymbol)
                .font(.system(size: 34, weight: .medium))
                .foregroundStyle(headerColor)
                .frame(width: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text("XCSSET Guard").font(.title2.bold())
                Text(statusText).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(16)
    }

    private var headerSymbol: String {
        switch model.phase {
        case .idle: return "shield"
        case .scanning, .fixing: return "shield.lefthalf.filled"
        case .done:
            if !model.threats.isEmpty { return "exclamationmark.shield.fill" }
            return model.blockedFolders.isEmpty ? "checkmark.shield.fill" : "questionmark.circle.fill"
        }
    }

    private var headerColor: Color {
        switch model.phase {
        case .done: return model.findings.isEmpty ? .green : .orange
        default: return .accentColor
        }
    }

    private var statusText: String {
        switch model.phase {
        case .idle: return "Checks this Mac for leftovers of the XCSSET malware."
        case .scanning: return "Scanning…"
        case .fixing: return "Fixing selected items…"
        case .done:
            let when = model.lastScan.map { " · scanned \($0.formatted(date: .omitted, time: .shortened))" } ?? ""
            let blocked = model.blockedFolders.count
            let incomplete = blocked > 0 ? " · scan incomplete: \(blocked) folder(s) not readable" : ""
            if model.threats.isEmpty {
                // Never claim "no threats" when part of the Mac couldn't be checked.
                return blocked > 0 ? "Nothing found so far, but \(blocked) folder(s) couldn't be scanned\(when)"
                                   : "No threats found\(when)"
            }
            return "\(model.threats.count) item(s) need attention\(incomplete)\(when)"
        }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("System log:", selection: $model.logWindow) {
                Text("Off").tag("0")
                Text("Last 30 min").tag("30m")
                Text("Last 2 hours").tag("2h")
                Text("Last day (slow)").tag("1d")
            }
            .fixedSize()
            .help("How far back to search the system log for connections to XCSSET servers.")

            Button {
                model.chooseFolder()
            } label: {
                Label(model.pretty(model.scanRoot.path), systemImage: "folder")
                    .lineLimit(1).truncationMode(.middle)
            }
            .help("Where to look for infected Git hooks and Xcode projects.")

            Spacer()

            Button {
                model.scan()
            } label: {
                Label(model.phase == .idle ? "Scan" : "Scan Again", systemImage: "magnifyingglass")
                    .frame(minWidth: 90)
            }
            .keyboardShortcut("r", modifiers: .command)
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .disabled(model.busy)
        }
        .disabled(model.busy)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private func bannerView(_ b: (text: String, good: Bool)) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: b.good ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(b.good ? .green : .orange)
            Text(b.text)
            Spacer()
            Button { model.banner = nil } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless)
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background((b.good ? Color.green : Color.orange).opacity(0.12))
    }

    private var accessBanner: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: "lock.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Scan incomplete: macOS blocked \(model.blockedFolders.count) folder(s)").font(.callout.weight(.semibold))
                Text(model.blockedFolders.map { (model.pretty($0.path) as NSString).lastPathComponent
                        .replacingOccurrences(of: "com~apple~CloudDocs", with: "iCloud Drive") }
                        .joined(separator: ", ")
                     + ". Turn on Full Disk Access for XCSSET Guard, then scan again.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open Full Disk Access…") { model.openFullDiskAccessSettings() }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.orange.opacity(0.12))
    }

    private var idleView: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 56)).foregroundStyle(.tertiary)
            Text("Scan your Mac for XCSSET leftovers").font(.title3)
            Text("Scanning only reads; nothing is changed until you choose what to fix.")
                .foregroundStyle(.secondary)
            Button("Scan Now") { model.scan() }
                .controlSize(.large).buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding()
    }

    private var results: some View {
        List {
            if !model.threats.isEmpty {
                Section("Needs attention") {
                    ForEach(model.threats) { f in FindingRow(finding: f) }
                }
            }
            if !model.blockedFolders.isEmpty {
                Section("Not scanned") {
                    ForEach(model.blockedFolders) { f in FindingRow(finding: f) }
                }
            }
            Section("Checks") {
                ForEach(model.checks) { c in CheckRow(check: c) }
            }
            Section {
                DisclosureGroup("Details", isExpanded: $model.showDetails) {
                    ScrollView {
                        Text(model.fixLog.isEmpty ? model.log : model.fixLog + "\n" + model.log)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(minHeight: 160, maxHeight: 260)
                }
            }
        }
        .listStyle(.inset)
    }

    private var footer: some View {
        HStack {
            Button("Open Quarantine Folder") { model.openQuarantine() }
                .buttonStyle(.link)
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
            let n = model.selectedFixable.count
            Button(n == 0 ? "Fix Selected" : "Fix \(n) Selected…") { model.confirmFix = true }
                .controlSize(.large)
                .disabled(n == 0 || model.busy)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}

struct FindingRow: View {
    @EnvironmentObject var model: GuardModel
    let finding: Finding

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            if finding.fixable {
                Toggle("", isOn: Binding(
                    get: { model.selected.contains(finding.id) },
                    set: { on in if on { model.selected.insert(finding.id) } else { model.selected.remove(finding.id) } }
                ))
                .labelsHidden()
                .toggleStyle(.checkbox)
                .disabled(model.busy)
            } else {
                Image(systemName: "hand.raised.fill").foregroundStyle(.secondary).frame(width: 16)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(finding.kindLabel)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Color.orange.opacity(0.18)))
                    Text(finding.fixDescription).font(.caption).foregroundStyle(.secondary)
                }
                Text(model.pretty(finding.path))
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
                Text(finding.reason).font(.callout).foregroundStyle(.secondary)
                    .lineLimit(3).textSelection(.enabled)
            }
            Spacer(minLength: 0)
            if finding.path.hasPrefix("/"), FileManager.default.fileExists(atPath: finding.path) {
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: finding.path)])
                } label: { Image(systemName: "arrow.right.circle") }
                .buttonStyle(.borderless)
                .help("Show in Finder")
            }
        }
        .padding(.vertical, 3)
    }
}

struct CheckRow: View {
    let check: Check

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            icon.frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title)
                ForEach(check.notes, id: \.self) { n in
                    Text(n).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 1)
    }

    @ViewBuilder private var icon: some View {
        switch check.state {
        case .running: ProgressView().controlSize(.small)
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .warn: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        case .info: Image(systemName: "info.circle.fill").foregroundStyle(.blue)
        }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct XCSSETGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = GuardModel()

    var body: some Scene {
        Window("XCSSET Guard", id: "main") {
            ContentView().environmentObject(model)
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
