import SwiftUI
import Combine
import AppKit

@main
struct CertTokenHelperApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings { EmptyView() }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var promptPanel: NSPanel?
    private let manager = PasswordPromptManager()
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        manager.$isPromptVisible
            .receive(on: DispatchQueue.main)
            .sink { [weak self] visible in
                if visible {
                    self?.showPrompt()
                } else {
                    self?.hidePrompt()
                }
            }
            .store(in: &cancellables)

        NSLog("CertTokenHelper: launched and listening for password requests")
    }

    private func showPrompt() {
        if promptPanel == nil {
            let panel = NSPanel(
                contentRect: NSRect(x: 0, y: 0, width: 400, height: 320),
                styleMask: [.titled, .closable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            panel.title = "Autenticação do Certificado"
            panel.isFloatingPanel = true
            panel.level = .floating
            panel.hidesOnDeactivate = false
            panel.isReleasedWhenClosed = false
            panel.delegate = self
            panel.contentView = NSHostingView(
                rootView: PasswordPromptView(manager: manager)
            )
            promptPanel = panel
        }

        NSApp.activate(ignoringOtherApps: true)
        promptPanel?.center()
        promptPanel?.makeKeyAndOrderFront(nil)
    }

    private func hidePrompt() {
        promptPanel?.orderOut(nil)
        NSApp.hide(nil)
    }

    func windowWillClose(_ notification: Notification) {
        if manager.isPromptVisible {
            manager.cancel()
        }
    }
}
