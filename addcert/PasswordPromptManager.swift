import Combine
import Foundation

class PasswordPromptManager: ObservableObject {
    @Published var isPromptVisible = false
    @Published var errorMessage: String?
    @Published var isVerifying = false

    static let passwordNeeded = Notification.Name("br.com.certisign.addcert.passwordNeeded")
    static let passwordProvided = Notification.Name("br.com.certisign.addcert.passwordProvided")
    static let passwordCancelled = Notification.Name("br.com.certisign.addcert.passwordCancelled")
    static let passwordSuccess = Notification.Name("br.com.certisign.addcert.passwordSuccess")
    static let passwordFailed = Notification.Name("br.com.certisign.addcert.passwordFailed")

    init() {
        DistributedNotificationCenter.default().addObserver(
            forName: Self.passwordNeeded,
            object: nil, queue: .main
        ) { [weak self] notification in
            self?.isVerifying = false
            self?.errorMessage = notification.object as? String
            self?.isPromptVisible = true
        }

        DistributedNotificationCenter.default().addObserver(
            forName: Self.passwordSuccess,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.isVerifying = false
            self?.isPromptVisible = false
            self?.errorMessage = nil
        }

        DistributedNotificationCenter.default().addObserver(
            forName: Self.passwordFailed,
            object: nil, queue: .main
        ) { [weak self] notification in
            self?.isVerifying = false
            self?.errorMessage = notification.object as? String
            self?.isPromptVisible = false
        }
    }

    func submitPassword(_ password: String) {
        isVerifying = true
        DistributedNotificationCenter.default().postNotificationName(
            Self.passwordProvided,
            object: password,
            userInfo: nil,
            deliverImmediately: true
        )
    }

    func cancel() {
        DistributedNotificationCenter.default().postNotificationName(
            Self.passwordCancelled,
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
        isPromptVisible = false
        errorMessage = nil
        isVerifying = false
    }
}
