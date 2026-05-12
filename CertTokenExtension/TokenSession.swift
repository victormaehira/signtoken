import CryptoTokenKit

class TokenSession: TKTokenSession, TKTokenSessionDelegate {

    private static var cachedSessionToken: String?

    // MARK: - Cross-process password prompt via DistributedNotificationCenter

    private static let passwordNeededNotification = Notification.Name("br.com.certisign.addcert.passwordNeeded")
    private static let passwordProvidedNotification = Notification.Name("br.com.certisign.addcert.passwordProvided")
    private static let passwordCancelledNotification = Notification.Name("br.com.certisign.addcert.passwordCancelled")
    private static let passwordSuccessNotification = Notification.Name("br.com.certisign.addcert.passwordSuccess")
    private static let passwordFailedNotification = Notification.Name("br.com.certisign.addcert.passwordFailed")

    private static let passwordSemaphore = DispatchSemaphore(value: 0)
    private static var receivedPassword: String?
    private static var receivedOtp: String?
    private static var passwordWasCancelled = false
    private static var observersReady = false

    private static func setupObservers() {
        guard !observersReady else { return }
        observersReady = true

        DistributedNotificationCenter.default().addObserver(
            forName: passwordProvidedNotification,
            object: nil, queue: nil
        ) { notification in
            if let jsonString = notification.object as? String,
               let data = jsonString.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
                receivedPassword = dict["password"]
                receivedOtp = dict["otp"]
            } else {
                receivedPassword = notification.object as? String
                receivedOtp = nil
            }
            passwordWasCancelled = false
            passwordSemaphore.signal()
        }

        DistributedNotificationCenter.default().addObserver(
            forName: passwordCancelledNotification,
            object: nil, queue: nil
        ) { _ in
            receivedPassword = nil
            passwordWasCancelled = true
            passwordSemaphore.signal()
        }
    }

    private static func requestCredentials(errorMessage: String?) -> (password: String, otp: String)? {
        setupObservers()
        receivedPassword = nil
        receivedOtp = nil
        passwordWasCancelled = false

        DistributedNotificationCenter.default().postNotificationName(
            passwordNeededNotification,
            object: errorMessage,
            userInfo: nil,
            deliverImmediately: true
        )

        NSLog("CertTokenExtension: waiting for password from main app…")
        let result = passwordSemaphore.wait(timeout: .now() + 120)
        if result == .timedOut {
            NSLog("CertTokenExtension: password request timed out")
            return nil
        }
        guard let password = receivedPassword else { return nil }
        return (password: password, otp: receivedOtp ?? "")
    }

    private static func notifySuccess() {
        DistributedNotificationCenter.default().postNotificationName(
            passwordSuccessNotification,
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
    }

    private static func notifyFailed(_ message: String) {
        DistributedNotificationCenter.default().postNotificationName(
            passwordFailedNotification,
            object: message,
            userInfo: nil,
            deliverImmediately: true
        )
    }

    // MARK: - Remote HSM session

    private static let maxPasswordAttempts = 3

    private static func openRemoteSession() throws -> String {
        if let token = cachedSessionToken { return token }

        var errorMessage: String? = nil

        for attempt in 1...maxPasswordAttempts {
            guard let credentials = requestCredentials(errorMessage: errorMessage) else {
                if passwordWasCancelled {
                    throw NSError(domain: "CertTokenExtension", code: -5, userInfo: [
                        NSLocalizedDescriptionKey: "Password entry cancelled by user"
                    ])
                }
                throw NSError(domain: "CertTokenExtension", code: -6, userInfo: [
                    NSLocalizedDescriptionKey: "Password request timed out"
                ])
            }

            NSLog("CertTokenExtension: received credentials (otp length: %d)", credentials.otp.count)
            FileLogger.shared.log("CertTokenExtension: received credentials, calling RemoteIdSignature.openSession")

            do {
                let result = try RemoteIdSignature.openSession(
                    pin: credentials.password,
                    otp: credentials.otp
                )
                cachedSessionToken = result.sessionToken
                notifySuccess()
                NSLog("CertTokenExtension: remote session opened successfully")
                FileLogger.shared.log("CertTokenExtension: remote session opened successfully")
                return result.sessionToken
            } catch {
                NSLog("CertTokenExtension: openSession attempt %d/%d failed: %@",
                      attempt, maxPasswordAttempts, error.localizedDescription)
                FileLogger.shared.log("CertTokenExtension: openSession attempt \(attempt)/\(maxPasswordAttempts) failed: \(error.localizedDescription)")

                if attempt < maxPasswordAttempts {
                    errorMessage = "Falha na autenticação. Tentativa \(attempt) de \(maxPasswordAttempts): \(error.localizedDescription)"
                }
            }
        }

        let finalMessage = "Número máximo de tentativas excedido."
        notifyFailed(finalMessage)
        throw NSError(domain: "CertTokenExtension", code: -2, userInfo: [
            NSLocalizedDescriptionKey: finalMessage
        ])
    }

    override init(token: TKToken) {
        super.init(token: token)
        NSLog(">[NSLog]init do TokenSession")
        print(">[print]init do TokenSession")
        FileLogger.shared.log(">[FileLogger.sharedv4] init do TokenSession")
        delegate = self
    }

    func tokenSession(
    _ session: TKTokenSession,
    supports operation: TKTokenOperation,
    keyObjectID: Any,
    algorithm: TKTokenKeyAlgorithm
    ) -> Bool {
        switch operation {
        case .signData:
            let ok = algorithm.supportsAlgorithm(.rsaSignatureRaw)
            NSLog("CertTokenExtension: supports signData key=%@ -> %@",
                String(describing: keyObjectID), ok ? "YES" : "NO")
            return ok
        case .decryptData:
            let ok = algorithm.supportsAlgorithm(.rsaEncryptionRaw)
            NSLog("CertTokenExtension: supports decryptData key=%@ -> %@",
                String(describing: keyObjectID), ok ? "YES" : "NO")
            return ok
        default:
            NSLog("CertTokenExtension: supports op=%d -> NO (unhandled)",
                operation.rawValue)
            return false
        }
    }

    // DigestInfo ASN.1 prefixes (RFC 8017 Section 9.2 Notes)
    private static let sha256DigestInfoPrefix: [UInt8] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    ]
    private static let sha384DigestInfoPrefix: [UInt8] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30
    ]
    private static let sha512DigestInfoPrefix: [UInt8] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40
    ]

    /// Strips PKCS#1 v1.5 padding (0x00 0x01 [0xFF..] 0x00 [payload])
    /// and returns the inner payload (typically a DigestInfo).
    private static func stripPKCS1v15Padding(from data: Data) -> Data? {
        let bytes = [UInt8](data)
        guard bytes.count >= 11,
              bytes[0] == 0x00,
              bytes[1] == 0x01 else { return nil }

        var i = 2
        while i < bytes.count && bytes[i] == 0xFF { i += 1 }
        guard i < bytes.count, bytes[i] == 0x00 else { return nil }
        i += 1
        guard i < bytes.count else { return nil }
        return Data(bytes[i...])
    }

    /// Strips DigestInfo ASN.1 wrapper, returning just the raw hash
    /// and its algorithm name.
    private static func extractHash(from digestInfo: Data) -> (hash: Data, algorithm: String)? {
        let bytes = [UInt8](digestInfo)
        if bytes.starts(with: sha256DigestInfoPrefix) && bytes.count == 19 + 32 {
            return (Data(bytes.suffix(32)), "SHA256")
        }
        if bytes.starts(with: sha384DigestInfoPrefix) && bytes.count == 19 + 48 {
            return (Data(bytes.suffix(48)), "SHA384")
        }
        if bytes.starts(with: sha512DigestInfoPrefix) && bytes.count == 19 + 64 {
            return (Data(bytes.suffix(64)), "SHA512")
        }
        return nil
    }

    func tokenSession(
        _ session: TKTokenSession,
        sign dataToSign: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        NSLog("CertTokenExtension: sign requested for key %@ (%d bytes)",
              String(describing: keyObjectID), dataToSign.count)
        FileLogger.shared.log("CertTokenExtension: sign requested (\(dataToSign.count) bytes), hex=\(dataToSign.map { String(format: "%02x", $0) }.joined())")

        let sessionToken = try Self.openRemoteSession()

        var hashData = dataToSign
        var hashAlgorithm = "SHA256"

        if let extracted = Self.extractHash(from: dataToSign) {
            hashData = extracted.hash
            hashAlgorithm = extracted.algorithm
            FileLogger.shared.log("CertTokenExtension: stripped DigestInfo, raw hash=\(hashData.count) bytes, algorithm=\(hashAlgorithm)")
        } else if let innerPayload = Self.stripPKCS1v15Padding(from: dataToSign),
                  let extracted = Self.extractHash(from: innerPayload) {
            hashData = extracted.hash
            hashAlgorithm = extracted.algorithm
            FileLogger.shared.log("CertTokenExtension: stripped PKCS#1 v1.5 padding + DigestInfo, raw hash=\(hashData.count) bytes, algorithm=\(hashAlgorithm)")
        } else {
            FileLogger.shared.log("CertTokenExtension: no DigestInfo/PKCS#1 wrapper detected, dataToSign=\(dataToSign.count) bytes, passing as-is")
        }

        FileLogger.shared.log("CertTokenExtension: calling RemoteIdSignature.signHash")
        let signature = try RemoteIdSignature.signHash(
            sessionToken: sessionToken,
            hashData: hashData,
            algorithm: hashAlgorithm
        )

        FileLogger.shared.log("CertTokenExtension: remote sign succeeded (\(signature.count) bytes)")
        NSLog("CertTokenExtension: remote sign succeeded (%d bytes)", signature.count)
        return signature
    }

    func tokenSession(
        _ session: TKTokenSession,
        decrypt ciphertext: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        NSLog("CertTokenExtension: decrypt requested for key %@ (%d bytes)",
              String(describing: keyObjectID), ciphertext.count)

        throw NSError(domain: "CertTokenExtension", code: -4, userInfo: [
            NSLocalizedDescriptionKey: "Remote decrypt not yet implemented"
        ])
    }
}
