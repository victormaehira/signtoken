import Foundation
import Security

enum RemoteIdSignature {

    static var baseURL = "https://remoteidcertisign.com.br"

    private static let openSessionPath = "/api/signature/tokensessao"
    private static let signHashPath = "/api/signature/requestHashSessionSignature"

    static let serialNumberHardCoded = "5fc79cc5ece66260482c639ce17fb067"
    static let desktopCodeHardCoded = "28db78d7-252d-48f0-a613-01d7c89289c9"
    static let issueHardCoded = "CN=AC Certisign RFB G5,OU=Secretaria da Receita Federal do Brasil - RFB,O=ICP-Brasil,C=BR"
    static let pushHardCoded = false
    static let nomeAplicacaoDesktopHardCoded = ""
    static let privateKeyToSignBearerToken: String = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkszQ4BlgI8X/YBuoYhQO/Uzl6KrIyNRI6wxWp+3gZbDg0OSkMCk86F4LVMGGM1RmNYAsRbpyrIm4RI5Pa+foucyQZGfdX5DdP8sAs671P9l44LjNbeokJPt4sOj8CHZ0bpksntR/zkbimsyyauJQX99AnPZN6ozmPdHOyC6sFZ0vjou6HUIc8g7wwMYr4MOLy0omPOz1Bqwdd5/9PF/e2c/CEJ8YJ95MaK6Lu6wtwoCT4mkIh5VGqmjWaJyD1CBx1OwbRYvI6gUlkSMaCWv1YtsHHCnmNu+epA1a9/BIVbnW+xC9GgmiDZmJdQbWHvLWBw4LNQzD9bnUDwL5HF069AgMBAAECggEAGCVNmokTjvwYygr5du7JRdtlqctopIOzUHoZSvpa+R8sfjuDEQjR5Kpdu/OD2anEPT2/YabdwRkjGdAldQ0A6J5oxGVSJciHc2kbU3qcHoT3+zSKwvaL8JcO61z+r8i3p74RdpjPPl42u/m4qFY3H+xsz9PvMyOK5MUl0Qx03i2ycrRUJnX3v+GSf6J6OuneHb/LMMSPiu5D1VklvlaF+Fihetvx1xYl+vbVfLBS4/QwaeG4G2usw76EL945s4Kge1yRXaAzHB+fMGDogO8ADcuHNas34BuD/PY3k18A/5qpyXZEbaBO2AYdcoS08P5seN6L4vbdcmaHNYLQDrD84QKBgQDRO1NkM2Bj7e+GW6LzSuZfSTzddp/ecXDyWZB01fzz6zKWCPFb1kagRbPvBOF3EtBCqRVJHUlrKC4fpBqu2LzzvrrnFMe2ZSmSzxSwMuce5GhxyAcDh6Gh/xkaLvBi9AAheZXhiZoSbgvQWuxC9Y2kKILYyVHkDQTBDz0vmyAzlwKBgQDJg642RSyCN/MAS8qnF/kPt0hFjaLSkgs4hIdrJyPaQjvDQst/pl6JEzhiLoTLdbXDPcVK8i1Ehs+hnwRN0+sh8gyuR4rNFyKMl1UaT63SLTrILx88mKnUdyALRwlvpbP+eMNbECAQX2ZcfXr6MwbZTro/0tfsjxulI8fU+RmKywKBgAQnTld94Zr6PTgIl6qGwR4BITEwSqoqzFgzSPfYy6W39JAf61KsZUiHObQz/5nSiMnZ+28xIqT67jd4lYMFEHMyRRmTQweu6G1eqQV6bTYiyKQBmYoLZj0GCGSJrAH64AnKFRyeE63r+1YOiAQoRcCNgVN2Y6bIT2DZwZgxVylPAoGBAMcrFRaii/kwX0adonBAK3QzDIViFdnVaq2znzxy9OaVrAezjvpdbvZAPuwbWjjV4I5WERegAMnIDJOLXW+m0rE8UPg30aIfCZC3Se+1bPFcrsqIeHEl2kUacFt1HIhy2FHc/giVCXvlLoCfrNp5cH17aG4IcE1orEQt9yYyBeK9AoGAHPLi/comEHsO5RpFxMRvlT9iaKgp2lVM5NUoA3McTx/IDrgODD1bCQXeL8RwjqVF4CEbF09ZTvr+WKWz297QZZhk67zjx5y24GeL3NsNgbJfYX2dIE1HxN5+tAJyrX+58R3XpvgitjlDtqwa6w5x6JS5Sae8pdRWdbm/4oE76EQ="
    
    // MARK: - Open Session
    struct SessionResult {
        let sessionToken: String
    }

    static func openSession(
        pin: String,
        otp: String,
        appName: String = "addcert"
    ) throws -> SessionResult {
        let body: [String: Any] = [
            "desktopCode": desktopCodeHardCoded,
            "pin": pin,
            "otp": otp,
            "push": pushHardCoded,
            "nomeAplicacaoDesktop": nomeAplicacaoDesktopHardCoded,
            "issue": issueHardCoded,
            "serialNumber": serialNumberHardCoded
        ]

        FileLogger.shared.log("RemoteIdSignature: openSession serial=\(serialNumberHardCoded) issuer=\(issueHardCoded)")

        let response = try performRequest(path: openSessionPath, body: body)

        guard let status = response["status"] as? Bool else {
            throw RemoteIdError.unexpectedResponse("Missing 'status' field in openSession response")
        }

        if status {
            guard let token = response["token"] as? String, !token.isEmpty else {
                throw RemoteIdError.unexpectedResponse("Missing 'token' in successful openSession response")
            }
            FileLogger.shared.log("RemoteIdSignature: openSession succeeded, token length=\(token.count)")
            return SessionResult(sessionToken: token)
        } else {
            let message = response["message"] as? String ?? "Erro desconhecido ao abrir sessao"
            throw RemoteIdError.serverError(message)
        }
    }

    // MARK: - Sign Hash

    static func signHash(
        sessionToken: String,
        hashData: Data,
        algorithm: String = "SHA256"
    ) throws -> Data {
        let hashBase64 = hashData.base64EncodedString()

        let body: [String: Any] = [
            "desktopCode": desktopCodeHardCoded,
            "sessionToken": sessionToken,
            "issue": issueHardCoded,
            "serialNumber": serialNumberHardCoded,
            "algorithm": algorithm,
            "hashArray": [
                ["id": 0, "hash": hashBase64]
            ]
        ]

        FileLogger.shared.log("RemoteIdSignature: signHash hashLen=\(hashData.count) algorithm=\(algorithm) hashHex=\(hashData.map { String(format: "%02x", $0) }.joined())")

        let response = try performRequest(path: signHashPath, body: body)

        guard let status = response["status"] as? Bool else {
            throw RemoteIdError.unexpectedResponse("Missing 'status' field in signHash response")
        }

        guard status else {
            let message = response["message"] as? String ?? "Erro desconhecido na assinatura"
            throw RemoteIdError.serverError(message)
        }

        guard let idArray = response["idArray"] as? [[String: Any]],
              let firstResult = idArray.first else {
            throw RemoteIdError.unexpectedResponse("Missing 'idArray' in signHash response")
        }

        guard let itemStatus = firstResult["status"] as? Bool, itemStatus else {
            let message = firstResult["message"] as? String ?? "Assinatura rejeitada pelo servidor"
            throw RemoteIdError.serverError(message)
        }

        guard let signatureBase64 = firstResult["signatureBase64"] as? String,
              let signatureData = Data(base64Encoded: signatureBase64) else {
            throw RemoteIdError.unexpectedResponse("Missing or invalid 'signatureBase64' in signHash response")
        }

        FileLogger.shared.log("RemoteIdSignature: signHash succeeded, signatureLen=\(signatureData.count)")
        return signatureData
    }

    // MARK: - Bearer Token Signing

    private static var cachedSigningKey: SecKey?

    /// Strips the PKCS#8 ASN.1 wrapper to extract the inner PKCS#1 RSA private key.
    /// SecKeyCreateWithData on macOS expects PKCS#1, not PKCS#8.
    private static func pkcs1FromPKCS8(_ pkcs8: Data) -> Data {
        let bytes = [UInt8](pkcs8)
        var i = 0

        func readLength() -> Int {
            guard i < bytes.count else { return 0 }
            let first = bytes[i]; i += 1
            if first < 0x80 { return Int(first) }
            let count = Int(first & 0x7F)
            var length = 0
            for _ in 0..<count {
                guard i < bytes.count else { return 0 }
                length = (length << 8) | Int(bytes[i]); i += 1
            }
            return length
        }

        // Outer SEQUENCE
        guard i < bytes.count, bytes[i] == 0x30 else { return pkcs8 }
        i += 1; _ = readLength()

        // INTEGER (version)
        guard i < bytes.count, bytes[i] == 0x02 else { return pkcs8 }
        i += 1; let vLen = readLength(); i += vLen

        // SEQUENCE (AlgorithmIdentifier)
        guard i < bytes.count, bytes[i] == 0x30 else { return pkcs8 }
        i += 1; let algLen = readLength(); i += algLen

        // OCTET STRING (contains the PKCS#1 key)
        guard i < bytes.count, bytes[i] == 0x04 else { return pkcs8 }
        i += 1; _ = readLength()

        return Data(bytes[i...])
    }

    private static func getSigningKey() throws -> SecKey {
        if let key = cachedSigningKey { return key }

        guard let keyData = Data(base64Encoded: privateKeyToSignBearerToken) else {
            throw RemoteIdError.unexpectedResponse("Failed to decode privateKeyToSignBearerToken base64")
        }

        let pkcs1Data = pkcs1FromPKCS8(keyData)
        FileLogger.shared.log("RemoteIdSignature: key import - PKCS#8 size=\(keyData.count), PKCS#1 size=\(pkcs1Data.count)")

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(pkcs1Data as CFData, attributes as CFDictionary, &error) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw RemoteIdError.unexpectedResponse("Failed to import signing key: \(desc)")
        }

        cachedSigningKey = secKey
        FileLogger.shared.log("RemoteIdSignature: signing key imported successfully")
        return secKey
    }

    /// Replicates RequestHashSignatureData.conteudoAssinavel() from the Java backend.
    /// Fields are concatenated in alphabetical order by field name.
    private static func conteudoAssinavel(from body: [String: Any]) -> String {
        var sb = ""
        if let v = body["algorithm"] as? String { sb += v }
        if let v = body["desktopCode"] as? String { sb += v }
        if let hashArray = body["hashArray"] as? [[String: Any]] {
            for item in hashArray {
                if let hash = item["hash"] as? String { sb += hash }
                if let id = item["id"] as? Int { sb += String(id) }
                else if let id = item["id"] as? String { sb += id }
            }
        }
        if let v = body["issue"] as? String { sb += v }
        if let v = body["nomeAplicacaoDesktop"] as? String { sb += v }
        if let v = body["otp"] as? String { sb += v }
        if let v = body["pin"] as? String { sb += v }
        if let v = body["push"] as? Bool, v { sb += "push" }
        if let v = body["serialNumber"] as? String { sb += v }
        if let v = body["sessionToken"] as? String { sb += v }
        if let v = body["systemId"] as? String { sb += v }
        return sb
    }

    private static func createBearerToken(for body: [String: Any]) throws -> String {
        let signable = conteudoAssinavel(from: body)
        FileLogger.shared.log("RemoteIdSignature: conteudoAssinavel = \(signable)")

        guard let signableData = signable.data(using: .utf8) else {
            throw RemoteIdError.unexpectedResponse("Failed to encode conteudoAssinavel to UTF-8")
        }

        let key = try getSigningKey()

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA256,
            signableData as CFData,
            &error
        ) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw RemoteIdError.unexpectedResponse("Failed to sign bearer token: \(desc)")
        }

        return (signature as Data).base64EncodedString()
    }

    // MARK: - HTTP Transport

    private static func performRequest(path: String, body: [String: Any]) throws -> [String: Any] {
        guard let url = URL(string: baseURL + path) else {
            throw RemoteIdError.invalidURL(baseURL + path)
        }

        let jsonData = try JSONSerialization.data(withJSONObject: body, options: .sortedKeys)

        if let requestString = String(data: jsonData, encoding: .utf8) {
            FileLogger.shared.log("RemoteIdSignature: REQUEST \(path) -> \(requestString)")
        }

        let bearerToken = try createBearerToken(for: body)
        FileLogger.shared.log("RemoteIdSignature: BEARER \(path) -> \(bearerToken)")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = jsonData
        request.timeoutInterval = 30

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?
        var httpStatusCode: Int = 0

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            responseData = data
            responseError = error
            if let httpResponse = response as? HTTPURLResponse {
                httpStatusCode = httpResponse.statusCode
            }
            semaphore.signal()
        }
        task.resume()

        let waitResult = semaphore.wait(timeout: .now() + 60)
        if waitResult == .timedOut {
            task.cancel()
            throw RemoteIdError.timeout(path)
        }

        if let error = responseError {
            NSLog("RemoteIdSignature: network error on %@: %@", path, error.localizedDescription)
            throw RemoteIdError.networkError(error)
        }

        guard httpStatusCode / 100 == 2 else {
            var serverMessage = "HTTP \(httpStatusCode)"
            if let data = responseData {
                let responseBody = String(data: data, encoding: .utf8) ?? "(binary)"
                FileLogger.shared.log("RemoteIdSignature: ERROR RESPONSE \(path) [HTTP \(httpStatusCode)] -> \(responseBody)")
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let message = json["message"] as? String {
                    serverMessage += ": \(message)"
                }
            }
            NSLog("RemoteIdSignature: HTTP error on %@: %@", path, serverMessage)
            throw RemoteIdError.httpError(statusCode: httpStatusCode, message: serverMessage)
        }

        guard let data = responseData, !data.isEmpty else {
            throw RemoteIdError.unexpectedResponse("Empty response body from \(path)")
        }

        if let responseString = String(data: data, encoding: .utf8) {
            FileLogger.shared.log("RemoteIdSignature: RESPONSE \(path) [HTTP \(httpStatusCode)] -> \(responseString)")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RemoteIdError.unexpectedResponse("Failed to parse JSON response from \(path)")
        }

        return json
    }

    // MARK: - Errors

    enum RemoteIdError: LocalizedError {
        case invalidURL(String)
        case timeout(String)
        case networkError(Error)
        case httpError(statusCode: Int, message: String)
        case serverError(String)
        case unexpectedResponse(String)

        var errorDescription: String? {
            switch self {
            case .invalidURL(let url):
                return "URL invalida: \(url)"
            case .timeout(let path):
                return "Timeout na requisicao: \(path)"
            case .networkError(let error):
                return "Erro de rede: \(error.localizedDescription)"
            case .httpError(_, let message):
                return message
            case .serverError(let message):
                return message
            case .unexpectedResponse(let detail):
                return "Resposta inesperada do servidor: \(detail)"
            }
        }
    }
}
