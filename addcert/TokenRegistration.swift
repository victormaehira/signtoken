import Foundation
import Security
import CryptoTokenKit

enum TokenRegistration {

    private static let extensionBundleID = "br.com.certisign.addcert.CertTokenExtension"
    private static let tokenInstanceID = "certisign-hsm-token"
    private static let certObjectID = "cert-0"
    private static let keyObjectID = "key-0"

    // certificado do tato
    /*
    static let certificateBase64 =
    "MIIFgjCCA2qgAwIBAgIIenQqH3pqZyQwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCQlIxLTArBgNVBAoTJENlcnRpc2lnbiBDZXJ0aWZpY2Fkb3JhIERpZ2l0YWwgUy5BLjEkMCIGA1UEAxMbQUMgQ2VydGlTaWduIENvcnBvcmF0aXZhIEczMB4XDTI1MTEwNzAzMDAwMFoXDTI2MTEwNzAzMDAwMFowgY4xCzAJBgNVBAYTAkJSMS0wKwYDVQQKDCRDZXJ0aXNpZ24gQ2VydGlmaWNhZG9yYSBEaWdpdGFsIFMuQS4xHjAcBgNVBAMMFVJlbmF0byBNYWNlZ29zc2EgRGlhczEwMC4GCSqGSIb3DQEJARYhcmVuYXRvLm1hY2Vnb3NzYUBjZXJ0aXNpZ24uY29tLmJyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAniBmkUmNtfZbP9mNbbnZ4ua0n7nacLJXd1/5An+tVHmsGL5+3iW7ZjXFbudy7STDoPbQ7Xbp5hR4Lr1S6Jl789fHl+uZRoGN+PZqmkakGE+dlxWeZV2l1doeuLWacuod2V+pD+zlVnzFk7Ox9pu7yKGPUC8X3+St9TaE6hwkwESv7+fMJNpUOfwzFkOPGDOKCzd0vfKeY10Mn8HaF/fQU1MY56eLLPNAOxz+Gefmj+xWL0TWZ0Gi9n1DnPX3iGaXMEKoHaCCBNBbFQXkcJ/GiGJAjL96qcqTz33kfzcoMs6dezYgwrbz47j6+RNsP1l4YZ3VP8A29SOmsZtblPGADwIDAQABo4IBDTCCAQkwPAYDVR0RBDUwM6AxBgorBgEEAYI3FAIDoCMMIXJlbmF0by5tYWNlZ29zc2FAY2VydGludHJhLmNvbS5icjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFGFwXVXxIdM+YNQGfgQ/ME7pW2lDMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly9jZXJ0aXNpZ24tY2EuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9sY3IvQUNDZXJ0aXNpZ25Db3Jwb3JhdGl2YUczL0xhdGVzdENSTC5jcmwwDgYDVR0PAQH/BAQDAgXgMB8GA1UdJQQYMBYGCCsGAQUFBwMCBgorBgEEAYI3FAICMA0GCSqGSIb3DQEBCwUAA4ICAQCTQmeMXUxpw8iz9xYTEnRWAZKcSpG1sYoAL9QS5+pvrzoJUR/VB6on5yZeEt2v8DKcU0+biR//nVdlgT/KdK8FKsAc/cuJ8fjzh/HStQZWIsP7gt52ORet9Q43kmAQIjBrs3tD6EK1jRJtFeOlMyN8ir9IyEkA/Jo3Hi+M7UKbOdi9gfQUyCr+H/e3L0FiP0nIvS/rlCUDAwoK8pQF8lNmQVS561GRR30jCSHlKyCTjTpeNXTjewnw5xU7xGIDoZriZStNWplC2P6HswZLQgzP06UXwMVxYsBveYyzKBIe2n9oGtZjwPh2rYj5rdGbobWZZx6gKzRFyXhQHUYSxcOtqNnYuqFWWiucaPcGWS/YwBnnVKKFDOJpMaGe/3vJq56Kmd7hAy0ssUhWBY5Wx867SkbhrRx5P7jQb/cXUgJdcsY7tQON7L+j+RmfQDm9d7hN74Jyz4HBynGRVkCxZJk7XGO5FgF0N2Ey/ta4sLNtBq07ywjn1/rPxbi9papoYXdjTvuT+R80JVJssiH6IIHIopn+IihXe2vjF6a0B4Ojc+6JMN9Atm0fr/3ozQhvkjCKMY+crQh6BFjrSKRaF7yPn8fHINsu+yjsOEe75/N4/yFRh7vWSVN1Mul/EJ1xfDjrJ+fUPiFHIq2rX27Fv1omodbLpLX7BM9VVWmzN00sjw=="
    */
     
    //VICTOR
    static let certificateBase64 =
    "MIIFfDCCA2SgAwIBAgIIEt6nQ2Ejuz0wDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCQlIxLTArBgNVBAoTJENlcnRpc2lnbiBDZXJ0aWZpY2Fkb3JhIERpZ2l0YWwgUy5BLjEkMCIGA1UEAxMbQUMgQ2VydGlTaWduIENvcnBvcmF0aXZhIEczMB4XDTI1MTEwOTAzMDAwMFoXDTI2MTEwOTAzMDAwMFowgYoxCzAJBgNVBAYTAkJSMS0wKwYDVQQKDCRDZXJ0aXNpZ24gQ2VydGlmaWNhZG9yYSBEaWdpdGFsIFMuQS4xHDAaBgNVBAMME1ZpY3RvciBZdWppIE1hZWhpcmExLjAsBgkqhkiG9w0BCQEWH3ZpY3Rvci5tYWVoaXJhQGNlcnRpc2lnbi5jb20uYnIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC38o1fQqrgsZz8AhWwCKxgDYE4ia0/sdMvqgHqT0G8n88TbRgZ2kMrc5e9ybVD+TlvmSaeN08EAx5NdB7mGJK/EGvRGlbKRIH0Soi9Eyv6Tvb9SDGod0OikK7YtS50rzkWQx2UVs7tQwOX139hlLXE8dfiL0KJ3/42hsKa/L1ZsoJBTXHleMScOFye1FdNgychP5ICJvWEo/Azz0CxZ9CITfRYpT7LVfFrQPWTGmdIIf7HOuO1YlTZ42gws3g05B5xTfq8KtSHzSIsRkscfmaZVP00o/o097f+gAU5jDC/t9ABDfHQT9PznIQWoR315/D+EVMsHVPbxGB4bg1pBBsvAgMBAAGjggELMIIBBzA6BgNVHREEMzAxoC8GCisGAQQBgjcUAgOgIQwfdmljdG9yLm1hZWhpcmFAY2VydGludHJhLmNvbS5icjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFGFwXVXxIdM+YNQGfgQ/ME7pW2lDMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly9jZXJ0aXNpZ24tY2EuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9sY3IvQUNDZXJ0aXNpZ25Db3Jwb3JhdGl2YUczL0xhdGVzdENSTC5jcmwwDgYDVR0PAQH/BAQDAgXgMB8GA1UdJQQYMBYGCCsGAQUFBwMCBgorBgEEAYI3FAICMA0GCSqGSIb3DQEBCwUAA4ICAQCbrURiIPc+nIVatWYsyuZ631y/ziDamb3VzgQJf2gRY0qlAd/vFkanoTkaYRU0GEMeBbxh1Wk2eWUz85ptmr+lPFTYtb6CsVidpyP9QA9Pe6aWmd0vhxgUrWjIOLZmr2IVvmztsmqmWEMXkMU/I/LG3Y2oAJvzdHvieRMRspBw91Fc6mnUvce3OV0+xuqYrhya2dmOnrJx9kpvHPBeWri4qzik3XlpiG/VDvbfdeFnHg9NPbmsMR9hXjINSSHFEddJwaQZZhaL4T9GvEcibi7wAn5rbHyt85oOj0MF3vTqTbPm7TMChTT6HnlSZmzGOlVrUlkT6dxlYqUQvFAPDFQDodu1RKLaF/+KD9Jlsjm0e4QO8CstvIXA9QCQNqzrwoVFrg0Ob4d7WH733OjpiGsOmtRk2FKQfKKFpATTBwrfZ6bJjvKedOC9aD3i+GJoNvlbpTq6XopWci9L8T7NFBO6ubA6ZUkkwR1RMh+p0xXNP5fkWZL1djd0JYz1aO6MbCKspSIFlO+CaXe4gWgOg/GlJ4JgFWw0OEPaVxWzd75uW7XaE4WN/+EyBJ5dtf+4/5P53ZB6F/eAl6Ajan8yOnHPLReQLYMxGmvROBcEYcrysu3X0Oe6gPzJtLm/qdXso0V8tZSdajmy+i3hfQ55Xp67uxKeNxd+v/GimYvJg/33QQ=="
    
    // self signed cursor
    /*
    static let certificateBase64 = """
    MIIDajCCAlICCQC+XvuMmLZU4DANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJC\
    UjELMAkGA1UECAwCU1AxETAPBgNVBAcMCFNhb1BhdWxvMRIwEAYDVQQKDAlDZXJ0\
    aXNpZ24xEDAOBgNVBAsMB0hTTVRlc3QxIjAgBgNVBAMMGUluc3RhbGxDZXJ0UGx1\
    Z2luVGVzdENlcnQwHhcNMjYwNDA3MTg1NTI1WhcNMzYwNDA0MTg1NTI1WjB3MQsw\
    CQYDVQQGEwJCUjELMAkGA1UECAwCU1AxETAPBgNVBAcMCFNhb1BhdWxvMRIwEAYD\
    VQQKDAlDZXJ0aXNpZ24xEDAOBgNVBAsMB0hTTVRlc3QxIjAgBgNVBAMMGUluc3Rh\
    bGxDZXJ0UGx1Z2luVGVzdENlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\
    AoIBAQCmMf/nDClD+QpXaGy/4FRmiurDApkSXF3e0M4SQQWOrBv1wTIKPZowwr8b\
    UaGiGg3uk7PepF9S/L7q8R/ACX5KxPjNj6RnDIHrzZDan2Y/4WuiDXJVE9hNQRuJ\
    vO0SDwI2idCRp7dGpQIGwcvdksGjzzmuuGcwPUqmrzTG16RyPCDe7tZqqs4oPb28\
    iiqViWhjGKpWnpLXbhOIqwVNvj+UQtKsOLcOOQZa4tRt0T3JrJJIVLWey5IDFxxT\
    irXEUTggmX03GEOKt0+3Uo11oMrQTvg2DaVtWD1BdGs5snH0RsSI8yNuzxfZp9Nu\
    ZpD6gd3V5ibXZ6A/eQ4U3qItsf//AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABcY\
    HRnQL7m8OWogxe9VRcD49d+gFNhh2YzrChtXJSa08/HdJL/ApW2ZSkgghAOduUHc\
    yAFh2grc3XCBGuGNEo4l8oHpGVz9Dx6eCJVMc9nJNnLbJAOZuUArKaMNQyGsOxxK\
    YRUcjNOhLxsAyX7J434FSMZlzuOc0RnydmJibl/LkippFINJT8vV6TgRc7CZfYyL\
    elKCQeGiwtQHX/W2GWPCoUgNWuhGoPJxc2X6Wkqc/P0XpwhZULZy2/a0N14qCtN+\
    y0e9fYmA5pdzKJEVku5ATwmXcBGEeYLjW7m/ijO2A0M8kDf/6otw2F/CD0B25dZ8\
    xYefvb4SafN8f9WGdio=
    """
    */
     
    enum RegistrationError: LocalizedError {
        case invalidBase64Data
        case invalidDERCertificate
        case driverNotFound
        case keychainError(OSStatus)

        var errorDescription: String? {
            switch self {
            case .invalidBase64Data:
                return "Falha ao decodificar dados base64 do certificado"
            case .invalidDERCertificate:
                return "Os dados nao representam um certificado DER valido"
            case .driverNotFound:
                return "Extension CryptoTokenKit nao encontrada"
            case .keychainError(let status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? "codigo \(status)"
                return "Erro no Keychain: \(message)"
            }
        }
    }

    static func registerIfPossible() throws {
        let cleanBase64 = certificateBase64
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: " ", with: "")

        guard let derData = Data(base64Encoded: cleanBase64) else {
            throw RegistrationError.invalidBase64Data
        }

        guard let certificate = SecCertificateCreateWithData(nil, derData as CFData) else {
            throw RegistrationError.invalidDERCertificate
        }

        let subjectSummary = SecCertificateCopySubjectSummary(certificate) as String? ?? "(desconhecido)"
        NSLog("Registrando certificado no token: %@", subjectSummary)

        ensureExtensionRegistered()

        try registerTokenConfiguration(certificate: certificate, displayLabel: subjectSummary)

        NSLog("Certificado registrado com sucesso via CryptoTokenKit")
    }

    /// Registra a extensao CryptoTokenKit no sistema via pluginkit,
    /// necessario quando o app e executado fora de /Applications (ex.: via Xcode).
     private static func ensureExtensionRegistered() {
        if TKTokenDriver.Configuration.driverConfigurations[extensionBundleID] != nil {
            NSLog("Extensao ja registrada no sistema")
            return
        }

        let appURL = Bundle.main.bundleURL

        // Forca o registro do app bundle no Launch Services para que
        // o macOS descubra as extensoes embutidas
        let lsregisterPath = "/System/Library/Frameworks/CoreServices.framework" +
            "/Versions/A/Frameworks/LaunchServices.framework" +
            "/Versions/A/Support/lsregister"
        runProcess(lsregisterPath, ["-f", appURL.path])

        guard let pluginsURL = Bundle.main.builtInPlugInsURL else {
            NSLog("BuiltInPlugIns URL nao encontrada")
            return
        }

        let appexURL = pluginsURL.appendingPathComponent("CertTokenExtension.appex")
        guard FileManager.default.fileExists(atPath: appexURL.path) else {
            NSLog("CertTokenExtension.appex nao encontrada em: %@", appexURL.path)
            return
        }

        NSLog("Registrando extensao via pluginkit: %@", appexURL.path)
        runProcess("/usr/bin/pluginkit", ["-a", appexURL.path])
        runProcess("/usr/bin/pluginkit", ["-e", "use", "-i", extensionBundleID])

        Thread.sleep(forTimeInterval: 3.0)
    }

    private static func runProcess(_ path: String, _ arguments: [String]) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            NSLog("%@ %@ -> exit code: %d output: %@",
                  (path as NSString).lastPathComponent,
                  arguments.joined(separator: " "),
                  process.terminationStatus,
                  output)
        } catch {
            NSLog("Falha ao executar %@: %@", path, error.localizedDescription)
        }
    }

    private static func registerTokenConfiguration(certificate: SecCertificate, displayLabel: String) throws {
        var configs = TKTokenDriver.Configuration.driverConfigurations

        for attempt in 1...5 where configs[extensionBundleID] == nil {
            NSLog("Driver nao encontrado (tentativa %d/5), aguardando...", attempt)
            Thread.sleep(forTimeInterval: 3.0)
            configs = TKTokenDriver.Configuration.driverConfigurations
        }

        let availableDrivers = configs.keys.joined(separator: ", ")
        NSLog("Drivers disponiveis: %@", availableDrivers.isEmpty ? "(nenhum)" : availableDrivers)

        guard let driverConfig = configs[extensionBundleID] else {
            throw RegistrationError.driverNotFound
        }

        let tokenConfig = driverConfig.addTokenConfiguration(for: tokenInstanceID)

        guard let certItem = TKTokenKeychainCertificate(certificate: certificate, objectID: certObjectID) else {
            throw RegistrationError.invalidDERCertificate
        }
        certItem.label = displayLabel

        guard let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: keyObjectID) else {
            throw RegistrationError.invalidDERCertificate
        }
        keyItem.label = displayLabel + " (chave)"
        keyItem.canSign = true
        keyItem.canDecrypt = true
        keyItem.isSuitableForLogin = true

        tokenConfig.keychainItems = [certItem, keyItem]
    }
}
