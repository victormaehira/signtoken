import CryptoTokenKit

class Token: TKToken, TKTokenDelegate {
    override init(tokenDriver: TKTokenDriver, instanceID: String) {
        super.init(tokenDriver: tokenDriver, instanceID: instanceID)
        NSLog(">init do Token")
        print(">init do Token")
        delegate = self
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        return TokenSession(token: self)
    }
}
