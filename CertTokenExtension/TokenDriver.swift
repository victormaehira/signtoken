import CryptoTokenKit

class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    override init() {
        NSLog(">init do TokenDriver")
        print(">init do TokenDriver")
        super.init()
        delegate = self
    }

    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        return Token(tokenDriver: driver, instanceID: configuration.instanceID)
    }
}
