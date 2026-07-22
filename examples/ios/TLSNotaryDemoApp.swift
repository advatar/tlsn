import SwiftUI
import TLSNotaryMobile

@main
struct TLSNotaryDemoApp: App {
    private let client: TLSNotaryMobileClient

    init() {
        if let secureKey = try? SecureEnclaveHolderKey() {
            client = try! TLSNotaryMobileClient(holderKey: secureKey)
        } else {
            client = try! TLSNotaryMobileClient(holderKey: SoftwareHolderKey())
        }
    }

    var body: some Scene {
        WindowGroup {
            WebEvidenceView(client: client)
        }
    }
}
