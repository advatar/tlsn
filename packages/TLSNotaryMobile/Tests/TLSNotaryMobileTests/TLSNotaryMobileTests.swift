import Foundation
import Testing
@testable import TLSNotaryMobile

@Test func createsAndVerifiesHolderSignedEvidence() async throws {
    let client = try TLSNotaryMobileClient(holderKey: SoftwareHolderKey())
    let result = try await client.createEvidence(
        EvidenceRequest(
            url: #require(URL(string: "https://example.com/account")),
            retrievedAt: Date(timeIntervalSince1970: 1_753_184_000),
            responseBody: Data("{\"verified\":true}".utf8),
            disclosedFields: ["/verified"],
            notaryAttestation: Data("{\"signature\":\"test\"}".utf8)
        )
    )

    #expect(result.signatureAlgorithm == "ES256")
    #expect(result.verifyHolderSignature())
    #expect(result.credential.contains("TlsNotaryEvidenceCredential"))
    #expect(result.credential.contains("https://example.com"))
}

@Test func rejectsNonHTTPSBeforeCallingRust() async throws {
    let client = try TLSNotaryMobileClient(holderKey: SoftwareHolderKey())
    await #expect(throws: TLSNotaryMobileError.self) {
        try await client.createEvidence(
            EvidenceRequest(
                url: #require(URL(string: "http://example.com")),
                responseBody: Data()
            )
        )
    }
}

@Test func asyncRustCallbackReturnsValidationErrors() async throws {
    let client = try TLSNotaryMobileClient(
        notary: NotaryConfiguration(
            baseURL: #require(URL(string: "http://127.0.0.1:3000")),
            trustedPublicKeyX963: Data(repeating: 1, count: 65)
        )
    )
    await #expect(throws: TLSNotaryMobileError.self) {
        try await client.notarize(url: #require(URL(string: "http://example.com")))
    }
}
