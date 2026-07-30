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
    let portable = try result.portableEvidence()
    #expect(portable.version == 1)
    #expect(portable.assurance == .holderSelfIssued)
    #expect(portable.issuerAuthorizationCommitment == nil)
    #expect(portable.transcriptCommitment.count == 96)
    #expect(portable.freshUntil > portable.observedAt)
}

@Test func rejectsMalformedOrPromotedPortableEvidence() throws {
    let digest = String(repeating: "1", count: 96)
    let credential = EvidenceCredential(
        credential: """
        {"evidence":[{"portableEvidence":{
          "version":1,
          "notaryIdentityCommitment":"\(digest)",
          "serverIdentityCommitment":"\(digest)",
          "transcriptCommitment":"\(digest)",
          "disclosedFieldsCommitment":"\(digest)",
          "holderBindingCommitment":"\(digest)",
          "schemaCommitment":"\(digest)",
          "observedAt":"2026-07-22T12:00:00Z",
          "freshUntil":"2026-07-22T12:05:00Z",
          "statusCommitment":"\(digest)",
          "assurance":"issuerUpgraded",
          "issuerAuthorizationCommitment":null
        }}]}
        """,
        holderPublicKey: "",
        holderSignature: "",
        signatureAlgorithm: "ES256"
    )
    #expect(throws: TLSNotaryMobileError.self) {
        try credential.portableEvidence()
    }
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

@Test func walletOfferRequiresConfiguredIssuer() async throws {
    let client = try TLSNotaryMobileClient()
    let evidence = EvidenceCredential(
        credential: "{}",
        holderPublicKey: "",
        holderSignature: "",
        signatureAlgorithm: "ES256"
    )
    await #expect(throws: TLSNotaryMobileError.self) {
        try await client.prepareWalletOffer(from: evidence)
    }
}

@Test func decodesVCIssuerAuthorizationCodeOffer() throws {
    let response = Data(
        """
        {
          "credential_offer_uri": "https://issuer.example/credential-offer/one",
          "deep_link": "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fcredential-offer%2Fone",
          "expires_in": 300
        }
        """.utf8
    )
    let offer = try JSONDecoder().decode(WalletCredentialOffer.self, from: response)
    #expect(offer.credentialOfferURI.absoluteString.hasSuffix("/credential-offer/one"))
    #expect(offer.walletURI.scheme == "openid-credential-offer")
    #expect(offer.expiresIn == 300)
}
