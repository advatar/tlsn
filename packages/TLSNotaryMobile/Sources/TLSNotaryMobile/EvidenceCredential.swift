import CryptoKit
import Foundation
import TLSNMobileFFI

public struct EvidenceRequest: Sendable {
    public var url: URL
    public var method: String
    public var retrievedAt: Date
    public var responseBody: Data
    public var disclosedFields: [String]
    public var notaryAttestation: Data?

    public init(
        url: URL,
        method: String = "GET",
        retrievedAt: Date = .now,
        responseBody: Data,
        disclosedFields: [String] = [],
        notaryAttestation: Data? = nil
    ) {
        self.url = url
        self.method = method
        self.retrievedAt = retrievedAt
        self.responseBody = responseBody
        self.disclosedFields = disclosedFields
        self.notaryAttestation = notaryAttestation
    }
}
public struct EvidenceCredential: Codable, Sendable {
    public let credential: String
    public let holderPublicKey: String
    public let holderSignature: String
    public let signatureAlgorithm: String

    public func verifyHolderSignature() -> Bool {
        guard
            let publicKeyBytes = Data(base64URLEncoded: holderPublicKey),
            let signatureBytes = Data(base64URLEncoded: holderSignature),
            let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureBytes)
        else {
            return false
        }
        return publicKey.isValidSignature(signature, for: Data(credential.utf8))
    }
}

public enum TLSNotaryMobileError: Error, Equatable, LocalizedError {
    case invalidRequest(String)
    case rustFailure(String)
    case invalidRustResponse
    case signingFailure(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidRequest(message), let .rustFailure(message), let .signingFailure(message):
            message
        case .invalidRustResponse:
            "The Rust engine returned an invalid response."
        }
    }
}

public protocol HolderSigningKey: Sendable {
    var did: String { get }
    var publicKeyX963: Data { get }
    func sign(_ data: Data) throws -> Data
}

public struct SoftwareHolderKey: HolderSigningKey {
    private let key: P256.Signing.PrivateKey

    public init() {
        key = P256.Signing.PrivateKey()
    }

    public var publicKeyX963: Data { key.publicKey.x963Representation }
    public var did: String { Self.didJwk(publicKey: publicKeyX963) }

    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    static func didJwk(publicKey: Data) -> String {
        precondition(publicKey.count == 65 && publicKey.first == 0x04)
        let x = publicKey[1..<33].base64URLEncodedString()
        let y = publicKey[33..<65].base64URLEncodedString()
        let jwk = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return "did:jwk:\(Data(jwk.utf8).base64URLEncodedString())"
    }
}

public actor TLSNotaryMobileClient {
    private let holderKey: any HolderSigningKey

    public init(holderKey: any HolderSigningKey = SoftwareHolderKey()) throws {
        guard tlsn_mobile_abi_version() == 1 else {
            throw TLSNotaryMobileError.rustFailure("Unsupported Rust ABI version.")
        }
        self.holderKey = holderKey
    }

    public func createEvidence(_ request: EvidenceRequest) async throws -> EvidenceCredential {
        let input = try Self.encode(request: request, holder: holderKey.did)
        let credential = try await Task.detached {
            try Self.callRust(input)
        }.value

        do {
            let signature = try holderKey.sign(Data(credential.utf8))
            return EvidenceCredential(
                credential: credential,
                holderPublicKey: holderKey.publicKeyX963.base64URLEncodedString(),
                holderSignature: signature.base64URLEncodedString(),
                signatureAlgorithm: "ES256"
            )
        } catch {
            throw TLSNotaryMobileError.signingFailure(error.localizedDescription)
        }
    }

    private static func encode(request: EvidenceRequest, holder: String) throws -> Data {
        guard request.url.scheme?.lowercased() == "https" else {
            throw TLSNotaryMobileError.invalidRequest("Only HTTPS pages can be notarized.")
        }
        var object: [String: Any] = [
            "url": request.url.absoluteString,
            "method": request.method,
            "retrievedAt": ISO8601DateFormatter().string(from: request.retrievedAt),
            "responseBody": request.responseBody.base64EncodedString(),
            "disclosedFields": request.disclosedFields,
            "holder": holder,
        ]
        if let attestation = request.notaryAttestation {
            object["notaryAttestation"] = try JSONSerialization.jsonObject(with: attestation)
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private nonisolated static func callRust(_ input: Data) throws -> String {
        guard let inputString = String(data: input, encoding: .utf8) else {
            throw TLSNotaryMobileError.invalidRequest("Request is not UTF-8.")
        }
        let pointer = inputString.withCString { tlsn_mobile_create_evidence($0) }
        guard let pointer else { throw TLSNotaryMobileError.invalidRustResponse }
        defer { tlsn_mobile_string_free(pointer) }
        let output = String(cString: pointer)
        guard let data = output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw TLSNotaryMobileError.invalidRustResponse
        }
        if let error = object["error"] as? String {
            throw TLSNotaryMobileError.rustFailure(error)
        }
        return output
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
