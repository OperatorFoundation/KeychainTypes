import XCTest
@testable import KeychainTypes
import Crypto
import SwiftHexTools

final class KeychainTypesTests: XCTestCase
{
    func testKeyFormats() throws
    {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        print("raw: \(publicKey.rawRepresentation.count) - \(publicKey.rawRepresentation.hex)")
        print("compact: \(publicKey.compactRepresentation?.count ?? 0) - \(publicKey.compactRepresentation?.hex ?? "none")")
        print("compressed: \(publicKey.compressedRepresentation.count) - \(publicKey.compressedRepresentation.hex)")
        print("x963: \(publicKey.x963Representation.count) - \(publicKey.x963Representation.hex)")
        print("der: \(publicKey.derRepresentation.count) - \(publicKey.derRepresentation.hex)")
        print("pem: \(publicKey.pemRepresentation.count) - \(publicKey.pemRepresentation.data.hex)")
    }

    func testPublicKey() throws
    {
        let inputString = "\"AgR8/StHp2HnkV9oqxk0mR0ZAmHEWpyNTeAMrP3XORBvsjmCSozWougOLljPwxy6Kmybv8aix3MJyr1w8hFec6BU\""
        let publicKey = PublicKey(jsonString: inputString)
    }
    
    func testPublicKeyJSON() throws
    {
        let keyString = "\"AgR8/StHp2HnkV9oqxk0mR0ZAmHEWpyNTeAMrP3XORBvsjmCSozWougOLljPwxy6Kmybv8aix3MJyr1w8hFec6BU\""
        
        let decoder = JSONDecoder()
        let key = try decoder.decode(PublicKey.self, from: keyString.data)
    }
}
