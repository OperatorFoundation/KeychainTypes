//
//  KeychainProtocol.swift
//
//
//  Created by Dr. Brandon Wiley on 1/27/22.
//

import Crypto
import Foundation

public protocol KeychainProtocol: Codable
{
    func generateAndSavePrivateKey(label: String, type: KeyType) -> PrivateKey?
    func retrievePrivateKey(label: String, type: KeyType) -> PrivateKey?
    func deleteKey(label: String)

    func retrieveOrGeneratePrivateKey(label: String, type: KeyType) -> PrivateKey?
    func storePrivateKey(_ key: PrivateKey, label: String) -> Bool

    func storePassword(server: String, username: String, password: String) throws
    func retrievePassword(server: String) throws -> (username: String, password: String)
    func deletePassword(server: String) throws

    func newSymmetricKey(sizeInBits: Int) -> SymmetricKey
    func hmac(digest: DigestType, key: SymmetricKey, data: Data) -> AuthenticationCode
}
