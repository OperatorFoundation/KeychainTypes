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
    // Key Agreement
    func generateAndSavePrivateKey(label: String) -> PrivateKey?
    func retrievePrivateKey(label: String) -> PrivateKey?
    func deleteKey(label: String)

    func retrieveOrGeneratePrivateKey(label: String) -> PrivateKey?
    func storePrivateKey(_ key: PrivateKey, label: String) -> Bool
    func generateKeySearchQuery(label: String) -> CFDictionary

    // Signing
    func generateAndSavePrivateSigningKey(label: String) -> PrivateKey?
    func retrievePrivateSigningKey(label: String) -> PrivateKey?

    func retrieveOrGeneratePrivateSigningKey(label: String) -> PrivateKey?
    func storePrivateSigningKey(_ key: PrivateKey, label: String) -> Bool
}
