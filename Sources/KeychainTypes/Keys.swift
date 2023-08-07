//
//  Keys.swift
//
//
//  Created by Dr. Brandon Wiley on 1/27/22.
//

import Crypto
import Foundation

import Datable
import SwiftHexTools

public struct Keypair
{
    public let privateKey: PrivateKey
    public let publicKey: PublicKey

    public init(privateKey: PrivateKey, publicKey: PublicKey)
    {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

public enum KeyType: UInt8, Codable
{
    case Curve25519KeyAgreement = 1
    case P256KeyAgreement = 2
    case P384KeyAgreement = 3
    case P521KeyAgreement = 4

    case Curve25519Signing = 5
    case P256Signing = 6
    case P384Signing = 7
    case P521Signing = 8

    #if os(macOS) || os(iOS)
    case P256SecureEnclaveKeyAgreement = 9
    case P256SecureEnclaveSigning = 10
    #endif
}

public extension KeyType
{
    init?(_ data: Data)
    {
        guard data.count == 1 else
        {
            return nil
        }

        let uint8 = UInt8(data: data)

        self.init(rawValue: uint8)
    }

    var data: Data
    {
        return self.rawValue.data
    }
}

public enum PrivateKey
{
    case Curve25519KeyAgreement(Curve25519.KeyAgreement.PrivateKey)
    case P521KeyAgreement(P521.KeyAgreement.PrivateKey)
    case P384KeyAgreement(P384.KeyAgreement.PrivateKey)
    case P256KeyAgreement(P256.KeyAgreement.PrivateKey)

    case Curve25519Signing(Curve25519.Signing.PrivateKey)
    case P521Signing(P521.Signing.PrivateKey)
    case P384Signing(P384.Signing.PrivateKey)
    case P256Signing(P256.Signing.PrivateKey)

    #if os(macOS) || os(iOS)
    case P256SecureEnclaveKeyAgreement(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case P256SecureEnclaveSigning(SecureEnclave.P256.Signing.PrivateKey)
    #endif
}

extension PrivateKey
{
    static public func new(type: KeyType) throws -> PrivateKey
    {
        switch type
        {
            case .Curve25519KeyAgreement:
                return .Curve25519KeyAgreement(Curve25519.KeyAgreement.PrivateKey())
            case .P521KeyAgreement:
                return .P521KeyAgreement(P521.KeyAgreement.PrivateKey())
            case .P384KeyAgreement:
                return .P384KeyAgreement(P384.KeyAgreement.PrivateKey())
            case .P256KeyAgreement:
                return .P256KeyAgreement(P256.KeyAgreement.PrivateKey())

            case .Curve25519Signing:
                return .Curve25519KeyAgreement(Curve25519.KeyAgreement.PrivateKey())
            case .P521Signing:
                return .P521Signing(P521.Signing.PrivateKey())
            case .P384Signing:
                return .P384Signing(P384.Signing.PrivateKey())
            case .P256Signing:
                return .P256Signing(P256.Signing.PrivateKey())

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                return .P256SecureEnclaveKeyAgreement(try SecureEnclave.P256.KeyAgreement.PrivateKey())
            case .P256SecureEnclaveSigning:
                return .P256SecureEnclaveSigning(try SecureEnclave.P256.Signing.PrivateKey())
            #endif
        }
    }

    public init(type: KeyType) throws
    {
        switch type
        {
            case .Curve25519KeyAgreement:
                self = .Curve25519KeyAgreement(Curve25519.KeyAgreement.PrivateKey())
            case .P521KeyAgreement:
                self = .P521KeyAgreement(P521.KeyAgreement.PrivateKey())
            case .P384KeyAgreement:
                self = .P384KeyAgreement(P384.KeyAgreement.PrivateKey())
            case .P256KeyAgreement:
                self = .P256KeyAgreement(P256.KeyAgreement.PrivateKey())

            case .Curve25519Signing:
                self = .Curve25519Signing(Curve25519.Signing.PrivateKey())
            case .P521Signing:
                self = .P521Signing(P521.Signing.PrivateKey())
            case .P384Signing:
                self = .P384Signing(P384.Signing.PrivateKey())
            case .P256Signing:
                self = .P256Signing(P256.Signing.PrivateKey())

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                self = .P256SecureEnclaveKeyAgreement(try SecureEnclave.P256.KeyAgreement.PrivateKey())
            case .P256SecureEnclaveSigning:
                self = .P256SecureEnclaveSigning(try SecureEnclave.P256.Signing.PrivateKey())
            #endif
        }
    }

    public init(typedData: Data) throws
    {
        guard typedData.count > 1 else
        {
            throw KeysError.badKeyTypeData(#file, #line, typedData.hex, typedData.count)
        }

        let typeData = typedData[0..<1]
        let valueData = typedData[1...]

        guard let type = KeyType(typeData) else
        {
            throw KeysError.badKeyTypeData(#file, #line, typedData.hex, typedData.count)
        }

        try self.init(type: type, data: valueData)
    }

    public init(type: KeyType, data: Data) throws
    {
        switch type
        {
            case .Curve25519KeyAgreement:
                self = .Curve25519KeyAgreement(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data))
            case .P521KeyAgreement:
                self = .P521KeyAgreement(try P521.KeyAgreement.PrivateKey(rawRepresentation: data))
            case .P384KeyAgreement:
                self = .P384KeyAgreement(try P384.KeyAgreement.PrivateKey(rawRepresentation: data))
            case .P256KeyAgreement:
                self = .P256KeyAgreement(try P256.KeyAgreement.PrivateKey(rawRepresentation: data))

            case .Curve25519Signing:
                self = .Curve25519Signing(try Curve25519.Signing.PrivateKey(rawRepresentation: data))
            case .P521Signing:
                self = .P521Signing(try P521.Signing.PrivateKey(rawRepresentation: data))
            case .P384Signing:
                self = .P384Signing(try P384.Signing.PrivateKey(rawRepresentation: data))
            case .P256Signing:
                self = .P256Signing(try P256.Signing.PrivateKey(rawRepresentation: data))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                self = .P256SecureEnclaveKeyAgreement(try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data))
            case .P256SecureEnclaveSigning:
                self = .P256SecureEnclaveSigning(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data))
            #endif
        }
    }

    public init(type: KeyType, x963Data data: Data) throws
    {
        switch type
        {
            case .Curve25519KeyAgreement:
                throw KeysError.noX963
            case .P521KeyAgreement:
                self = .P521KeyAgreement(try P521.KeyAgreement.PrivateKey(x963Representation: data))
            case .P384KeyAgreement:
                self = .P384KeyAgreement(try P384.KeyAgreement.PrivateKey(x963Representation: data))
            case .P256KeyAgreement:
                self = .P256KeyAgreement(try P256.KeyAgreement.PrivateKey(x963Representation: data))

            case .Curve25519Signing:
                throw KeysError.noX963
            case .P521Signing:
                self = .P521Signing(try P521.Signing.PrivateKey(x963Representation: data))
            case .P384Signing:
                self = .P384Signing(try P384.Signing.PrivateKey(x963Representation: data))
            case .P256Signing:
                self = .P256Signing(try P256.Signing.PrivateKey(x963Representation: data))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                throw KeysError.noX963
            case .P256SecureEnclaveSigning:
                throw KeysError.noX963
            #endif
        }
    }

    public var type: KeyType
    {
        switch self
        {
            case .Curve25519KeyAgreement:
                return .Curve25519KeyAgreement
            case .P521KeyAgreement:
                return .P521KeyAgreement
            case .P384KeyAgreement:
                return .P384KeyAgreement
            case .P256KeyAgreement:
                return .P256KeyAgreement

            case .Curve25519Signing:
                return .Curve25519Signing
            case .P521Signing:
                return .P521Signing
            case .P384Signing:
                return .P384Signing
            case .P256Signing:
                return .P256Signing

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                return .P256SecureEnclaveKeyAgreement
            case .P256SecureEnclaveSigning:
                return .P256SecureEnclaveSigning
            #endif
        }
    }

    public var data: Data?
    {
        switch self
        {
            case .Curve25519KeyAgreement(let key):
                return key.rawRepresentation
            case .P521KeyAgreement(let key):
                return key.rawRepresentation
            case .P384KeyAgreement(let key):
                return key.rawRepresentation
            case .P256KeyAgreement(let key):
                return key.rawRepresentation

            case .Curve25519Signing(let key):
                return key.rawRepresentation
            case .P521Signing(let key):
                return key.rawRepresentation
            case .P384Signing(let key):
                return key.rawRepresentation
            case .P256Signing(let key):
                return key.rawRepresentation

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement(let key):
                return key.dataRepresentation
            case .P256SecureEnclaveSigning(let key):
                return key.dataRepresentation
            #endif
        }
    }

    public var x963: Data?
    {
        switch self
        {
            case .Curve25519KeyAgreement:
                return nil
            case .P521KeyAgreement(let key):
                return key.x963Representation
            case .P384KeyAgreement(let key):
                return key.x963Representation
            case .P256KeyAgreement(let key):
                return key.x963Representation

            case .Curve25519Signing:
                return nil
            case .P521Signing(let key):
                return key.x963Representation
            case .P384Signing(let key):
                return key.x963Representation
            case .P256Signing(let key):
                return key.x963Representation

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                return nil
            case .P256SecureEnclaveSigning:
                return nil
            #endif
        }
    }

    public var typedData: Data?
    {
        let typeData = self.type.data
        guard let valueData = self.data else
        {
            return nil
        }

        return typeData + valueData
    }

    public var secureEnclave: Bool
    {
        switch self
        {
            case .Curve25519KeyAgreement:
                return false
            case .P521KeyAgreement:
                return false
            case .P384KeyAgreement:
                return false
            case .P256KeyAgreement:
                return false

            case .Curve25519Signing:
                return false
            case .P521Signing:
                return false
            case .P384Signing:
                return false
            case .P256Signing:
                return false

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                return true
            case .P256SecureEnclaveSigning:
                return true
            #endif
        }
    }

    public var publicKey: PublicKey
    {
        switch self
        {
            case .Curve25519KeyAgreement(let key):
                return PublicKey.Curve25519KeyAgreement(key.publicKey)
            case .P521KeyAgreement(let key):
                return PublicKey.P521KeyAgreement(key.publicKey)
            case .P384KeyAgreement(let key):
                return PublicKey.P384KeyAgreement(key.publicKey)
            case .P256KeyAgreement(let key):
                return PublicKey.P256KeyAgreement(key.publicKey)

            case .Curve25519Signing(let key):
                return PublicKey.Curve25519Signing(key.publicKey)
            case .P521Signing(let key):
                return PublicKey.P521Signing(key.publicKey)
            case .P384Signing(let key):
                return PublicKey.P384Signing(key.publicKey)
            case .P256Signing(let key):
                return PublicKey.P256Signing(key.publicKey)

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement(let key):
                return PublicKey.P256KeyAgreement(key.publicKey)
            case .P256SecureEnclaveSigning(let key):
                return PublicKey.P256Signing(key.publicKey)
            #endif
        }
    }

    public func sharedSecretFromKeyAgreement(with publicKeyShare: PublicKey) throws -> SharedSecret
    {
        switch self
        {
            case .Curve25519KeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .Curve25519KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }

            case .P521KeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .P521KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }

            case .P384KeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .P384KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }

            case .P256KeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .P256KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .P256KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }
            #endif

            default:
                throw KeysError.keyTypeDoesNotSupportKeyAgreement(self.type)
        }
    }

    public func signature<D>(for dataToSign: D) throws -> Signature where D : DataProtocol
    {
        switch self
        {
            case .P521Signing(let privateKey):
                return Signature.P521(try privateKey.signature(for: dataToSign))

            case .P384Signing(let privateKey):
                return Signature.P384(try privateKey.signature(for: dataToSign))

            case .P256Signing(let privateKey):
                return Signature.P256(try privateKey.signature(for: dataToSign))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveSigning(let privateKey):
                return Signature.P256(try privateKey.signature(for: dataToSign))
            #endif

            default:
                throw KeysError.keyTypeDoesNotSupportSigning(self.type)
        }
    }

    public func signature<D>(for digest: D) throws -> Signature where D : Crypto.Digest
    {
        switch self
        {
            case .P521Signing(let privateKey):
                return Signature.P521(try privateKey.signature(for: digest))

            case .P384Signing(let privateKey):
                return Signature.P384(try privateKey.signature(for: digest))

            case .P256Signing(let privateKey):
                return Signature.P256(try privateKey.signature(for: digest))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveSigning(let privateKey):
                return Signature.P256(try privateKey.signature(for: digest))
            #endif

            default:
                throw KeysError.keyTypeDoesNotSupportSigning(self.type)
        }
    }

    public func signature(for digest: Digest) throws -> Signature
    {
        let data: Data
        switch digest
        {
            case .SHA256(let hashData):
                data = hashData
            case .SHA384(let hashData):
                data = hashData
            case .SHA512(let hashData):
                data = hashData
        }

        switch self
        {
            case .P521Signing(let privateKey):
                return Signature.P521(try privateKey.signature(for: data))

            case .P384Signing(let privateKey):
                return Signature.P384(try privateKey.signature(for: data))

            case .P256Signing(let privateKey):
                return Signature.P256(try privateKey.signature(for: data))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveSigning(let privateKey):
                return Signature.P256(try privateKey.signature(for: data))
            #endif

            default:
                throw KeysError.keyTypeDoesNotSupportSigning(self.type)
        }
    }
}

extension PrivateKey: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let typedData = try container.decode(Data.self)

        try self.init(typedData: typedData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        try container.encode(self.typedData)
    }
}

extension PrivateKey
{
    public var string: String?
    {
        do
        {
            let encoder = JSONEncoder()
            let resultData = try encoder.encode(self)
            return resultData.string.replacingOccurrences(of: "\"", with: "")
        }
        catch
        {
            return nil
        }
    }

    public init(string: String) throws
    {
        let inputString = "\"\(string)\""
        let inputData = inputString.data
        let decoder = JSONDecoder()
        self = try decoder.decode(Self.self, from: inputData)
    }
}

extension PrivateKey: Equatable
{
    public static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool
    {
        guard let ldata = lhs.typedData else
        {
            return false
        }

        guard let rdata = rhs.typedData else
        {
            return false
        }

        return ldata == rdata
    }
}

public enum PublicKey
{
    case Curve25519KeyAgreement(Curve25519.KeyAgreement.PublicKey)
    case P521KeyAgreement(P521.KeyAgreement.PublicKey)
    case P384KeyAgreement(P384.KeyAgreement.PublicKey)
    case P256KeyAgreement(P256.KeyAgreement.PublicKey)

    case Curve25519Signing(Curve25519.Signing.PublicKey)
    case P521Signing(P521.Signing.PublicKey)
    case P384Signing(P384.Signing.PublicKey)
    case P256Signing(P256.Signing.PublicKey)
}

extension PublicKey
{
    public init(typedData: Data) throws
    {
        guard typedData.count > 1 else
        {
            throw KeysError.badKeyTypeData(#file, #line, typedData.hex, typedData.count)
        }

        let typeData = typedData[0..<1]
        let valueData = typedData[1...]

        guard let type = KeyType(typeData) else
        {
            throw KeysError.badKeyTypeData(#file, #line, typedData.hex, typedData.count)
        }

        try self.init(type: type, data: valueData)
    }

    public init(type: KeyType, data: Data) throws
    {
        switch type
        {
            case .Curve25519KeyAgreement:
                self = .Curve25519KeyAgreement(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data))
            case .P521KeyAgreement:
                self = .P521KeyAgreement(try P521.KeyAgreement.PublicKey(compactRepresentation: data))
            case .P384KeyAgreement:
                self = .P384KeyAgreement(try P384.KeyAgreement.PublicKey(compactRepresentation: data))
            case .P256KeyAgreement:
                self = .P256KeyAgreement(try P256.KeyAgreement.PublicKey(compactRepresentation: data))

            case .Curve25519Signing:
                self = .Curve25519KeyAgreement(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data))
            case .P521Signing:
                self = .P521Signing(try P521.Signing.PublicKey(compactRepresentation: data))
            case .P384Signing:
                self = .P384Signing(try P384.Signing.PublicKey(compactRepresentation: data))
            case .P256Signing:
                self = .P256Signing(try P256.Signing.PublicKey(compactRepresentation: data))

            #if os(macOS) || os(iOS)
            case .P256SecureEnclaveKeyAgreement:
                throw KeysError.cannotStorePublicKeysInSecureEnclave
            case .P256SecureEnclaveSigning:
                throw KeysError.cannotStorePublicKeysInSecureEnclave
            #endif
        }
    }

    public var type: KeyType
    {
        switch self
        {
            case .Curve25519KeyAgreement:
                return .Curve25519KeyAgreement
            case .P521KeyAgreement:
                return .P521KeyAgreement
            case .P384KeyAgreement:
                return .P384KeyAgreement
            case .P256KeyAgreement:
                return .P256KeyAgreement

            case .Curve25519Signing:
                return .Curve25519Signing
            case .P521Signing:
                return .P521Signing
            case .P384Signing:
                return .P384Signing
            case .P256Signing:
                return .P256Signing
        }
    }

    public var data: Data?
    {
        switch self
        {
            case .Curve25519KeyAgreement(let key):
                return key.rawRepresentation
            case .P521KeyAgreement(let key):
                return key.compactRepresentation
            case .P384KeyAgreement(let key):
                return key.compactRepresentation
            case .P256KeyAgreement(let key):
                return key.compactRepresentation

            case .Curve25519Signing(let key):
                return key.rawRepresentation
            case .P521Signing(let key):
                return key.compactRepresentation
            case .P384Signing(let key):
                return key.compactRepresentation
            case .P256Signing(let key):
                return key.compactRepresentation
        }
    }

    public var typedData: Data?
    {
        let typeData = self.type.data
        guard let valueData = self.data else
        {
            return nil
        }

        return typeData + valueData
    }

    public func isValidSignature<D>(_ signature: Signature, for dataToVerify: D) -> Bool where D : DataProtocol
    {
        switch self
        {
            case .P521Signing(let publicKey):
                switch signature
                {
                    case .P521(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: dataToVerify)

                    default:
                        return false
                }

            case .P384Signing(let publicKey):
                switch signature
                {
                    case .P384(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: dataToVerify)

                    default:
                        return false
                }

            case .P256Signing(let publicKey):
                switch signature
                {
                    case .P256(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: dataToVerify)

                    default:
                        return false
                }

            default:
                return false
        }
    }

    public func isValidSignature<D>(_ signature: Signature, for digest: D) -> Bool where D : Crypto.Digest
    {
        switch self
        {
            case .P521Signing(let publicKey):
                switch signature
                {
                    case .P521(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: digest)

                    default:
                        return false
                }

            case .P384Signing(let publicKey):
                switch signature
                {
                    case .P384(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: digest)

                    default:
                        return false
                }

            case .P256Signing(let publicKey):
                switch signature
                {
                    case .P256(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: digest)

                    default:
                        return false
                }

            default:
                return false
        }
    }

    public func isValidSignature(_ signature: Signature, for digest: Digest) -> Bool
    {
        let data: Data
        switch digest
        {
            case .SHA256(let hashData):
                data = hashData
            case .SHA384(let hashData):
                data = hashData
            case .SHA512(let hashData):
                data = hashData
        }

        switch self
        {
            case .P521Signing(let publicKey):
                switch signature
                {
                    case .P521(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: data)

                    default:
                        return false
                }

            case .P384Signing(let publicKey):
                switch signature
                {
                    case .P384(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: data)

                    default:
                        return false
                }

            case .P256Signing(let publicKey):
                switch signature
                {
                    case .P256(let ecdsa):
                        return publicKey.isValidSignature(ecdsa, for: data)

                    default:
                        return false
                }

            default:
                return false
        }
    }

}

extension PublicKey: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let typedData = try container.decode(Data.self)

        try self.init(typedData: typedData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        try container.encode(self.typedData)
    }
}

extension PublicKey
{
    public var string: String?
    {
        do
        {
            let encoder = JSONEncoder()
            let resultData = try encoder.encode(self)
            return resultData.string.replacingOccurrences(of: "\"", with: "")
        }
        catch
        {
            return nil
        }
    }

    public init(string: String) throws
    {
        let inputString = "\"\(string)\""
        let inputData = inputString.data
        let decoder = JSONDecoder()
        self = try decoder.decode(Self.self, from: inputData)
    }
}

extension PublicKey: Equatable
{
    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool
    {
        guard let ldata = lhs.typedData else
        {
            return false
        }

        guard let rdata = rhs.typedData else
        {
            return false
        }

        return ldata == rdata
    }
}

extension PublicKey: Hashable
{
    public func hash(into hasher: inout Hasher)
    {
        guard let data = self.typedData else
        {
            return
        }

        hasher.combine(data)
    }
}

public enum KeysError: Error
{
    case noX963
    case cannotStorePublicKeysInSecureEnclave
    case keyTypeMismatch(KeyType, KeyType)
    case keyTypeDoesNotSupportKeyAgreement(KeyType)
    case keyTypeDoesNotSupportSigning(KeyType)
    case badTypeData
    case badKeyTypeData(String, Int, String, Int)
}
