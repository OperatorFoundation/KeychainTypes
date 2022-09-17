//
//  Keys.swift
//
//
//  Created by Dr. Brandon Wiley on 1/27/22.
//

import Crypto
import Foundation

public enum KeyType
{
    case Curve25519KeyAgreement
    case P521KeyAgreement
    case P384KeyAgreement
    case P256KeyAgreement

    case Curve25519Signing
    case P521Signing
    case P384Signing
    case P256Signing

    case P256SecureEnclaveKeyAgreement
    case P256SecureEnclaveSigning
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

    case P256SecureEnclaveKeyAgreement(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case P256SecureEnclaveSigning(SecureEnclave.P256.Signing.PrivateKey)
}

extension PrivateKey
{
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
                self = .Curve25519KeyAgreement(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data))
            case .P521Signing:
                self = .P521Signing(try P521.Signing.PrivateKey(rawRepresentation: data))
            case .P384Signing:
                self = .P384Signing(try P384.Signing.PrivateKey(rawRepresentation: data))
            case .P256Signing:
                self = .P256Signing(try P256.Signing.PrivateKey(rawRepresentation: data))

            case .P256SecureEnclaveKeyAgreement:
                throw KeysError.cannotMakeSecureEnclaveKeyFromData
            case .P256SecureEnclaveSigning:
                throw KeysError.cannotMakeSecureEnclaveKeyFromData
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

            case .P256SecureEnclaveKeyAgreement:
                return .P256SecureEnclaveKeyAgreement
            case .P256SecureEnclaveSigning:
                return .P256SecureEnclaveSigning
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

            case .P256SecureEnclaveKeyAgreement:
                return nil
            case .P256SecureEnclaveSigning:
                return nil
        }
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

            case .P256SecureEnclaveKeyAgreement:
                return true
            case .P256SecureEnclaveSigning:
                return true
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

            case .P256SecureEnclaveKeyAgreement(let key):
                return PublicKey.P256KeyAgreement(key.publicKey)
            case .P256SecureEnclaveSigning(let key):
                return PublicKey.P256Signing(key.publicKey)
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

            case .P256SecureEnclaveKeyAgreement(let privateKey):
                switch publicKeyShare
                {
                    case .P256KeyAgreement(let publicKey):
                        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

                    default:
                        throw KeysError.keyTypeMismatch(self.type, publicKeyShare.type)
                }
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

            case .P256SecureEnclaveSigning(let privateKey):
                return Signature.P256(try privateKey.signature(for: dataToSign))

            default:
                throw KeysError.keyTypeDoesNotSupportSigning(self.type)
        }
    }

    public func signature<D>(for digest: D) throws -> Signature where D : Digest
    {
        switch self
        {
            case .P521Signing(let privateKey):
                return Signature.P521(try privateKey.signature(for: digest))

            case .P384Signing(let privateKey):
                return Signature.P384(try privateKey.signature(for: digest))

            case .P256Signing(let privateKey):
                return Signature.P256(try privateKey.signature(for: digest))

            case .P256SecureEnclaveSigning(let privateKey):
                return Signature.P256(try privateKey.signature(for: digest))

            default:
                throw KeysError.keyTypeDoesNotSupportSigning(self.type)
        }
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

            case .P256SecureEnclaveKeyAgreement:
                throw KeysError.cannotMakeSecureEnclaveKeyFromData
            case .P256SecureEnclaveSigning:
                throw KeysError.cannotMakeSecureEnclaveKeyFromData
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

    public func isValidSignature<D>(_ signature: Signature, for digest: D) -> Bool where D : Digest
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
}

public enum Signature
{
    case P521(P521.Signing.ECDSASignature)
    case P384(P384.Signing.ECDSASignature)
    case P256(P256.Signing.ECDSASignature)
}

public enum KeysError: Error
{
    case cannotMakeSecureEnclaveKeyFromData
    case keyTypeMismatch(KeyType, KeyType)
    case keyTypeDoesNotSupportKeyAgreement(KeyType)
    case keyTypeDoesNotSupportSigning(KeyType)
}
