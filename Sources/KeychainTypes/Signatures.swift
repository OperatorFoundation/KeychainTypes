//
//  Signatures.swift
//  
//
//  Created by Dr. Brandon Wiley on 9/18/22.
//

import Crypto
import Foundation

public enum SignatureType: UInt8, Codable
{
    case P256 = 2
    case P384 = 3
    case P521 = 5
}

public extension SignatureType
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

public enum Signature
{
    case P256(P256.Signing.ECDSASignature)
    case P384(P384.Signing.ECDSASignature)
    case P521(P521.Signing.ECDSASignature)
}

public extension Signature
{
    var type: SignatureType
    {
        switch self
        {
            case .P256:
                return .P256
            case .P384:
                return .P384
            case .P521:
                return .P521
        }
    }

    var data: Data
    {
        switch self
        {
            case .P521(let signature):
                return signature.rawRepresentation
            case .P384(let signature):
                return signature.rawRepresentation
            case .P256(let signature):
                return signature.rawRepresentation
        }
    }

    var typedData: Data?
    {
        let typeData = self.type.data
        let valueData = self.data

        return typeData + valueData
    }

    init(typedData: Data) throws
    {
        guard typedData.count > 1 else
        {
            throw KeysError.badTypeData
        }

        let typeData = typedData[0..<1]
        let valueData = typedData[1...]

        guard let type = SignatureType(typeData) else
        {
            throw KeysError.badTypeData
        }

        try self.init(type: type, data: valueData)
    }

    init(type: SignatureType, data: Data) throws
    {
        switch type
        {
            case .P256:
                let signature = try Crypto.P256.Signing.ECDSASignature(rawRepresentation: data)
                self = .P256(signature)
            case .P384:
                let signature = try Crypto.P384.Signing.ECDSASignature(rawRepresentation: data)
                self = .P384(signature)
            case .P521:
                let signature = try Crypto.P521.Signing.ECDSASignature(rawRepresentation: data)
                self = .P521(signature)
        }
    }
}

extension Signature: Codable
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

extension Signature: Equatable
{
    public static func == (lhs: Signature, rhs: Signature) -> Bool
    {
        switch lhs
        {
            case .P256(let ls):
                switch rhs
                {
                    case .P256(let rs):
                        return ls.rawRepresentation == rs.rawRepresentation

                    default:
                        return false
                }

            case .P384(let ls):
                switch rhs
                {
                    case .P384(let rs):
                        return ls.rawRepresentation == rs.rawRepresentation

                    default:
                        return false
                }

            case .P521(let ls):
                switch rhs
                {
                    case .P521(let rs):
                        return ls.rawRepresentation == rs.rawRepresentation

                    default:
                        return false
                }
        }
    }
}
