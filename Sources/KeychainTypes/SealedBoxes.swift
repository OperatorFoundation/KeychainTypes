//
//  SealedBox.swift
//  
//
//  Created by Dr. Brandon Wiley on 11/29/22.
//

import Crypto
import Foundation

public enum SealedBoxType: UInt8, Codable
{
    case AESGCM = 2
    case ChaChaPoly = 3
}

public extension SealedBoxType
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

public enum SealedBox
{
    case AESGCM(AES.GCM.SealedBox)
    case ChaChaPoly(ChaChaPoly.SealedBox)
}

extension SealedBox: Equatable
{
    public static func == (lhs: SealedBox, rhs: SealedBox) -> Bool
    {
        switch lhs
        {
            case .AESGCM(let left):
                switch rhs
                {
                    case .AESGCM(let right):
                        return left == right

                    default:
                        return false
                }

            case .ChaChaPoly(let left):
                switch rhs
                {
                    case .ChaChaPoly(let right):
                        return left == right

                    default:
                        return false
                }
        }
    }
}

extension SealedBox: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let sealedBoxData = try container.decode(Data.self)
        try self.init(typedData: sealedBoxData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        let sealedBoxData = self.typedData
        try container.encode(sealedBoxData)
    }
}

public extension SealedBox
{
    var type: SealedBoxType
    {
        switch self
        {
            case .AESGCM:
                return .AESGCM
            case .ChaChaPoly:
                return .ChaChaPoly
        }
    }

    var sealedBoxData: Data?
    {
        switch self
        {
            case .AESGCM(let box):
                return box.data
            case .ChaChaPoly(let box):
                return box.data
        }
    }

    var typedData: Data?
    {
        let typeData = self.type.data
        guard let valueData = self.sealedBoxData else
        {
            return nil
        }

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

        guard let type = SealedBoxType(typeData) else
        {
            throw KeysError.badTypeData
        }

        try self.init(type: type, sealedBoxData: valueData)
    }

    init(type: SealedBoxType, sealedBoxData: Data) throws
    {
        switch type
        {
            case .AESGCM:
                self = .AESGCM(try Crypto.AES.GCM.SealedBox(combined: sealedBoxData))
            case .ChaChaPoly:
                self = .ChaChaPoly(try Crypto.ChaChaPoly.SealedBox(combined: sealedBoxData))
        }
    }

    init(type: SealedBoxType, nonce: Nonce, key: SymmetricKey, dataToSeal: Data) throws
    {
        switch type
        {
            case .AESGCM:
                switch nonce
                {
                    case .AESGCM(let nonce):
                        let sealed = try AES.GCM.seal(dataToSeal, using: key, nonce: nonce)
                        self = .AESGCM(sealed)

                    default:
                        throw SealedBoxError.nonceTypeMismatch
                }
            case .ChaChaPoly:
                switch nonce
                {
                    case .ChaChaPoly(let nonce):
                        let sealed = try Crypto.ChaChaPoly.seal(dataToSeal, using: key, nonce: nonce)
                        self = .ChaChaPoly(sealed)

                    default:
                        throw SealedBoxError.nonceTypeMismatch
                }
        }
    }
}

extension AES.GCM.SealedBox: Equatable
{
    public static func == (lhs: AES.GCM.SealedBox, rhs: AES.GCM.SealedBox) -> Bool
    {
        return lhs.data == rhs.data
    }
}

extension ChaChaPoly.SealedBox: Equatable
{
    public static func == (lhs: ChaChaPoly.SealedBox, rhs: ChaChaPoly.SealedBox) -> Bool
    {
        return lhs.data == rhs.data
    }
}

public extension AES.GCM.SealedBox
{
    var data: Data?
    {
        return self.combined
    }
}

public extension ChaChaPoly.SealedBox
{
    var data: Data?
    {
        return self.combined
    }
}

public enum SealedBoxError: Error
{
    case nonceTypeMismatch
}
