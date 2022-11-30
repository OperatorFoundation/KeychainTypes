//
//  Nonces.swift
//  
//
//  Created by Dr. Brandon Wiley on 11/29/22.
//

import Crypto
import Foundation

public enum NonceType: UInt8, Codable
{
    case AESGCM = 2
    case ChaChaPoly = 3
}

public extension NonceType
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

public enum Nonce: Codable, Equatable
{
    case AESGCM(AES.GCM.Nonce)
    case ChaChaPoly(ChaChaPoly.Nonce)
}

public extension Nonce
{
    var type: NonceType
    {
        switch self
        {
            case .AESGCM:
                return .AESGCM
            case .ChaChaPoly:
                return .ChaChaPoly
        }
    }

    var nonceData: Data
    {
        switch self
        {
            case .AESGCM(let nonce):
                return nonce.data
            case .ChaChaPoly(let nonce):
                return nonce.data
        }
    }

    var typedData: Data
    {
        let typeData = self.type.data
        let valueData = self.nonceData

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

        guard let type = NonceType(typeData) else
        {
            throw KeysError.badTypeData
        }

        try self.init(type: type, nonceData: valueData)
    }

    init(type: NonceType, nonceData: Data) throws
    {
        switch type
        {
            case .AESGCM:
                let nonce = try AES.GCM.Nonce(data: nonceData)
                self = .AESGCM(nonce)
            case .ChaChaPoly:
                let nonce = try Crypto.ChaChaPoly.Nonce(data: nonceData)
                self = .ChaChaPoly(nonce)
        }
    }
}

public extension AES.GCM.Nonce
{
    var data: Data
    {
        return Data(self)
    }
}

public extension Crypto.ChaChaPoly.Nonce
{
    var data: Data
    {
        return Data(self)
    }
}

extension AES.GCM.Nonce: Equatable
{
    public static func == (lhs: AES.GCM.Nonce, rhs: AES.GCM.Nonce) -> Bool
    {
        return Data(lhs) == Data(rhs)
    }
}

extension Crypto.ChaChaPoly.Nonce: Equatable
{
    public static func == (lhs: ChaChaPoly.Nonce, rhs: ChaChaPoly.Nonce) -> Bool
    {
        return Data(lhs) == Data(rhs)
    }
}

extension AES.GCM.Nonce: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let nonceData = try container.decode(Data.self)
        try self.init(data: nonceData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        let nonceData = Data(self)
        try container.encode(nonceData)
    }
}

extension Crypto.ChaChaPoly.Nonce: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let nonceData = try container.decode(Data.self)
        try self.init(data: nonceData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        let nonceData = Data(self)
        try container.encode(nonceData)
    }
}
