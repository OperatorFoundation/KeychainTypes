//
//  Digests.swift
//  
//
//  Created by Dr. Brandon Wiley on 9/18/22.
//

import Crypto
import Foundation

public enum DigestType: UInt8, Codable
{
    case SHA256 = 2
    case SHA384 = 3
    case SHA512 = 5
}

public extension DigestType
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

public enum Digest: Codable, Equatable
{
    case SHA256(Data)
    case SHA384(Data)
    case SHA512(Data)
}

public extension Digest
{
    var type: DigestType
    {
        switch self
        {
            case .SHA256:
                return .SHA256
            case .SHA384:
                return .SHA384
            case .SHA512:
                return .SHA512
        }
    }

    var digestData: Data
    {
        switch self
        {
            case .SHA256(let digest):
                return digest.data
            case .SHA384(let digest):
                return digest.data
            case .SHA512(let digest):
                return digest.data
        }
    }

    var typedData: Data
    {
        let typeData = self.type.data
        let valueData = self.digestData

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

        guard let type = DigestType(typeData) else
        {
            throw KeysError.badTypeData
        }

        try self.init(type: type, digestData: valueData)
    }

    init(type: DigestType, digestData: Data) throws
    {
        switch type
        {
            case .SHA256:
                self = .SHA256(digestData)
            case .SHA384:
                self = .SHA384(digestData)
            case .SHA512:
                self = .SHA512(digestData)
        }
    }

    init(type: DigestType, dataToHash: Data)
    {
        switch type
        {
            case .SHA256:
                self = .SHA256(Crypto.SHA256.hash(data: dataToHash).data)
            case .SHA384:
                self = .SHA384(Crypto.SHA256.hash(data: dataToHash).data)
            case .SHA512:
                self = .SHA512(Crypto.SHA256.hash(data: dataToHash).data)
        }
    }
}

public extension SHA256Digest
{
    var data: Data
    {
        return Data(self)
    }
}

public extension SHA384Digest
{
    var data: Data
    {
        return Data(self)
    }
}

public extension SHA512Digest
{
    var data: Data
    {
        return Data(self)
    }
}
