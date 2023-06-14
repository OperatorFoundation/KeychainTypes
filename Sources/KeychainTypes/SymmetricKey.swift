//
//  SymmetricKeys.swift
//  
//
//  Created by Dr. Brandon Wiley on 11/30/22.
//

import Crypto
import Foundation

import Datable

extension SymmetricKey: Codable
{
    public init(from decoder: Decoder) throws
    {
        let container = try decoder.singleValueContainer()
        let keyData = try container.decode(Data.self)
        self.init(data: keyData)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.singleValueContainer()
        try container.encode(self.data)
    }
}

public extension SymmetricKey
{
    var data: Data
    {
        self.withUnsafeBytes {return Data(bytes: $0.baseAddress!, count: $0.count)}
    }
}
