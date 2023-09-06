//
//  SharedSecret+DataAndSymmetricKey.swift
//  
//
//  Created by Dr. Brandon Wiley on 8/22/23.
//

import Crypto
import Foundation

extension SharedSecret
{
    var data: Data
    {
        self.withUnsafeBytes {return Data(bytes: $0.baseAddress!, count: $0.count)}
    }
}

extension SharedSecret
{
    public func symmetricKey() -> SymmetricKey
    {
        return SymmetricKey(data: self.data)
    }
}
