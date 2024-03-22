//
//  Crypto+CustomStringConvertible.swift
//  
//
//  Created by Dr. Brandon Wiley on 4/19/22.
//

import Crypto
import Foundation

extension AES.GCM.Nonce: CustomStringConvertible
{
    public var description: String
    {
        let data = Data(self)
        return data.base64EncodedString()
    }
}

extension SymmetricKey: CustomStringConvertible
{
    public var description: String
    {
        do
        {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .withoutEscapingSlashes
            let data = try encoder.encode(self)
            return data.string
        }
        catch
        {
            return "{}"
        }
    }
}

extension P256.KeyAgreement.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.base64EncodedString()
    }
}

extension P256.KeyAgreement.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        if let compactRepresentation = self.compactRepresentation
        {
            return compactRepresentation.base64EncodedString()
        }
        else
        {
            return self.rawRepresentation.base64EncodedString()
        }
    }
}

extension P256.Signing.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.base64EncodedString()
    }
}

extension P256.Signing.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        if let compactRepresentation = self.compactRepresentation
        {
            return compactRepresentation.base64EncodedString()
        }
        else
        {
            return self.rawRepresentation.base64EncodedString()
        }
    }
}
