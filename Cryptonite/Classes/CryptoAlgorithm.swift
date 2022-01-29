//
//  CryptoAlgorithm.swift
//  Cryptonite
//
//  Created by Alexius on 2022/1/29.
//

import Foundation
import CommonCrypto

public enum Algorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    var algorithm: CCHmacAlgorithm {
        var alg: Int = 0
        switch self {
        case .MD5:    alg = kCCHmacAlgMD5
        case .SHA1:   alg = kCCHmacAlgSHA1
        case .SHA224: alg = kCCHmacAlgSHA224
        case .SHA256: alg = kCCHmacAlgSHA256
        case .SHA384: alg = kCCHmacAlgSHA384
        case .SHA512: alg = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(alg)
    }
    
    var length: Int32 {
        switch self {
        case .MD5:    return CC_MD5_DIGEST_LENGTH
        case .SHA1:   return CC_SHA1_DIGEST_LENGTH
        case .SHA224: return CC_SHA224_DIGEST_LENGTH
        case .SHA256: return CC_SHA256_DIGEST_LENGTH
        case .SHA384: return CC_SHA384_DIGEST_LENGTH
        case .SHA512: return CC_SHA512_DIGEST_LENGTH
        }
    }
}

extension Array where Element == UInt8 {
    public var hashString: String {
        return self.reduce(""){$0 + String(format: "%02x", $1)}
    }
    
    public var base64String: String {
        return self.data.base64EncodedString(options: Data.Base64EncodingOptions.lineLength76Characters)
    }
    
    public var data: Data {
        return Data(self)
    }
}

extension String {
    public var bytes: [UInt8] {
        return [UInt8](self.utf8)
    }
    
    public func hmac(with algorithm: Algorithm, key: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: Int(algorithm.length))
        CCHmac(algorithm.algorithm, key, key.count, bytes, bytes.count, &result)
        return result
    }
    
    public func hashString(by algorithm: Algorithm) -> String {
        return hash(by: algorithm).hashString
    }
    
    public func hash(by algorithm: Algorithm) -> [UInt8] {
         var hash = [UInt8](repeating: 0, count: Int(algorithm.length))
         switch algorithm {
         case .MD5:
             CC_MD5(bytes, CC_LONG(bytes.count), &hash)
         case .SHA1:
             CC_SHA1(bytes, CC_LONG(bytes.count), &hash)
         case .SHA224:
             CC_SHA224(bytes, CC_LONG(bytes.count), &hash)
         case .SHA256:
             CC_SHA256(bytes, CC_LONG(bytes.count), &hash)
         case .SHA384:
             CC_SHA384(bytes, CC_LONG(bytes.count), &hash)
         case .SHA512:
             CC_SHA512(bytes, CC_LONG(bytes.count), &hash)
         }
         return hash
     }
}

extension Data {
    public var bytes: [UInt8] {
        return [UInt8](self)
    }
}
