//
//  AsymmetricCryptoManager.swift
//  AsymmetricCrypto
//
//  Created by Ignacio Nieto Carvajal on 4/10/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

// Singleton instance
private let _singletonInstance = AsymmetricCryptoManager()

// Constants
private let kAsymmetricCryptoManagerApplicationTag = "com.AsymmetricCrypto.keypair"
private let kAsymmetricCryptoManagerKeyType = kSecAttrKeyTypeRSA
private let kAsymmetricCryptoManagerKeySize = 2048
private let kPasswordLessManagerCypheredBufferSize = 1024
private let kAsymmetricCryptoManagerSecPadding: SecPadding = .PKCS1

enum PasswordLessException: ErrorType {
    case UnknownError
    case DuplicateFoundWhileTryingToCreateKey
    case KeyNotFound
    case AuthFailed
    case UnableToAddPublicKeyToKeyChain
    case WrongInputDataFormat
    case UnableToEncrypt
    case UnableToDecrypt
    case UnableToSignData
    case UnableToVerifySignedData
    case UnableToPerformHashOfData
    case UnableToGenerateAccessControlWithGivenSecurity
    case OutOfMemory
}

class AsymmetricCryptoManager: NSObject {

    /** Shared instance */
    class var sharedInstance: AsymmetricCryptoManager {
        return _singletonInstance
    }
    
    // MARK: - Manage keys
    
    func createSecureKeyPair(completion: ((success: Bool, error: PasswordLessException?) -> Void)? = nil) {
        // access control for the private key
        let flags: SecAccessControlCreateFlags = [SecAccessControlCreateFlags.TouchIDAny, SecAccessControlCreateFlags.PrivateKeyUsage]
        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, nil) else {
            completion?(success: false, error: .UnableToGenerateAccessControlWithGivenSecurity)
            return
        }
        
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrAccessControl as String: accessControl,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag
        ]
        
        // private key parameters
        let publicKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag
        ]
        
        // global parameters for our key generation
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String:          kAsymmetricCryptoManagerKeyType,
            kSecAttrKeySizeInBits as String:    kAsymmetricCryptoManagerKeySize,
            kSecPublicKeyAttrs as String:       publicKeyParams,
            kSecPrivateKeyAttrs as String:      privateKeyParams,
        ]
        
        // asynchronously generate the key pair and call the completion block
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            var pubKey, privKey: SecKeyRef?
            let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)
            
            if status == errSecSuccess {
                dispatch_async(dispatch_get_main_queue(), { completion?(success: true, error: nil) })
            } else {
                var error = PasswordLessException.UnknownError
                switch (status) {
                case errSecDuplicateItem: error = .DuplicateFoundWhileTryingToCreateKey
                case errSecItemNotFound: error = .KeyNotFound
                case errSecAuthFailed: error = .AuthFailed
                default: break
                }
                dispatch_async(dispatch_get_main_queue(), { completion?(success: false, error: error) })
            }
        }
    }
    
    private func getPublicKeyData() -> NSData? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
        ]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters, &data)
        if status == errSecSuccess {
            return data as? NSData
        } else { return nil }
    }
    
    private func getPublicKeyReference() -> SecKeyRef? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true,
        ]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters, &ref)
        if status == errSecSuccess { return ref as! SecKeyRef? } else { return nil }
    }
    
    private func getPrivateKeyReference() -> SecKeyRef? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecReturnRef as String: true,
        ]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters, &ref)
        if status == errSecSuccess { return ref as! SecKeyRef? } else { return nil }
    }
    
    func keyPairExists() -> Bool {
        return self.getPublicKeyData() != nil
    }
    
    func deleteSecureKeyPair(completion: ((success: Bool) -> Void)?) {
        // private query dictionary
        let deleteQuery = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
        ]

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            let status = SecItemDelete(deleteQuery) // delete private key
            dispatch_async(dispatch_get_main_queue(), { completion?(success: status == errSecSuccess) })        }
    }
    
    // MARK: - Cypher and decypher methods
    
    func encryptMessageWithPublicKey(message: String, completion: (success: Bool, data: NSData?, error: PasswordLessException?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            
            if let publicKeyRef = self.getPublicKeyReference() {
                // prepare input input plain text
                guard let messageData = message.dataUsingEncoding(NSUTF8StringEncoding) else {
                    completion(success: false, data: nil, error: .WrongInputDataFormat)
                    return
                }
                let plainText = UnsafePointer<UInt8>(messageData.bytes)
                let plainTextLen = messageData.length
                
                // prepare output data buffer
                guard let cipherData = NSMutableData(length: SecKeyGetBlockSize(publicKeyRef)) else {
                    completion(success: false, data: nil, error: .OutOfMemory)
                    return
                }
                let cipherText = UnsafeMutablePointer<UInt8>(cipherData.mutableBytes)
                var cipherTextLen = cipherData.length
                
                let status = SecKeyEncrypt(publicKeyRef, .PKCS1, plainText, plainTextLen, cipherText, &cipherTextLen)
                
                // analyze results and call the completion in main thread
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    completion(success: status == errSecSuccess, data: cipherData, error: status == errSecSuccess ? nil : .UnableToEncrypt)
                    cipherText.destroy()
                })
                return
            } else { dispatch_async(dispatch_get_main_queue(), { completion(success: false, data: nil, error: .KeyNotFound) }) }
        }
    }
    
    func decryptMessageWithPrivateKey(encryptedData: NSData, completion: (success: Bool, result: String?, error: PasswordLessException?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            
            if let privateKeyRef = self.getPrivateKeyReference() {
                // prepare input input plain text
                let encryptedText = UnsafePointer<UInt8>(encryptedData.bytes)
                let encryptedTextLen = encryptedData.length
                
                // prepare output data buffer
                guard let plainData = NSMutableData(length: kPasswordLessManagerCypheredBufferSize) else {
                    completion(success: false, result: nil, error: .OutOfMemory)
                    return
                }
                let plainText = UnsafeMutablePointer<UInt8>(plainData.mutableBytes)
                var plainTextLen = plainData.length
                
                let status = SecKeyDecrypt(privateKeyRef, .PKCS1, encryptedText, encryptedTextLen, plainText, &plainTextLen)

                // analyze results and call the completion in main thread
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    if status == errSecSuccess {
                        // adjust NSData length
                        plainData.length = plainTextLen
                        // Generate and return result string
                        if let string = NSString(data: plainData, encoding: NSUTF8StringEncoding) as? String {
                            completion(success: true, result: string, error: nil)
                        } else { completion(success: false, result: nil, error: .UnableToDecrypt) }
                    } else { completion(success: false, result: nil, error: .UnableToDecrypt) }
                    plainText.destroy()
                })
                return
            } else { dispatch_async(dispatch_get_main_queue(), { completion(success: false, result: nil, error: .KeyNotFound) }) }
        }
    }
    
    // MARK: - Sign and verify signature.
    
    func signMessageWithPrivateKey(message: String, completion: (success: Bool, data: NSData?, error: PasswordLessException?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            var error: PasswordLessException? = nil
            
            if let privateKeyRef = self.getPrivateKeyReference() {
                // result data
                guard let resultData = NSMutableData(length: SecKeyGetBlockSize(privateKeyRef)) else {
                    dispatch_async(dispatch_get_main_queue(), { completion(success: false, data: nil, error: .OutOfMemory) })
                    return
                }
                let resultPointer    = UnsafeMutablePointer<UInt8>(resultData.mutableBytes)
                var resultLength     = resultData.length
                
                if let plainData = message.dataUsingEncoding(NSUTF8StringEncoding) {
                    // generate hash of the plain data to sign
                    guard let hashData = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH)) else {
                        dispatch_async(dispatch_get_main_queue(), { completion(success: false, data: nil, error: .OutOfMemory) })
                        return
                    }
                    let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                    CC_SHA1(UnsafePointer<Void>(plainData.bytes), CC_LONG(plainData.length), hash)
                    
                    // sign the hash
                    let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1SHA1, hash, hashData.length, resultPointer, &resultLength)
                    if status != errSecSuccess { error = .UnableToEncrypt }
                    else { resultData.length = resultLength }
                    hash.destroy()
                } else { error = .WrongInputDataFormat }
                
                // analyze results and call the completion in main thread
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    if error == nil {
                        // adjust NSData length and return result.
                        resultData.length = resultLength
                        completion(success: true, data: resultData, error: nil)
                    } else { completion(success: false, data: nil, error: error) }
                    //resultPointer.destroy()
                })
            } else { dispatch_async(dispatch_get_main_queue(), { completion(success: false, data: nil, error: .KeyNotFound) }) }
        }
    }
    
    func verifySignaturePublicKey(data: NSData, signatureData: NSData, completion: (success: Bool, error: PasswordLessException?) -> Void) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) { () -> Void in
            var error: PasswordLessException? = nil

            if let publicKeyRef = self.getPublicKeyReference() {
                // hash data
                guard let hashData = NSMutableData(length: Int(CC_SHA1_DIGEST_LENGTH)) else {
                    dispatch_async(dispatch_get_main_queue(), { completion(success: false, error: .OutOfMemory) })
                    return
                }
                let hash = UnsafeMutablePointer<UInt8>(hashData.mutableBytes)
                CC_SHA1(UnsafePointer<Void>(data.bytes), CC_LONG(data.length), hash)
                // input and output data
                let signaturePointer = UnsafePointer<UInt8>(signatureData.bytes)
                let signatureLength = signatureData.length
                
                let status = SecKeyRawVerify(publicKeyRef, SecPadding.PKCS1SHA1, hash, Int(CC_SHA1_DIGEST_LENGTH), signaturePointer, signatureLength)
                
                if status != errSecSuccess { error = .UnableToDecrypt }
                
                // analyze results and call the completion in main thread
                hash.destroy()
                dispatch_async(dispatch_get_main_queue(), { () -> Void in
                    completion(success: status == errSecSuccess, error: error)
                })
                return
            } else { dispatch_async(dispatch_get_main_queue(), { completion(success: false, error: .KeyNotFound) }) }
        }
    }
    
    
}




