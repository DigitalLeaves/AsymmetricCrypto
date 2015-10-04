# AsymmetricCryptoManager
AsymmetricCryptoManager is a Swift implementation of an asymmetric cryptography manager to facilitate the use of asymmetric cryptographic operations in Swift. Included is a sample view controller for testing purposes.

![](http://digitalleaves.com/blog/wp-content/uploads/2015/10/ezgif.com-optimize.gif)

## Usage

AsymmetricCryptoManager follows the Singleton pattern, thus it must be accessed by means of the sharedInstance variable.

### Encryption: 

```swift
AsymmetricCryptoManager.sharedInstance.encryptMessageWithPublicKey(clearText) { (success, data, error) -> Void in
  if success {
    let b64encoded = data!.base64EncodedStringWithOptions([])
    // transmit b64encoded encrypted string.
  } else { 
    // handle the error ...
  }
}
```

### Decryption:

```swift
AsymmetricCryptoManager.sharedInstance.decryptMessageWithPrivateKey(encryptedData) { (success, result, error) -> Void in
  if success {
    // manage the resulting string.  
  } else {
    // manage the error
  }
```

### Sign a message:

```swift
AsymmetricCryptoManager.sharedInstance.signMessageWithPrivateKey(clearText) { (success, data, error) -> Void in
  if success {
    let b64encoded = data!.base64EncodedStringWithOptions([])
  } else {
    // manage the error
  }
}
```

### Verify the signature:

```swift
AsymmetricCryptoManager.sharedInstance.verifySignaturePublicKey(rawData, signatureData: signatureData) { (success, error) -> Void in
  if success {
    // verification was successful
  } else {
    // verification failed.
  }
}
```
