# AsymmetricCryptoManager
AsymmetricCryptoManager is a Swift implementation of an asymmetric cryptography manager to facilitate the use of asymmetric cryptographic operations in Swift. Included is a sample view controller for testing purposes.

![](http://digitalleaves.com/blog/wp-content/uploads/2015/10/ezgif.com-optimize.gif)

## Usage

AsymmetricCryptoManager follows the Singleton pattern, thus it must be accessed by means of the sharedInstance variable.

### Generating a key pair

```swift
AsymmetricCryptoManager.sharedInstance.createSecureKeyPair({ (success, error) -> Void in
  if success {
    // start using the key pair.
  } else { 
    // handle the error
  }
})
```

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

## LICENSE

The MIT License (MIT)
Copyright (c) 2015 Ignacio Nieto Carvajal (http://digitalleaves.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
