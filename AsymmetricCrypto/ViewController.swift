//
//  ViewController.swift
//  AsymmetricCrypto
//
//  Created by Ignacio Nieto Carvajal on 4/10/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    // MARK: - outlets && buttons
    @IBOutlet weak var keyPairLabel: UILabel!
    @IBOutlet weak var keyPairButton: UIButton!
    
    @IBOutlet weak var clearTextTextfield: UITextField!
    @IBOutlet weak var cypherButton: UIButton!
    @IBOutlet weak var signButton: UIButton!
    @IBOutlet weak var cypheredTextTextfield: UITextField!
    @IBOutlet weak var decypherButton: UIButton!
    @IBOutlet weak var verifySignatureButton: UIButton!
    
    // data
    var keyPairExists = AsymmetricCryptoManager.sharedInstance.keyPairExists() {
        didSet {
            if keyPairExists {
                keyPairLabel.text = "A valid keypair is present"
                keyPairButton.setTitle("Delete keypair", for: UIControlState())
            } else {
                keyPairLabel.text = "No key pair present"
                keyPairButton.setTitle("Generate keypair", for: UIControlState())
            }
            signButton.isEnabled = keyPairExists
            cypherButton.isEnabled = keyPairExists
            verifySignatureButton.isEnabled = keyPairExists
            decypherButton.isEnabled = keyPairExists
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        self.keyPairExists = AsymmetricCryptoManager.sharedInstance.keyPairExists()
    }

    // MARK: - button actions
    @IBAction func generateKeyPair(_ sender: AnyObject) {
        self.view.isUserInteractionEnabled = false
        if keyPairExists { // delete current key pair
            AsymmetricCryptoManager.sharedInstance.deleteSecureKeyPair({ (success) -> Void in
                if success {
                    self.showAlertWithFadingOutMessage("Keypair successfully deleted")
                    self.keyPairExists = false
                } else { self.showAlertWithFadingOutMessage("Error deleting keypair.") }
                self.view.isUserInteractionEnabled = true
            })
        } else { // generate keypair
            AsymmetricCryptoManager.sharedInstance.createSecureKeyPair({ (success, error) -> Void in
                if success {
                    self.showAlertWithFadingOutMessage("RSA-2048 keypair successfully generated.")
                    self.keyPairExists = true
                } else { self.showAlertWithFadingOutMessage("An error happened while generating a keypair: \(error)") }
                self.view.isUserInteractionEnabled = true
            })
        }
    }
    
    @IBAction func cypherText(_ sender: AnyObject) {
        // safety check.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a clear text in the upper textfield.")
            return
        }
        self.view.isUserInteractionEnabled = false
        self.cypheredTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.encryptMessageWithPublicKey(clearTextTextfield.text!) { (success, data, error) -> Void in
            if success {
                let b64encoded = data!.base64EncodedString(options: [])
                self.cypheredTextTextfield.text = b64encoded
                self.clearTextTextfield.text = ""
            } else {
                self.showAlertWithFadingOutMessage("Error cyphering data: \(error)")
            }
            self.view.isUserInteractionEnabled = true
        }
    }
    
    @IBAction func signText(_ sender: AnyObject) {
        // safety check.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert the text to be signed in the upper textfield.")
            return
        }
        self.view.isUserInteractionEnabled = false
        self.cypheredTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.signMessageWithPrivateKey(clearTextTextfield.text!) { (success, data, error) -> Void in
            if success {
                let b64encoded = data!.base64EncodedString(options: [])
                self.cypheredTextTextfield.text = b64encoded
            } else {
                self.showAlertWithFadingOutMessage("Error signing message: \(error)")
            }
            self.view.isUserInteractionEnabled = true
        }
    }
    
    @IBAction func decypherText(_ sender: AnyObject) {
        // safety check.
        if cypheredTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a cyphered, base64 encoded text in the lower textfield.")
            return
        }
        guard let encryptedData = Data(base64Encoded: cypheredTextTextfield.text!, options: []) else {
            self.showAlertWithFadingOutMessage("Unable to base64 decode the input string.")
            return
        }
        self.view.isUserInteractionEnabled = false
        self.clearTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.decryptMessageWithPrivateKey(encryptedData) { (success, result, error) -> Void in
            if success {
                self.clearTextTextfield.text = result!
                self.cypheredTextTextfield.text = ""
            } else {
                self.showAlertWithFadingOutMessage("Error decoding base64 string: \(error)")
            }
            self.view.isUserInteractionEnabled = true
        }
    }
    
    @IBAction func verifySignature(_ sender: AnyObject) {
        // safety checks.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a the text that was signed in the upper textfield.")
            return
        }
        if cypheredTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert the generated signature in the lower textfield.")
            return
        }
        
        guard let rawData = clearTextTextfield.text?.data(using: String.Encoding.utf8), let signatureData = Data(base64Encoded: cypheredTextTextfield.text!, options: []) else {
            self.showAlertWithFadingOutMessage("Unable to decode or identify input data. Probably one of the input fields is corrupted.")
            return
        }
        self.view.isUserInteractionEnabled = false
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.verifySignaturePublicKey(rawData, signatureData: signatureData) { (success, error) -> Void in
            self.showAlertWithFadingOutMessage(success ? "Signature verification was successful." : "Error: the signature is not valid for the input text")
            self.view.isUserInteractionEnabled = true
        }
    }
}

