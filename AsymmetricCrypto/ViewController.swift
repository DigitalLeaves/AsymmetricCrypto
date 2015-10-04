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
                keyPairButton.setTitle("Delete keypair", forState: .Normal)
            } else {
                keyPairLabel.text = "No key pair present"
                keyPairButton.setTitle("Generate keypair", forState: .Normal)
            }
            signButton.enabled = keyPairExists
            cypherButton.enabled = keyPairExists
            verifySignatureButton.enabled = keyPairExists
            decypherButton.enabled = keyPairExists
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
    
    override func viewWillAppear(animated: Bool) {
        super.viewWillAppear(animated)
        self.keyPairExists = AsymmetricCryptoManager.sharedInstance.keyPairExists()
    }

    // MARK: - button actions
    @IBAction func generateKeyPair(sender: AnyObject) {
        self.view.userInteractionEnabled = false
        if keyPairExists { // delete current key pair
            AsymmetricCryptoManager.sharedInstance.deleteSecureKeyPair({ (success) -> Void in
                if success {
                    self.showAlertWithFadingOutMessage("Keypair successfully deleted")
                    self.keyPairExists = false
                } else { self.showAlertWithFadingOutMessage("Error deleting keypair.") }
                self.view.userInteractionEnabled = true
            })
        } else { // generate keypair
            AsymmetricCryptoManager.sharedInstance.createSecureKeyPair({ (success, error) -> Void in
                if success {
                    self.showAlertWithFadingOutMessage("RSA-2048 keypair successfully generated.")
                    self.keyPairExists = true
                } else { self.showAlertWithFadingOutMessage("An error happened while generating a keypair: \(error)") }
                self.view.userInteractionEnabled = true
            })
        }
    }
    
    @IBAction func cypherText(sender: AnyObject) {
        // safety check.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a clear text in the upper textfield.")
            return
        }
        self.view.userInteractionEnabled = false
        self.cypheredTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.encryptMessageWithPublicKey(clearTextTextfield.text!) { (success, data, error) -> Void in
            if success {
                let b64encoded = data!.base64EncodedStringWithOptions([])
                self.cypheredTextTextfield.text = b64encoded
                self.clearTextTextfield.text = ""
            } else {
                self.showAlertWithFadingOutMessage("Error cyphering data: \(error)")
            }
            self.view.userInteractionEnabled = true
        }
    }
    
    @IBAction func signText(sender: AnyObject) {
        // safety check.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert the text to be signed in the upper textfield.")
            return
        }
        self.view.userInteractionEnabled = false
        self.cypheredTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.signMessageWithPrivateKey(clearTextTextfield.text!) { (success, data, error) -> Void in
            if success {
                let b64encoded = data!.base64EncodedStringWithOptions([])
                self.cypheredTextTextfield.text = b64encoded
            } else {
                self.showAlertWithFadingOutMessage("Error signing message: \(error)")
            }
            self.view.userInteractionEnabled = true
        }
    }
    
    @IBAction func decypherText(sender: AnyObject) {
        // safety check.
        if cypheredTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a cyphered, base64 encoded text in the lower textfield.")
            return
        }
        guard let encryptedData = NSData(base64EncodedString: cypheredTextTextfield.text!, options: []) else {
            self.showAlertWithFadingOutMessage("Unable to base64 decode the input string.")
            return
        }
        self.view.userInteractionEnabled = false
        self.clearTextTextfield.text = ""
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.decryptMessageWithPrivateKey(encryptedData) { (success, result, error) -> Void in
            if success {
                self.clearTextTextfield.text = result!
                self.cypheredTextTextfield.text = ""
            } else {
                self.showAlertWithFadingOutMessage("Error decoding base64 string: \(error)")
            }
            self.view.userInteractionEnabled = true
        }
    }
    
    @IBAction func verifySignature(sender: AnyObject) {
        // safety checks.
        if clearTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert a the text that was signed in the upper textfield.")
            return
        }
        if cypheredTextTextfield.text!.isEmpty {
            self.showAlertWithFadingOutMessage("Please, insert the generated signature in the lower textfield.")
            return
        }
        
        guard let rawData = clearTextTextfield.text?.dataUsingEncoding(NSUTF8StringEncoding), let signatureData = NSData(base64EncodedString: cypheredTextTextfield.text!, options: []) else {
            self.showAlertWithFadingOutMessage("Unable to decode or identify input data. Probably one of the input fields is corrupted.")
            return
        }
        self.view.userInteractionEnabled = false
        self.view.endEditing(true)
        AsymmetricCryptoManager.sharedInstance.verifySignaturePublicKey(rawData, signatureData: signatureData) { (success, error) -> Void in
            self.showAlertWithFadingOutMessage(success ? "Signature verification was successful." : "Error: the signature is not valid for the input text")
            self.view.userInteractionEnabled = true
        }
    }
}

