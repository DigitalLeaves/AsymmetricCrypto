//
//  UIViewController+Alerts.swift
//
//  Created by Ignacio Nieto Carvajal on 13/7/15.
//  Copyright (c) 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

var asymmetricCryptoAlert: UIAlertController?

extension UIViewController {
    func showAlertWithMessage(_ msg: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: nil, message: msg, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .default, handler: nil))
        asymmetricCryptoAlert = alert
        self.present(alert, animated: true, completion: completion)
    }
    
    func showAlertWithFadingOutMessage(_ msg: String, completion: (() -> Void)? = nil) {
        asymmetricCryptoAlert = UIAlertController(title: nil, message: msg, preferredStyle: .alert)
        self.present(asymmetricCryptoAlert!, animated: true, completion: completion)
        Timer.scheduledTimer(timeInterval: 3.0, target: self, selector: #selector(UIViewController.dismissLoadingMessageAlert), userInfo: nil, repeats: false)
    }
    
    func showLoadingAlertMessage(_ completion: (() -> Void)?) {
        let finalMessage = "Loading...\n\n\n"
        asymmetricCryptoAlert = UIAlertController(title: finalMessage, message: nil, preferredStyle: .alert)
        let activityIndicator = UIActivityIndicatorView(activityIndicatorStyle: .whiteLarge)
        activityIndicator.color = UIColor.black
        activityIndicator.center = CGPoint(x: 130.5, y: 85.5)
        asymmetricCryptoAlert!.view.addSubview(activityIndicator)
        activityIndicator.startAnimating()
        
        self.present(asymmetricCryptoAlert!, animated: true) { () -> Void in
            if completion != nil {
                DispatchQueue.main.asyncAfter(deadline: DispatchTime.now() + Double(Int64(0.0 * Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC), execute: { () -> Void in
                    completion!()
                })
            }
        }
    }
    
    func dismissLoadingMessageAlert() {
        self.dismissMessageAlert(nil)
    }
    
    func dismissMessageAlert(_ completion: (() -> Void)? = nil) {
        self.dismiss(animated: true, completion: { () -> Void in
            asymmetricCryptoAlert = nil
            completion?()
        })
    }
}
