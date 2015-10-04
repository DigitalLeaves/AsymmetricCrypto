//
//  UIViewController+Alerts.swift
//
//  Created by Ignacio Nieto Carvajal on 13/7/15.
//  Copyright (c) 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

var asymmetricCryptoAlert: UIAlertController?

extension UIViewController {
    func showAlertWithMessage(msg: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: nil, message: msg, preferredStyle: .Alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .Default, handler: nil))
        asymmetricCryptoAlert = alert
        self.presentViewController(alert, animated: true, completion: completion)
    }
    
    func showAlertWithFadingOutMessage(msg: String, completion: (() -> Void)? = nil) {
        asymmetricCryptoAlert = UIAlertController(title: nil, message: msg, preferredStyle: .Alert)
        self.presentViewController(asymmetricCryptoAlert!, animated: true, completion: completion)
        NSTimer.scheduledTimerWithTimeInterval(3.0, target: self, selector: "dismissLoadingMessageAlert", userInfo: nil, repeats: false)
    }
    
    func showLoadingAlertMessage(completion: (() -> Void)?) {
        let finalMessage = "Loading...\n\n\n"
        asymmetricCryptoAlert = UIAlertController(title: finalMessage, message: nil, preferredStyle: .Alert)
        let activityIndicator = UIActivityIndicatorView(activityIndicatorStyle: .WhiteLarge)
        activityIndicator.color = UIColor.blackColor()
        activityIndicator.center = CGPointMake(130.5, 85.5)
        asymmetricCryptoAlert!.view.addSubview(activityIndicator)
        activityIndicator.startAnimating()
        
        self.presentViewController(asymmetricCryptoAlert!, animated: true) { () -> Void in
            if completion != nil {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, Int64(0.0 * Double(NSEC_PER_SEC))), dispatch_get_main_queue(), { () -> Void in
                    completion!()
                })
            }
        }
    }
    
    func dismissLoadingMessageAlert() {
        self.dismissMessageAlert(nil)
    }
    
    func dismissMessageAlert(completion: (() -> Void)? = nil) {
        self.dismissViewControllerAnimated(true, completion: { () -> Void in
            completion?()
            asymmetricCryptoAlert = nil
        })
    }
}