//
//  ViewController.swift
//  recorder
//
//  Created by Dmitri Wamback on 2024-07-31.
//

import UIKit
import LocalAuthentication
import AVFoundation

class ViewController: UIViewController, AVAudioRecorderDelegate, UIDocumentPickerDelegate {
    
    var audioRecording:     AVAudioRecorder?
    var audioFilename:      URL!
    var apiUrlToPost:       String!
    
    var postApiURL:         UITextField!
    var apiText:            UILabel!
    
    let audioRecordingSettings = [
        AVFormatIDKey:              Int(kAudioFormatMPEG4AAC),
        AVSampleRateKey:            12000,
        AVNumberOfChannelsKey:      1,
        AVEncoderAudioQualityKey:   AVAudioQuality.high.rawValue
    ]

    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.view.backgroundColor = UIColor(red: 14.0/255.0, green: 18.0/255.0, blue: 24.0/255.0, alpha: 1.0)
        
        let backgroundImage = UIImage(named: "Logo")
        let imageView = UIImageView(frame: self.view.bounds)
        imageView.image = backgroundImage
        imageView.contentMode = .scaleAspectFill
        imageView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        imageView.alpha = 0.05
        self.view.insertSubview(imageView, at: 0)
        
        
        authenticate()
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//

    func authenticate() {
        
        let context = LAContext()
        var error: NSError?
        
        if (!context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)) { return }
            
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "Log in with Face ID") {
            success, authenticateError in DispatchQueue.main.async {
                if (success) { self.login() }
                else { exit(0) }
            }
        }
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    func login() {
        let screenWidth = self.view.frame.width
        let screenHeight = self.view.frame.height
        
        let buttonWidth = 175
        let offset = 10
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // START RECORDING BUTTON //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        let startButton = UIButton(type: .system)
        startButton.setTitle("START", for: .normal)
        startButton.frame = CGRect(x: Int(screenWidth)/2 - (buttonWidth + offset), 
                                   y: Int(screenHeight) - 100,
                                   width: Int(buttonWidth),
                                   height: 60)
        
        startButton.backgroundColor = UIColor(red: 10.5/255.0, green: 13.5/255.0, blue: 18.0/255.0, alpha: 1.0)
        startButton.titleLabel?.font = UIFont.systemFont(ofSize: 20)
        startButton.titleLabel?.textColor = .white
        startButton.layer.cornerRadius = 10
        startButton.addTarget(self, action: #selector(startRecording), for: .touchUpInside)
        self.view.addSubview(startButton)
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // END RECORDING BUTTON //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        let stopButton = UIButton(type: .system)
        stopButton.setTitle("END", for: .normal)
        stopButton.frame = CGRect(x: Int(screenWidth)/2 + offset,
                                  y: Int(screenHeight) - 100,
                                  width: Int(buttonWidth),
                                  height: 60)
        
        stopButton.backgroundColor = UIColor(red: 10.5/255.0, green: 13.5/255.0, blue: 18.0/255.0, alpha: 1.0)
        stopButton.titleLabel?.font = UIFont.systemFont(ofSize: 20)
        stopButton.titleLabel?.textColor = .white
        stopButton.layer.cornerRadius = 10
        stopButton.addTarget(self, action: #selector(endRecording), for: .touchUpInside)
        self.view.addSubview(stopButton)
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // INPUT API URL //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        let horizontalPadding = 10
        let postAPIWidth = buttonWidth * 2 + offset * 2 - horizontalPadding * 2
        postApiURL = UITextField(frame: CGRect(x: Int(screenWidth)/2 - postAPIWidth/2,
                                               y: 80,
                                               width: Int(postAPIWidth),
                                               height: 60))
        postApiURL.placeholder = "API callback URL"
        postApiURL.backgroundColor = UIColor(red: 10.5/255.0, green: 13.5/255.0, blue: 18.0/255.0, alpha: 1.0)
        postApiURL.textColor = .white
        postApiURL.layer.cornerRadius = 10
        
        let padding = UIView(frame: CGRect(x: 0, y: 0, width: Int(horizontalPadding), height: Int(postApiURL.frame.height)))
        postApiURL.leftView = padding
        postApiURL.leftViewMode = .always
        
        postApiURL.rightView = padding
        postApiURL.rightViewMode = .always
        
        self.view.addSubview(postApiURL)
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // SUBMIT API URL BUTTON //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        let submitApiURL = UIButton(type: .system)
        
        submitApiURL.frame = CGRect(x: Int(screenWidth)/2 - postAPIWidth/2,
                                    y: 160,
                                    width: Int(postAPIWidth),
                                    height: 60)
        submitApiURL.setTitle("SUBMIT URL", for: .normal)
        submitApiURL.backgroundColor = UIColor(red: 10.5/255.0, green: 13.5/255.0, blue: 18.0/255.0, alpha: 1.0)
        submitApiURL.titleLabel?.font = UIFont.systemFont(ofSize: 20)
        submitApiURL.titleLabel?.textColor = .white
        submitApiURL.layer.cornerRadius = 10
        submitApiURL.addTarget(self, action: #selector(submitAPIURL), for: .touchUpInside)
        
        self.view.addSubview(submitApiURL)
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // API URL TEXT //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        apiText = UILabel(frame: CGRect(x: Int(screenWidth)/2 - postAPIWidth/2,
                                        y: 240,
                                        width: Int(postAPIWidth),
                                        height: 30))
        apiText.text = "No API URL"
        apiText.textColor = .white
        
        self.view.addSubview(apiText)
        
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        // GESTURES //
        //-----------------------------------------------------------------------------------------------------------------------------------------//
        
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(leaveKeyboardFocus))
        view.addGestureRecognizer(tapGesture)
    }
    
    
    
    
    
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    @objc func startRecording() {
        let audioSessionInstance = AVAudioSession.sharedInstance()
        
        do {
            try audioSessionInstance.setCategory(.playAndRecord, mode: .default)
            try audioSessionInstance.setActive(true)
            
            let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            audioFilename = directory.appendingPathComponent("recording.m4a")
            
            audioRecording = try AVAudioRecorder(url: audioFilename, settings: audioRecordingSettings)
            audioRecording?.delegate = self
            audioRecording?.record()
        }
        catch {}
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    @objc func endRecording() {
        audioRecording?.stop()
        
        saveRecording()
        audioRecording = nil
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    func saveRecording() {
        let picker = UIDocumentPickerViewController(forExporting: [audioFilename])
        picker.delegate = self
        picker.modalPresentationStyle = .formSheet
        self.present(picker, animated: true, completion: nil)
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    @objc func leaveKeyboardFocus() {
        view.endEditing(true)
    }
    
    //---------------------------------------------------------------------------------------------------------------------------------------------//
    
    @objc func submitAPIURL() {
        apiUrlToPost = postApiURL.text
        apiText.text = apiUrlToPost
        view.endEditing(true)
    }
}

