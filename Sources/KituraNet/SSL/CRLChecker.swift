//
//  OCSPChecker.swift
//  KituraNet
//
//  Created by Geert Berkers on 03/10/2019.
//

import LoggerAPI
import Foundation

@available(OSX 10.13, *)
public class CRLChecker {
       
    var url: String
    
    var bashPath : String {
        return "\(Bash.projectPath)/var/bash"
    }
    
    var hostName: String {
        return String(url.split(separator: "/").first!)
    }
    
    var certPath: String {
        "\(Bash.projectPath)/var/bash/\(hostName).pem"
    }

    var crlPath : String {
        "\(Bash.projectPath)/var/www/crl/LatestCRL.pem"
    }
    
    init(url: String) {
        self.url = url
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
    }
    
    func checkCrl() -> Bool {
        // 1. Download SSL certificate
        guard let certPath = downloadSSLCertificate(url: url) else {
            return false
        }
  
        // 2. Get Serial Number
        guard var serialNumber = executeSSLCommando("openssl x509 -in \(certPath) -noout -serial ") else {
            Log.error("No certificate serialNumber")
            return false
        }
        
        serialNumber = serialNumber
            .replacingOccurrences(of: "serial=", with: "")
            .replacingOccurrences(of: "\n", with: "")
        
        Log.debug("SSL SerialNumber: \(serialNumber)")
        Log.debug("CRL: \(crlPath)")
        
        // 3. Check CRL Status
        guard let crlStatus = executeSSLCommando("openssl crl -inform pem -text -in \(crlPath) | grep \(serialNumber)") else {
            Log.error("No CRL Status")
            return false
        }
        
        if crlStatus.contains(serialNumber) {
            Log.info("CRL contains serialnumber!")
            return false
        }
        
        Log.debug("SSL Certificate is validated against CRL")
        
        return true
    }
    
    func downloadSSLCertificate(url: String) -> String? {
        Log.debug("HostName: \(hostName)")
        Log.debug("CertPath: \(certPath)")
        
        let command = "openssl s_client -showcerts -connect \(hostName):443 -servername \(hostName) </dev/null 2>/dev/null|openssl x509 -outform PEM > \(certPath)"
        
        guard let _ = executeSSLCommando(command) else {
            return nil
        }
        
        if (downloadedSSL(path: certPath)) {
            return certPath
        }
        
        Log.error("No Cert Path")
        return nil
    }
    
    func downloadedSSL(path: String) -> Bool {
        guard let _ = FileManager.default.contents(atPath: path) else {
            Log.error("SSL Path doesn't exist")
            return false
        }
        
        return true
    }
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}
