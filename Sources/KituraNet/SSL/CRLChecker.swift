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
  
        // 2. Vraag CRL op van het certificaat
        guard let crlUri = getCRLUri(certPath: certPath) else {
            return false
        }
        
        let crls = crlUri.split(separator: "|")
        var validCertificate = true
        
        crls.forEach { crlSubString in
            let crl = String(crlSubString)
            Log.debug("CRL: \(crl)")
            
            // 3. Download CRL
            guard let _ = downloadCRL(uri: crl) else {
                Log.error("No CRL to download...")
                return
            }
                        
            // 4. Get Serial Number
            guard var serialNumber = executeSSLCommando("openssl x509 -in \(certPath) -noout -serial ") else {
                Log.error("No certificate serialNumber")
                return
            }
            
            serialNumber = serialNumber
                .replacingOccurrences(of: "serial=", with: "")
                .replacingOccurrences(of: "\n", with: "")
            
            Log.debug("SSL SerialNumber: \(serialNumber)")
            
            // 5. Check CRL Status
            guard let crlStatus = executeSSLCommando("openssl crl -inform der -text -in \(hostName).crl | grep \(serialNumber)") else {
                Log.error("No CRL Status")
                return
            }
            
            if crlStatus.contains(serialNumber) {
                Log.info("CRL contains serialnumber!")
                validCertificate = false
            }
        }
        
        // Item not in CRL
        return validCertificate
    }
    
    func downloadSSLCertificate(url: String) -> String? {
        let certPath = "\(Bash.projectPath)/var/www/\(hostName).pem"
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
    
    func getCRLUri(certPath: String) -> String? {
        let getCrLCommand = "openssl x509 -in \(certPath) -noout -text | grep crl"
        
        // Example Result:
        // URI:http://crl.managedpki.com/KPNBVPKIoverheidOrganisatieServerCAG3/LatestCRL.crl
        
        if let crlUri = executeSSLCommando(getCrLCommand){
            return crlUri
                .replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: "URI:", with: "|")
                .replacingOccurrences(of: "\n", with: "")
        }

        Log.error("Could not get CRL!")
        return nil
    }
    
    func downloadCRL(uri: String) -> String? {
        let crlFile = String(uri.split(separator: "/").last!)
        
        if let crlResult = executeSSLCommando("wget -O\(Bash.projectPath)/var/bash/\(hostName).crl \(uri)") {
            Log.debug("CrlResult: \(crlResult)")
            return crlFile
        }

        Log.error("Download CRL not executed!")
        return nil
    }
    
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}
