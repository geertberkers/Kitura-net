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
    
    var crlPath : String {
        "\(bashPath)/\(hostName).crl"
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
            guard let _ = getCRL(uri: crl) else {
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
            guard let crlStatus = executeSSLCommando("openssl crl -inform der -text -in \(crlPath) | grep \(serialNumber)") else {
                Log.error("No CRL Status")
                return
            }
            
            if crlStatus.contains(serialNumber) {
                Log.error("CRL Check: Invalid SerialNumber!")
                validCertificate = false
            } else {
                Log.info("CRL Check: Valid SerialNumber!")
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

        Log.error("Could NOT get CRL uri!")
        return nil
    }
    
    func getCRL(uri: String) -> String? {
        let split = uri.split(separator: "/")
        let crlFile = String(split.dropLast().last!) + String(split.last!)
        let path = "\(Bash.projectPath)/var/bash/\(crlFile)"
        Log.debug("CRL Path: \(path)")
        if FileManager.default.fileExists(atPath: path) {
            Log.info("Cached CRL from disk.")
            return crlFile
        }
        
        return downloadCRL(uri: uri)
    }
    
    func downloadCRL(uri: String) -> String? {
        let split = uri.split(separator: "/")
        let crlFile = String(split.dropLast().last!) + String(split.last!)
        
        if let _ = executeSSLCommando("wget -O \(Bash.projectPath)/var/bash/\(crlFile) \(uri)") {
            // NOTE: This command does not return anything except empty characters
            return crlFile
        }

        Log.error("Download CRL NOT executed!")
        return nil
    }
    
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }

