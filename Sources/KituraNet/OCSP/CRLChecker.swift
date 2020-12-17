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
    
    
    
    //    let basePath = "\(projectPath)/var/www/certs/download/"
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
        var returnValue = true
        
        crls.forEach { crlSubString in
            let crl = String(crlSubString)
            Log.info("CRL: \(crl)")
            
            // 3. Download CRL
            guard let crlPath = downloadCRL(uri: crl) else {
                return //false
            }
            
            //            crlPath = "\(basePath)\(crlPath)"
            
            // 4. Get Serial Number
            guard var serialNumber = executeSSLCommando("openssl x509 -in \(certPath) -noout -serial ") else {
                return //false
            }
            
            serialNumber = serialNumber
                .replacingOccurrences(of: "serial=", with: "")
                .replacingOccurrences(of: "\n", with: "")
            
            Log.info("SN: \(serialNumber)")
            Log.info("CrlPath: \(crlPath)")
            
            // 5. Check CRL Status
            guard let crlStatus = executeSSLCommando("openssl crl -inform der -text -in \(crlPath) | grep \(serialNumber)") else {
                return //false
            }
            
            if crlStatus.contains(serialNumber) {
                returnValue = false
            }
        }
        
        // Item not in CRL
        return returnValue
        
        
        //        // 3. Download CRL
        //        guard let crlPath = downloadCRL(uri: crlUri) else {
        //            return false
        //        }
        //
        //        // 4. Get Serial Number
        //        guard let serialNumber = executeSSLCommando("openssl x509 -in \(certPath) -nouout -serial ") else {
        //            return false
        //        }
        //
        //        // 5. Check CRL Status
        //        guard let crlStatus = executeSSLCommando("openssl crl -inform der -text -in \(crlPath) | grep \(serialNumber)") else {
        //            return false
        //        }
        //
        //        return crlStatus.contains(serialNumber)
        
    }
    
    func downloadSSLCertificate(url: String) -> String? {
        let hostname = String(url.split(separator: "/").first!)
        //        let certPath = "\(hostname).pem"
        let certPath = "\(Bash.projectPath)/var/www/bash/\(hostname).pem"
        Log.info("HostName: \(hostname)")
        Log.info("CertPath: \(certPath)")
        
        //        let output = "openssl s_client -showcerts -connect \(hostname):443 </dev/null 2>/dev/null|openssl x509 -noout -text"
        let command = "openssl s_client -showcerts -connect \(hostname):443 -servername \(hostname) </dev/null 2>/dev/null|openssl x509 -outform PEM > \(certPath)"
        
        guard let _ = executeSSLCommando(command) else {
            return nil
        }
        
        // Save Output as certificate
        //result.data(using: .utf8)?.write(to: URL(fileURLWithPath: certPath))
        
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
        
        if let crlUri = executeSSLCommando(getCrLCommand){
            return crlUri
                .replacingOccurrences(of: " ", with: "")
                .replacingOccurrences(of: "URI:", with: "|")
                .replacingOccurrences(of: "\n", with: "")
        }
        // TODO: Execute commando
        
        // Example Result:
        // URI:http://crl.managedpki.com/KPNBVPKIoverheidOrganisatieServerCAG3/LatestCRL.crl
        
        //        guard let crlUri = executeSSLCommando("wget get")
        Log.error("Could not get CRL!")
        return nil
    }
    
    func downloadCRL(uri: String) -> String? {
        // TODO: Implement me
        let crlFile = String(uri.split(separator: "/").last!)
        if let pwd = executeSSLCommando("pwd") {
            Log.info("PWD: \(pwd)")
            
            //let command = "/usr/local/bin/wget"
            if let crlResult = executeSSLCommando("wget \(uri)") {
                Log.info("CrlResult: \(crlResult)")
                return crlFile
                //                return "\(pwd)/\(crlFile)"
            }
            
        }
        
        Log.error("Download CRL not executed!")
        return nil
    }
    
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}
