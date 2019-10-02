//
//  OCSPChecker.swift
//  KituraNet
//
//  Created by Geert Berkers on 02/10/2019.
//

import LoggerAPI
import Foundation

class OCSPChecker {
    
    init(url: String, projectPath: String) {
        self.url = url
        self.projectPath = projectPath
    }
    
    var url: String
    var projectPath: String
    var ocspUri: String? = nil
    
    var hostName: String {
        return String(url.split(separator: "/").first!)
    }
    
    func checkOCSP() -> Bool {
        Log.info("HostName: \(hostName)")
        
        guard let sslPath = getSSLCert() else {
            Log.error("Could NOT download SSL Cert from : \(hostName)")
            return false
        }
        
        Log.info("SSL Path: \(sslPath)")
        
        guard let issuerPath = getSSLIssuerCert() else {
            Log.error("Could NOT get issuer Cert")
            return false
        }
        
        Log.info("Issuer Path: \(issuerPath)")
        
        guard let ocspUri = getOCSPUri(sslPath: sslPath) else {
            Log.error("No OCSP Uri")
            return false
        }
        
        Log.info("OCSP uri: \(ocspUri)")
        
        self.ocspUri = ocspUri
        
        guard let ocspStatus = getOCSPStatus(issuerPath: issuerPath, sslPath: sslPath, uri: ocspUri) else {
            Log.error("No OCSP Status")
            return false
        }
        
        Log.info("OCSP Status: \(ocspStatus)")
        
        switch ocspStatus {
        case let status where status.contains(": good") :
            Log.info("OSCP Verification: Good!")
            return true
        case let status where status.contains(": revoked") :
            Log.error("OSCP Verification: Revoked!")
            return false
        case let status where status.contains(": unknown") :
            Log.error("OSCP Verification: Unknown!")
            return false
        default:
            Log.error("OCSP: No Result!")
            return false
        }
    }
    
    func getSSLCert() -> String? {
        //        // NOTE: Mock Cert from local storage
        //        return "\(bashPath)/\(hostName).crt"
        let certPath = "\(bashPath)/\(hostName).pem"
        let commando = "openssl s_client -connect \(hostName):443  -servername \(hostName) 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > \(certPath)"
        //        let commando = "openssl s_client -showcerts -connect \(hostName):443 -servername \(hostName) </dev/null 2>/dev/null|openssl x509 -text -outform PEM > \(certPath)"
        
        guard
            let _ = executeSSLCommando(commando),
            let _ = FileManager.default.contents(atPath: certPath)
            else {
                return nil
        }
        
        return certPath
    }
    
    func getOCSPUri(sslPath: String) -> String? {
        let command = "openssl x509 -noout -ocsp_uri -in \(sslPath)"
        return bash.execute(commandName: command)?.replacingOccurrences(of: "\n", with: "")
    }
    
    
    func getSSLIssuerCert() -> String? {
        let certPath = "\(bashPath)/\(hostName).ca.crt"
        
        let command = "openssl s_client -connect \(hostName):443 -servername \(hostName) -showcerts 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > \(certPath)"
        
        guard
            let _ = executeSSLCommando(command),
            let _ = FileManager.default.contents(atPath: certPath)
            else {
                return nil
        }
        
        return certPath
    }
    
    func getOCSPStatus(issuerPath: String, sslPath: String, uri: String) -> String? {
        let caPath = "\(projectPath)/var/www/ca/ca-certificates.crt"
        let command = "openssl ocsp -sha1 -issuer \(issuerPath) -cert \(sslPath) -url \(uri) -CAfile \(caPath) -no_nonce"
        return bash.execute(commandName: command)
    }
    
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}

extension OCSPChecker {
    
    var bashPath : String {
        return "\(projectPath)/var/bash"
    }
    
    var chain: String {
        return "\(projectPath)/var/www/ca/ca-certificates.crt"
    }
    
    
}
