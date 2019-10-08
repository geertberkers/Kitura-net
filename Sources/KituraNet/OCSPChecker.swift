//
//  OCSPChecker.swift
//  KituraNet
//
//  Created by Geert Berkers on 03/10/2019.
//

import LoggerAPI
import Foundation

public class OCSPChecker {

    public static var projectPath: String = ""

    var url: String
    
    var bashPath : String {
        return "\(OCSPChecker.projectPath)/var/bash"
    }
    
    var hostName: String {
        return String(url.split(separator: "/").first!)
    }
    
    init(url: String) {
        self.url = url
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
    }
    
    func checkOCSP() -> Bool {
        Log.info("HostName: \(hostName)")
        
        guard let (sslPath, issuerPath) = downloadCertificates() else {
            Log.error("Could NOT download SSL Certificates from: \(hostName)")
            return false
        }
        
        Log.info("SSL Cert Path: \(sslPath)")
        Log.info("SSL Issuer Path: \(issuerPath)")
        
        guard let ocspUri = getOCSPUri(sslPath: sslPath) else {
            Log.error("No OCSP Uri")
            return false
        }
        
        Log.info("OCSP uri: \(ocspUri)")
        
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
    
    func downloadCertificates() -> (String, String)? {
        let command = "openssl s_client -connect \(hostName):443 -servername \(hostName) -showcerts 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p'"
        
        guard let result = executeSSLCommando(command) else {
            Log.error("No certificates")
            return nil
        }
        
        let endCertificateSeperator = "-----END CERTIFICATE-----\n"
        let caCertificatePath = "\(bashPath)/\(hostName).crt"
        let issuerCertificatePath = "\(bashPath)/\(hostName).ca.crt"
        
        let certificates = result.components(separatedBy: endCertificateSeperator)
        
        guard
            certificates
                // Count certificatets only! Do not count empty line!
                .filter( { $0.starts(with: "-----BEGIN CERTIFICATE-----")})
                .count >= 2
            else {
                Log.error("No issuer certificates found!")
                return nil
        }
        
        let caCertificate = certificates.first! + endCertificateSeperator
        let issuerCerts = certificates.dropFirst().joined(separator: endCertificateSeperator)
        
        guard let caData = caCertificate.data(using: .utf8) else {
            Log.error("No CA Certificate")
            return nil
        }
        
        guard let issuerDatta = issuerCerts.data(using: .utf8) else {
            Log.error("No ISSUER Certificate")
            return nil
        }
        
        do {
            try caData.write(to: URL(fileURLWithPath: caCertificatePath))
            try issuerDatta.write(to: URL(fileURLWithPath: issuerCertificatePath))
            return (caCertificatePath, issuerCertificatePath)
        } catch {
            Log.error("Could not save CA or ISSUER certificates")
            return nil
        }
    }
    
    func getOCSPUri(sslPath: String) -> String? {
        let command = "openssl x509 -noout -ocsp_uri -in \(sslPath)"
        return bash.execute(commandName: command)?.replacingOccurrences(of: "\n", with: "")
    }
    
    func getOCSPStatus(issuerPath: String, sslPath: String, uri: String) -> String? {
        let caPath = "\(OCSPChecker.projectPath)/var/www/ca/ca-certificates.crt"
        let command = "openssl ocsp -sha1 -issuer \(issuerPath) -cert \(sslPath) -url \(uri) -CAfile \(caPath) -no_nonce"
        return bash.execute(commandName: command)
    }
    
    
    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}
