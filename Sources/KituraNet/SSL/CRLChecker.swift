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
        // 1. Download SSL certificate chain
        guard let caChain = downloadCertificateChain() else {
            Log.error("Could NOT download SSL Certificates from: \(hostName)")
            return false
        }

        // 2. Vraag CRL op van het certificaat
        guard let crlUri = getCRLUri(certPath: caChain) else {
            Log.error("Could NOT get CRL from certificate")
            return false
        }

        let crls = crlUri.split(separator: "|")
        var validCertificate = false

        crls.forEach { crlSubString in
            let crl = String(crlSubString)
            Log.debug("CRL: \(crl)")

            // 3. Download CRL
            guard let crlPath = downloadCRL(uri: crl) else {
                Log.error("No CRLPath")
                return
            }

            // 4. Convert to PEM format
            _ = executeSSLCommando("openssl crl -inform DER -in \(crlPath) -outform PEM -out \(hostName).pem")
            
            
            
            // 5. Validate
            let crlPem = "\(bashPath)/\(hostName).pem"
//            let caChain = "CA certificate chain in PEM format"
            let response = executeSSLCommando("openssl crl -in \(crlPem) -CAfile \(caChain)stelselnode.medmij.nl.crt ")
            
            if response == "verify OK" {
                validCertificate = true
            }
            
            
        }

        // Item not in CRL
        return validCertificate
    }
    
    
    func downloadCertificateChain() -> String? {
        let command = "openssl s_client -connect \(hostName):443 -servername \(hostName) -showcerts 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p'"
        
        guard let result = executeSSLCommando(command)?.data(using: .utf8) else {
            Log.error("No certificates")
            return nil
        }
        
        let caCertificatePath = "\(bashPath)/\(hostName).crt"
        
        do {
            try result.write(to: URL(fileURLWithPath: caCertificatePath))
            return caCertificatePath
        } catch {
            Log.error("Could not save CA or ISSUER certificates")
            return nil
        }
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
        if let pwd = executeSSLCommando("pwd") {
            Log.debug("PWD: \(pwd)")

            //let command = "/usr/local/bin/wget"
            if let crlResult = executeSSLCommando("wget -P \(Bash.projectPath)/var/bash -O \(hostName).crl \(uri)") {
                Log.debug("CrlResult: \(crlResult)")
                return crlFile
            }

        }

        Log.error("Download CRL not executed!")
        return nil
    }


    func executeSSLCommando(_ commando: String) -> String? {
        return bash.execute(commandName: commando)
    }
}
