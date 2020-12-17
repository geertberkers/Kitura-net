//
//  Bash.swift
//  KituraNet
//
//  Created by Geert Berkers on 03/10/2019.
//

import LoggerAPI
import Foundation

@available(OSX 10.13, *)
let bash: CommandExecuting = Bash()

protocol CommandExecuting {
    func execute(commandName: String) -> String?
    func execute(commandName: String, arguments: [String]) -> String?
}

@available(OSX 10.13, *)
public final class Bash: CommandExecuting {

    public static var logBash: Bool = true
    public static var projectPath: String = ""
    

    // MARK: - CommandExecuting
    
    func execute(commandName: String) -> String? {
        return execute(commandName: commandName, arguments: [])
    }
    
    func execute(commandName: String, arguments: [String]) -> String? {
        if Bash.logBash {
            Log.info("Command:\n\(commandName)")
        }
        
        guard let result = executeCommand(command: "/bin/bash" , arguments: ["-c", commandName]) else {
            Log.error("Could NOT execute Bash Command:\n\(commandName)")
            return nil
        }
        
        if Bash.logBash {
            Log.info("Result:\n\(result)")
        }
        
        return result
    }
    
    // MARK: Private
    
    private func executeCommand(command: String, arguments: [String] = []) -> String? {
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments
        
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: String.Encoding.utf8)
        } catch {
            return nil
        }
    }
}
