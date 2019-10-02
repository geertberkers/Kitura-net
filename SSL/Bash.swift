//
//  Bash.swift
//  KituraNet
//
//  Created by Geert Berkers on 02/10/2019.
//

import LoggerAPI
import Foundation

let bash: CommandExecuting = Bash()

protocol CommandExecuting {
    func execute(commandName: String) -> String?
    func execute(commandName: String, arguments: [String]) -> String?
}

final class Bash: CommandExecuting {
    
    // MARK: - CommandExecuting
    
    func execute(commandName: String) -> String? {
        return execute(commandName: commandName, arguments: [])
    }
    
    func execute(commandName: String, arguments: [String]) -> String? {
        Log.debug("Command:\n\(commandName)")
        
        guard let result = execute(command: "/bin/bash" , arguments: ["-c", commandName]) else {
            Log.error("Could NOT execute Bash Command:\n\(commandName)")
            return nil
        }
        
        Log.debug("Result:\n\(result)")
        
        return result
    }
    
    // MARK: Private
    
    private func execute(command: String, arguments: [String] = []) -> String? {
        
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

