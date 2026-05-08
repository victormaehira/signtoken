//
//  FileLogger.swift
//  CertTokenExtension
//
//  Created by victor.maehira on 08/05/26.
//

import Foundation
import os.log

final class FileLogger {
    static let shared = FileLogger()

    private let osLog: OSLog
    private let fileURL: URL
    private let queue = DispatchQueue(label: "br.com.certisign.addcert.filelogger")
    private let dateFormatter: DateFormatter

    private init() {
        osLog = OSLog(subsystem: "br.com.certisign.addcert.CertTokenExtension", category: "TokenSession")
        fileURL = URL(fileURLWithPath: "/tmp/CertTokenExtension.log")
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
    }

    func log(_ message: String, type: OSLogType = .default) {
        let timestamp = dateFormatter.string(from: Date())
        let line = "[\(timestamp)] \(message)\n"

        os_log("%{public}@", log: osLog, type: type, message)

        queue.async { [weak self] in
            guard let self = self else { return }
            if let handle = try? FileHandle(forWritingTo: self.fileURL) {
                handle.seekToEndOfFile()
                if let data = line.data(using: .utf8) {
                    handle.write(data)
                }
                handle.closeFile()
            } else {
                try? line.write(to: self.fileURL, atomically: false, encoding: .utf8)
            }
        }
    }
}
