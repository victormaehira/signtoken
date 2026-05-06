//
//  addcertApp.swift
//  addcert
//
//  Created by victor.maehira on 08/04/26.
//

import SwiftUI

@main
struct addcertApp: App {
    @StateObject private var passwordManager = PasswordPromptManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .sheet(isPresented: $passwordManager.isPromptVisible) {
                    PasswordPromptView(manager: passwordManager)
                }
        }
    }
}
