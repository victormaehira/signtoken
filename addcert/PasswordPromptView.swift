import SwiftUI

struct PasswordPromptView: View {
    @ObservedObject var manager: PasswordPromptManager
    @State private var password = ""
    @State private var otp = ""
    @FocusState private var isPasswordFocused: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 40))
                .foregroundStyle(.blue)

            Text("Senha da Chave Privada")
                .font(.title3)
                .fontWeight(.semibold)

            Text("Digite a senha para desbloquear a chave privada do certificado.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if let error = manager.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            if manager.isVerifying {
                ProgressView("Verificando…")
                    .controlSize(.small)
            } else {
                SecureField("Senha", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
                    .focused($isPasswordFocused)
                    .onSubmit { submit() }

                TextField("OTP", text: $otp)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
                    .onSubmit { submit() }
            }

            HStack(spacing: 12) {
                Button("Cancelar") {
                    manager.cancel()
                }
                .keyboardShortcut(.cancelAction)

                Button("Desbloquear") {
                    submit()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || otp.isEmpty || manager.isVerifying)
            }
        }
        .padding(30)
        .frame(width: 360)
        .onAppear {
            isPasswordFocused = true
        }
        .onChange(of: manager.errorMessage) { _ in
            password = ""
            otp = ""
            isPasswordFocused = true
        }
    }

    private func submit() {
        guard !password.isEmpty, !otp.isEmpty else { return }
        manager.submitPassword(password, otp: otp)
    }
}
