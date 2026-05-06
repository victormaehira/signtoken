import SwiftUI


private struct CertificadoBuscaItem: Identifiable, Hashable {
    let id: UUID
    var titular: String
    var emissor: String
    var validade: String
}

struct ContentView: View {
    @State private var statusMessage: String?
    @State private var isError = false
    @State private var isProcessing = false

    @State private var cpf = ""
    @State private var senha = ""
    @State private var otp = ""
    
    @State private var certificadosResultado: [CertificadoBuscaItem] = []
    @State private var certificadoSelecionado: CertificadoBuscaItem.ID?
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(.blue)

            Text("Instalador de Certificado")
                .font(.title2)
                .fontWeight(.semibold)

            Text("POC - HSM Remoto")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Form {
                LabeledContent("CPF") {
                    TextField("", text: $cpf)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("Senha") {
                    SecureField("", text: $senha)
                        .textFieldStyle(.roundedBorder)
                }
                LabeledContent("OTP") {
                    TextField("", text: $otp)
                        .textFieldStyle(.roundedBorder)
                }
            }
            .formStyle(.columns)
            .frame(maxWidth: 360)

            Button(action: buscarCertificado) {
                Label("Buscar Certificado (MOCK API REMOTE)", systemImage: "arrow.down.circle.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isProcessing)

            Table(certificadosResultado, selection: $certificadoSelecionado) {
                TableColumn("Titular") { item in
                    Text(item.titular)
                }
                TableColumn("Emissor") { item in
                    Text(item.emissor)
                }
                TableColumn("Validade") { item in
                    Text(item.validade)
                }
            }
            .frame(minHeight: 140, maxHeight: 220)

            Button(action: performRegistration) {
                Label("Instalar certificado", systemImage: "arrow.down.circle.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isProcessing)

            if let statusMessage {
                Label(
                    statusMessage,
                    systemImage: isError
                        ? "xmark.octagon.fill"
                        : "checkmark.circle.fill"
                )
                .foregroundStyle(isError ? .red : .green)
                .font(.callout)
                .multilineTextAlignment(.center)
            }
        }
        .padding(40)
        // .frame(minWidth: 400, minHeight: 300)
        .frame(minWidth: 520, minHeight: 420)
    }

    private func performRegistration() {
        isProcessing = true
        statusMessage = nil

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try TokenRegistration.registerIfPossible()
                DispatchQueue.main.async {
                    statusMessage = "Certificado instalado com sucesso!"
                    isError = false
                    isProcessing = false
                }
            } catch {
                DispatchQueue.main.async {
                    statusMessage = error.localizedDescription
                    isError = true
                    isProcessing = false
                }
            }
        }
    }
    
    private func buscarCertificado() {
        certificadosResultado = [
            CertificadoBuscaItem(
                id: UUID(),
                titular: "Victor Yuji Maehira",
                emissor: "AC Certisign Corporativa G3",
                validade: "12/04/2027"
            ),
            CertificadoBuscaItem(
                id: UUID(),
                titular: "Victor Yuji Maehira",
                emissor: "AC Certisign Corporativa G3",
                validade: "09/11/2026"
            ),
        ]
        certificadoSelecionado = certificadosResultado.first?.id
    }
}

#Preview {
    ContentView()
}
