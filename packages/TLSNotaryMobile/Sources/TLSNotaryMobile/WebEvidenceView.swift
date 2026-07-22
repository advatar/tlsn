#if os(iOS)
import SwiftUI
import WebKit

@available(iOS 17.0, *)
public struct WebEvidenceView: View {
    @State private var browser = BrowserModel()
    @State private var status = "Open an HTTPS page, then create evidence."
    @State private var credential: EvidenceCredential?
    private let client: TLSNotaryMobileClient

    public init(client: TLSNotaryMobileClient) {
        self.client = client
    }

    public var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                BrowserRepresentable(model: browser)
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text(status).font(.footnote)
                    Button("Create evidence credential") {
                        Task { await createEvidence() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(browser.url?.scheme != "https" || browser.isLoading)

                    if let credential {
                        ShareLink(
                            "Export credential",
                            item: credential.credential,
                            preview: SharePreview("TLSNotary Evidence Credential")
                        )
                    }
                }
                .padding()
            }
            .navigationTitle(browser.title ?? "TLSNotary")
        }
    }

    @MainActor
    private func createEvidence() async {
        guard let url = browser.url else { return }
        status = "Replaying selected HTTPS request…"
        do {
            let body = try await browser.replayCurrentGET()
            status = "Constructing holder-signed evidence…"
            let result = try await client.createEvidence(
                EvidenceRequest(url: url, responseBody: body)
            )
            credential = result
            status = result.verifyHolderSignature()
                ? "Evidence credential created and locally verified."
                : "Credential created, but holder verification failed."
        } catch {
            status = error.localizedDescription
        }
    }
}

@available(iOS 17.0, *)
@Observable
@MainActor
final class BrowserModel {
    fileprivate weak var webView: WKWebView?
    var url: URL?
    var title: String?
    var isLoading = false

    func replayCurrentGET() async throws -> Data {
        guard let webView, let url else {
            throw TLSNotaryMobileError.invalidRequest("No page is selected.")
        }
        let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = HTTPCookieStorage.shared
        cookies.forEach { configuration.httpCookieStorage?.setCookie($0) }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await URLSession(configuration: configuration).data(for: request)
        guard let http = response as? HTTPURLResponse, 200..<400 ~= http.statusCode else {
            throw TLSNotaryMobileError.invalidRequest("The replayed request did not succeed.")
        }
        return data
    }
}

@available(iOS 17.0, *)
private struct BrowserRepresentable: UIViewRepresentable {
    let model: BrowserModel

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    func makeUIView(context: Context) -> WKWebView {
        let view = WKWebView()
        view.navigationDelegate = context.coordinator
        model.webView = view
        view.load(URLRequest(url: URL(string: "https://example.com")!))
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        let model: BrowserModel
        init(model: BrowserModel) { self.model = model }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation?) {
            model.isLoading = true
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation?) {
            model.url = webView.url
            model.title = webView.title
            model.isLoading = false
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation?,
            withError error: any Error
        ) {
            model.isLoading = false
        }
    }
}
#endif
