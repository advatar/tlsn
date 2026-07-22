# iOS demo

Create an iOS 17+ app target in Xcode, add the local
`packages/TLSNotaryMobile` package, and use `TLSNotaryDemoApp.swift` as the app
entry point. Run `packages/TLSNotaryMobile/build-xcframework.sh` before opening
the package for the first time.

The demo intentionally begins with `https://example.com`. Navigation remains
inside `WKWebView`; tapping the button replays the current GET with the web
view's cookies and exports a holder-signed evidence envelope.
