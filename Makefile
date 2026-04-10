.PHONY: browser-demo browser-demo-help browser-demo-local

BROWSER_DEMO_HOSTS ?= example.com www.google.com
BROWSER_DEMO_PORTS ?= 443

browser-demo:
	DEMO_ALLOW_HOSTS="$(BROWSER_DEMO_HOSTS)" DEMO_ALLOW_PORTS="$(BROWSER_DEMO_PORTS)" sh ./scripts/browser-demo.sh

browser-demo-help:
	DEMO_SKIP_WASM_BUILD=1 DEMO_ALLOW_HOSTS="$(BROWSER_DEMO_HOSTS)" DEMO_ALLOW_PORTS="$(BROWSER_DEMO_PORTS)" sh ./scripts/browser-demo.sh --help

browser-demo-local:
	DEMO_ALLOW_HOSTS="localhost" DEMO_ALLOW_PORTS="4000" sh ./scripts/browser-demo.sh --allow-loopback --allow-private-ips
