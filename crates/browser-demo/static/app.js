const encoder = new TextEncoder();
const decoder = new TextDecoder();

const healthIndicator = document.querySelector("#health-indicator");
const wasmIndicator = document.querySelector("#wasm-indicator");
const requestForm = document.querySelector("#request-form");
const revealForm = document.querySelector("#reveal-form");
const requestButton = document.querySelector("#request-button");
const revealButton = document.querySelector("#reveal-button");
const sentTranscript = document.querySelector("#sent-transcript");
const recvTranscript = document.querySelector("#recv-transcript");
const verifierStatus = document.querySelector("#verifier-status");
const verifiedTranscript = document.querySelector("#verified-transcript");

const state = {
  wasm: null,
  prover: null,
  transcript: null,
  sessionId: null,
};

class WebSocketIo {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.socket.binaryType = "arraybuffer";
    this.bufferedReads = [];
    this.pendingReads = [];
    this.closed = false;
    this.error = null;
    this.openPromise = new Promise((resolve, reject) => {
      this.socket.addEventListener("open", () => resolve(), { once: true });
      this.socket.addEventListener(
        "error",
        () => reject(new Error(`failed to open websocket ${url}`)),
        { once: true },
      );
    });

    this.socket.addEventListener("message", (event) => {
      const payload = new Uint8Array(event.data);
      const pending = this.pendingReads.shift();
      if (pending) {
        pending.resolve(payload);
      } else {
        this.bufferedReads.push(payload);
      }
    });

    this.socket.addEventListener("close", () => {
      this.closed = true;
      while (this.pendingReads.length > 0) {
        const pending = this.pendingReads.shift();
        pending.resolve(null);
      }
    });

    this.socket.addEventListener("error", () => {
      this.error = new Error(`websocket ${url} failed`);
      while (this.pendingReads.length > 0) {
        const pending = this.pendingReads.shift();
        pending.reject(this.error);
      }
    });
  }

  async read() {
    await this.openPromise;
    if (this.error) {
      throw this.error;
    }
    if (this.bufferedReads.length > 0) {
      return this.bufferedReads.shift();
    }
    if (this.closed) {
      return null;
    }
    return await new Promise((resolve, reject) => {
      this.pendingReads.push({ resolve, reject });
    });
  }

  async write(data) {
    await this.openPromise;
    if (this.error) {
      throw this.error;
    }
    if (this.closed) {
      throw new Error("websocket is already closed");
    }
    this.socket.send(data);
  }

  async close() {
    try {
      await this.openPromise;
    } catch (_) {
      return;
    }
    if (!this.closed) {
      this.socket.close();
    }
  }
}

async function ensureWasm() {
  if (state.wasm) {
    return state.wasm;
  }

  const module = await import("/pkg/tlsn_wasm.js");
  await module.default();
  await module.initialize(undefined, Math.max(1, Math.min(navigator.hardwareConcurrency || 4, 4)));
  state.wasm = module;
  wasmIndicator.textContent = "ready";
  return module;
}

function setTranscript(element, text) {
  element.textContent = text && text.length > 0 ? text : "No transcript yet.";
  element.classList.toggle("empty", !text || text.length === 0);
}

function appendStatus(label, payload) {
  const line = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  verifierStatus.textContent = `${label}\n${line}`;
  verifierStatus.classList.remove("empty");
}

function wsUrl(path) {
  const url = new URL(path, window.location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

function parseHeaders(text) {
  const map = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const separator = line.indexOf(":");
    if (separator === -1) {
      throw new Error(`invalid header line: ${line}`);
    }
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    map.set(name, encoder.encode(value));
  }
  return map;
}

function parseLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function asUint8Array(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function formatBytes(value) {
  return decoder.decode(asUint8Array(value));
}

function buildHandlers() {
  const handlers = [];
  const requestHeaders = parseLines(document.querySelector("#request-header-input").value);
  const responseHeaders = parseLines(document.querySelector("#response-header-input").value);
  const jsonPaths = parseLines(document.querySelector("#json-path-input").value);

  if (document.querySelector("#reveal-request-line").checked) {
    handlers.push({ type: "SENT", part: "START_LINE", action: "REVEAL" });
  }

  if (document.querySelector("#reveal-response-status").checked) {
    handlers.push({ type: "RECV", part: "START_LINE", action: "REVEAL" });
  }

  for (const header of requestHeaders) {
    handlers.push({
      type: "SENT",
      part: "HEADERS",
      action: "REVEAL",
      params: { key: header.toLowerCase() },
    });
  }

  for (const header of responseHeaders) {
    handlers.push({
      type: "RECV",
      part: "HEADERS",
      action: "REVEAL",
      params: { key: header.toLowerCase() },
    });
  }

  if (document.querySelector("#reveal-full-response-body").checked) {
    handlers.push({ type: "RECV", part: "BODY", action: "REVEAL" });
    return handlers;
  }

  for (const path of jsonPaths) {
    handlers.push({
      type: "RECV",
      part: "BODY",
      action: "REVEAL",
      params: { type: "json", path },
    });
  }

  return handlers;
}

function applyAuthenticatedMask(bytesLike, authenticatedRanges) {
  const bytes = asUint8Array(bytesLike);
  const masked = new Uint8Array(bytes.length);
  masked.fill("·".charCodeAt(0));
  for (const range of authenticatedRanges || []) {
    masked.set(bytes.slice(range.start, range.end), range.start);
  }
  return decoder.decode(masked);
}

async function fetchHealth() {
  const response = await fetch("/api/health");
  const health = await response.json();
  healthIndicator.textContent = health.wasm_pkg_present ? "Server ready" : "Build wasm package first";
  if (!health.wasm_pkg_present) {
    wasmIndicator.textContent = "missing /pkg";
  }
}

async function pollSession(sessionId) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const response = await fetch(`/api/sessions/${sessionId}`);
    if (response.status === 404) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      continue;
    }
    const snapshot = await response.json();
    if (snapshot.status === "running") {
      await new Promise((resolve) => setTimeout(resolve, 500));
      continue;
    }
    return snapshot;
  }
  throw new Error("timed out waiting for notary result");
}

requestForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  requestButton.disabled = true;
  revealButton.disabled = true;
  verifierStatus.textContent = "Starting proof session...";
  verifierStatus.classList.remove("empty");
  verifiedTranscript.textContent = "No verified transcript yet.";
  verifiedTranscript.classList.add("empty");

  try {
    const wasm = await ensureWasm();
    const url = new URL(document.querySelector("#url-input").value);
    if (url.protocol !== "https:") {
      throw new Error("only https:// URLs are supported in this demo");
    }

    const sessionId = crypto.randomUUID();
    const notaryIo = new WebSocketIo(wsUrl(`/ws/notary/${sessionId}`));
    const serverIo = new WebSocketIo(
      wsUrl(`/ws/tcp?host=${encodeURIComponent(url.hostname)}&port=${encodeURIComponent(url.port || "443")}`),
    );

    const prover = new wasm.Prover({
      server_name: url.hostname,
      max_sent_data: 16 * 1024,
      max_sent_records: null,
      max_recv_data_online: null,
      max_recv_data: 256 * 1024,
      max_recv_records_online: null,
      defer_decryption_from_start: null,
      network: "Latency",
      client_auth: null,
    });

    prover.set_progress_callback((payload) => {
      appendStatus("Verifier transport", payload);
    });

    await prover.setup(notaryIo);

    const headers = parseHeaders(document.querySelector("#headers-input").value);
    headers.set("Host", encoder.encode(url.host));
    if (!headers.has("Accept")) {
      headers.set("Accept", encoder.encode("*/*"));
    }
    if (!headers.has("Accept-Encoding")) {
      headers.set("Accept-Encoding", encoder.encode("identity"));
    }
    if (!headers.has("Connection")) {
      headers.set("Connection", encoder.encode("close"));
    }
    if (!headers.has("User-Agent")) {
      headers.set("User-Agent", encoder.encode("TLSN Browser Demo"));
    }

    await prover.send_request(serverIo, {
      method: "GET",
      uri: `${url.pathname}${url.search}`,
      headers,
      body: null,
    });

    const transcript = prover.transcript();
    state.prover = prover;
    state.transcript = transcript;
    state.sessionId = sessionId;

    setTranscript(sentTranscript, formatBytes(transcript.sent));
    setTranscript(recvTranscript, formatBytes(transcript.recv));
    appendStatus("Transcript", { sessionId, server: url.host });
    revealButton.disabled = false;
  } catch (error) {
    appendStatus("Error", error.message || String(error));
  } finally {
    requestButton.disabled = false;
  }
});

revealForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  revealButton.disabled = true;

  try {
    if (!state.prover || !state.transcript || !state.sessionId) {
      throw new Error("fetch a transcript before finalizing a proof");
    }

    const handlers = buildHandlers();
    if (handlers.length === 0) {
      throw new Error("select at least one reveal rule");
    }

    const wasm = await ensureWasm();
    const revealOutput = wasm.compute_reveal(
      asUint8Array(state.transcript.sent),
      asUint8Array(state.transcript.recv),
      handlers,
    );

    appendStatus("Reveal plan", revealOutput);
    await state.prover.reveal(revealOutput.reveal);

    const snapshot = await pollSession(state.sessionId);
    appendStatus("Verifier result", snapshot);

    if (snapshot.status === "complete" && snapshot.output?.transcript) {
      const partial = snapshot.output.transcript;
      const sent = applyAuthenticatedMask(partial.sent, partial.sent_authed);
      const recv = applyAuthenticatedMask(partial.recv, partial.recv_authed);
      verifiedTranscript.textContent = `Sent\n${sent}\n\nReceived\n${recv}`;
      verifiedTranscript.classList.remove("empty");
    } else if (snapshot.status === "failed") {
      throw new Error(snapshot.error || "verifier failed");
    }
  } catch (error) {
    appendStatus("Error", error.message || String(error));
  } finally {
    revealButton.disabled = false;
  }
});

fetchHealth().catch((error) => {
  healthIndicator.textContent = error.message || "Server check failed";
});
