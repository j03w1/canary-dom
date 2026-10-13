# CanaryDOM: Client-Side Deception & DOM-XSS Threat Monitor

> A zero-dependency browser security engine that turns the Client DOM into an active defense honeypot. Detects malicious browser extensions, DOM-based XSS, credential scraping, and Magecart supply-chain attacks.

[![Deploy to GitHub Pages](https://github.com/YOUR_USERNAME/canary-dom/actions/workflows/deploy.yml/badge.svg)](https://YOUR_USERNAME.github.io/canary-dom/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MITRE D3FEND](https://img.shields.io/badge/MITRE-D3FEND%20Decoy%20Object-green.svg)](https://d3fend.mitre.org/)

---

## What is this and Whats the Threat Model

While traditional perimeter defenses (WAFs, Cloudflare, CSPs) analyze network ingress, **client-side execution environments remain largely opaque**. Once an attacker executes code in the DOM—via a compromised npm supply-chain package, a vulnerable UI dependency, or a malicious browser extension—they operate with the user's authority.

`CanaryDOM` addresses this observability gap through **active client-side deception**:
1. **Zero-Overhead Honeypots**: Injects deceptive DOM inputs with programmatic accessor traps.
2. **Global Environment Guards**: Wraps decoy runtime configurations inside `Proxy` traps that log caller stack traces upon inspection.
3. **Storage Tripwires**: Detects unauthorized enumeration of sensitive web storage keys (`localStorage`, `sessionStorage`).
4. **Supply-Chain Mutation Detection**: Employs `MutationObserver` to catch unauthorized `<script>` and `<iframe>` injections before they establish network persistence.

---

## MITRE ATT&CK & D3FEND Mapping

| Threat Vector / Technique | ATT&CK ID | CanaryDOM Mechanism | D3FEND Countermeasure |
| :--- | :--- | :--- | :--- |
| **Man-in-the-Browser / Scrapers** | T1185 | CSS-Invisible Honeypot Inputs | `D3-DO` (Decoy Object) |
| **DOM-Based XSS Recon** | T1059.007 | `Proxy` Property Get/Set Traps | `D3-EDR` (Execution Detection) |
| **Credentials in LocalStorage** | T1552.001 | Web Storage Trap & Override | `D3-SD` (System Deception) |
| **Magecart / Supply Chain Script Injection** | T1059.007 | `MutationObserver` Script Trap | `D3-SIA` (Script Integrity Analysis) |

---

## Live Demo

Experience the interactive attack simulator on GitHub Pages:  
**[https://j03w1.github.io/canary-dom/](https://j03w1.github.io/canary-dom/)**

---

## Quick Start

```html
<!-- Include CanaryDOM prior to application bundle -->
<script src="src/canary-dom.js"></script>
<script>
  CanaryDOM.init({
    telemetryEndpoint: '[https://siem.example.com/api/v1/client-alerts](https://siem.example.com/api/v1/client-alerts)',
    appId: 'checkout-frontend'
  });
</script>
```

### Telemetry Alert Format

When a trap is tripped, non-blocking telemetry is dispatched via `navigator.sendBeacon`:

```json
{
  "timestamp": "2026-10-13T13:40:02.114Z",
  "sessionNonce": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "appId": "checkout-frontend",
  "eventType": "GLOBAL_HONEYTOKEN_ACCESS",
  "severity": "HIGH",
  "url": "[https://example.com/checkout](https://example.com/checkout)",
  "details": {
    "targetGlobal": "__API_CONFIG__",
    "accessedProperty": "secret",
    "stack": "Error\n    at eval (eval at <anonymous> ...)"
  }
}
```

---

## Security Design Considerations

* **Tamper Resistance**: Engine configuration and exported API endpoints are sealed with `Object.freeze()`.
* **Zero Visual Impact**: Injected honeypot elements maintain full accessibility isolation (`tabindex="-1"`, `opacity: 0.0001`, `pointer-events: none`).
* **Non-Blocking Telemetry**: Telemetry uses `navigator.sendBeacon` with a `fetch(keepalive: true)` fallback to avoid interrupting page unloads or user interactions.

---

## License
MIT License.