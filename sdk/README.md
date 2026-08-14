# sdk — integration kits

Ai-Auth integrates with **any website, any mobile app, any backend** because
the surface is standard OIDC / OAuth 2.1 — an OIDC-certified client library
already works with zero code from us. These kits exist for a different reason:
they make the *secure* integration the *easy* one.

| Fact | Value |
| --- | --- |
| Status | 📋 Planned — documentation only, no code yet |
| Integration without an SDK | ✅ Fully supported — standard OIDC, discovery document, JWKS |

## Planned kits

| Kit | Platform | Language |
| --- | --- | --- |
| `sdk/web` | Browsers, SPAs, classic web apps | TypeScript |
| `sdk/ios` | iPhone, iPad | Swift |
| `sdk/android` | Android | Kotlin |
| `sdk/flutter` | Flutter apps | Dart |
| `sdk/react-native` | React Native apps | TypeScript |
| `sdk/server` | Backend token verification, webhook receivers | Go, Python, Node |

## What every kit enforces — not offers, enforces

| Rule | Where it comes from |
| --- | --- |
| PKCE `S256`, system browser, never a WebView | [mobile integration](../docs/mobile-integration.md) §1–2 |
| Verified links only — no custom URL scheme callbacks | §1 |
| Tokens in hardware-backed storage only | §3 |
| SPKI pinning with a shipped backup pin | §4 |
| DPoP proof on every call | [threat model](../docs/threat-model.md) T1 |
| No token ever logged or placed in a URL | T1 Path C |

⚠️ The kits carry the project's thesis to the client: the secure path is the
default path, and doing the wrong thing requires effort. An integrator who
bypasses the kit still gets a standards-compliant, safe server — the gateway's
safety rails do not depend on client goodwill.
