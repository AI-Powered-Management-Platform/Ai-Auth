# Ai-Auth — mobile integration

Client-side security for iOS, Android, Flutter, and React Native apps talking
to the Go gateway. Mobile is not a small web browser: apps run sandboxed on
hardware the user owns, on networks nobody trusts, and they cannot use
HttpOnly cookies. Every section below exists because one of those three facts
breaks a web assumption.

| Related | Contents |
| --- | --- |
| [threat-model.md](threat-model.md) | T1 Path B and C are the mobile-relevant paths |
| [hardening-backlog.md](hardening-backlog.md) | §1 session controls, §5 PKCE and PAR |
| [../README.md](../README.md) | Authentication policy, profiles |

---

## 1. Login flow — PKCE and verified deep links

Standard OAuth on mobile fails because any installed app can try to catch the
redirect. Two mechanisms close this, and both are mandatory.

| Step | Who | What |
| --- | --- | --- |
| 1 | App | Generates a random `code_verifier`, hashes it to a `code_challenge` (S256) |
| 2 | App | Opens the system browser to `/authorize` with the challenge |
| 3 | Gateway | Stores the challenge against the pending authorization |
| 4 | User | Authenticates — passkey via the platform's native sheet |
| 5 | Gateway | Redirects back with a single-use code |
| 6 | App | Calls `/token` with the code **and** the original verifier |
| 7 | Gateway | Hashes the verifier; match → tokens, mismatch → nothing |

A malicious app that intercepts the redirect holds a code it cannot spend — it
never saw the verifier.

**Verified links** close the interception itself. The gateway serves two static
files, and the OS then refuses to hand the callback to any app that is not
signed by the matching developer:

| Platform | File served by the gateway | Mechanism |
| --- | --- | --- |
| iOS | `/.well-known/apple-app-site-association` | Universal Links |
| Android | `/.well-known/assetlinks.json` | App Links, signature-matched |

⚠️ Custom URL schemes (`myapp://callback`) are first-come-first-served across
every app on the device. They are not a supported callback mode — verified
HTTPS links only.

⚠️ PKCE closes code interception and nothing else. An adversary-in-the-middle
proxy relays the *whole* flow, verifier included, and takes the session at the
end — that is [threat-model.md](threat-model.md) T1 Path A, and it is answered
by token binding (§6), not by PKCE.

---

## 2. Native passkeys

Apps must not build their own login web views. The operating system's modules
talk to the hardware enclave directly and bind the signature to our origin.

| Platform | API |
| --- | --- |
| iOS | `ASWebAuthenticationSession` / `ASAuthorizationController` for passkeys |
| Android | Credential Manager (`androidx.credentials`) |
| Flutter / React Native | Wrappers over the same two — never a WebView |

⚠️ A WebView login is invisible to the passkey machinery and teaches users to
type credentials into an unverifiable rectangle — the exact habit phishing
needs. The gateway should reject known-WebView user agents on `/authorize`.

Synced passkeys (iCloud Keychain, Google Password Manager) survive device loss:
the user signs into their platform account on a new device and the credential
returns. The trade is that account assurance now includes the platform
account's own recovery — AAL2, not AAL3. High-assurance actors use device-bound
credentials that never sync. The full argument is in the README's
authentication policy and [compliance.md](compliance.md) §3.

---

## 3. Token storage — hardware-backed only

The gateway issues a short-lived access token and a rotating refresh token.
Where the app puts them decides whether device theft is an incident or a
non-event.

| Platform | Store | Required attributes |
| --- | --- | --- |
| iOS | Keychain Services | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — hardware-encrypted, excluded from iCloud backup, dies with the device |
| Android | Keystore-wrapped `EncryptedSharedPreferences` | Key generated in hardware (StrongBox where present), non-exportable |
| Flutter / React Native | Plugins over the above | Never `SharedPreferences`, `UserDefaults`, or any file |

⚠️ `AfterFirstUnlock` variants keep tokens readable while the phone sits stolen
but powered on. `WhenUnlocked` is the default; loosen it only for a documented
background-refresh need, and say so in the risk register.

⚠️ On a rooted or jailbroken device every guarantee above weakens — the OS that
enforces them is the thing that was replaced. That is what §5 integrity
signals are for; storage attributes are necessary, not sufficient.

---

## 4. Transport — pinning, honestly stated

The app pins the gateway's **SPKI public-key hashes** (not leaf certificates)
and refuses any other presenter.

| Rule | Why |
| --- | --- |
| Pin SPKI hashes, minimum two — active plus backup | A single pinned key plus one rotation bricks every installed app |
| Ship the backup pin before its key is ever used | Rotation becomes a config change, not an app-store emergency |
| Pin the gateway domain only | Third-party domains rotate on their own schedule |
| Failure is a hard fail with telemetry | A pin failure is either an attack or a botched rotation — both are pages |

⚠️ What pinning actually buys: it stops network-level interception — hostile
Wi-Fi, rogue CAs, corporate middleboxes. It does **not** protect a device the
attacker controls: with root, instrumentation strips pinning at runtime.
Pinning defends the network path, integrity attestation (§5) addresses the
endpoint, and neither substitutes for the other.

---

## 5. Device integrity and risk telemetry

The mobile app is a sensor for the Thinker (the `ai` service). Signals stream to the
gateway, which forwards them to the Thinker — whose score remains advisory,
as everywhere else in the system.

| Signal | Source | What it indicates |
| --- | --- | --- |
| Play Integrity verdict | Android | App unmodified, device certified, not an emulator farm |
| App Attest / DeviceCheck | iOS | App signed by us, key held in the Secure Enclave |
| IP and carrier velocity | App + gateway | Location spoofing, proxy churn |
| Device fingerprint drift | App | Token moved to different hardware |

⚠️ Attestation verdicts are inputs to the risk band, never gates by themselves.
A hard block on "no attestation" locks out custom ROMs and older devices — an
operator decision per tenant policy, not a default. The default `strict`
profile constrains *authentication strength*, not *device ownership*.

---

## 6. Session lifecycle — mobile is where bearer tokens go to die

Mobile users never log out, so a mobile session is the longest-lived credential
in the system. Everything in [threat-model.md](threat-model.md) T1 applies with
more force here.

| Control | Mobile shape |
| --- | --- |
| Access token TTL | 5–15 minutes, silent refresh |
| Refresh rotation | One-time use; reuse revokes the whole family |
| Sender constraint | DPoP proof per call, key in Keychain / Keystore hardware |
| Step-up | Fresh passkey assertion before credential change or payment |

**Instant revocation** — when the Thinker flags an account or an operator hits
revoke, waiting for TTL expiry is not acceptable:

| Channel | Role |
| --- | --- |
| Server-side revocation list | The authority — every refresh checks it |
| Silent push (APNs / FCM) | Best-effort hint to wipe local tokens now |
| Fast probabilistic filter (e.g. Bloom) at the gateway | Sub-millisecond "possibly revoked?" pre-check on every call |

⚠️ Two honesty notes. Silent push is *advisory delivery* — both platforms
throttle or drop it, so the server-side check remains the enforcement, push
only shortens the window. And a Bloom filter answers "definitely not revoked"
or "**maybe** revoked": false positives kill a small share of valid sessions
early. That is the correct failure direction, but it is an availability cost —
size the filter for a stated false-positive rate and alert on forced
re-authentications, so the trade stays visible.

---

## 7. What the app never does

| Never | Because |
| --- | --- |
| Store tokens outside hardware-backed storage | §3 |
| Open login in a WebView | §2 |
| Use a custom URL scheme for the callback | §1 |
| Log tokens, verifiers, or assertions | T1 Path C |
| Ship without a backup pin | §4 |
| Treat a risk score as a local allow/deny | The Thinker does not authorise — nothing downstream of it does either |
