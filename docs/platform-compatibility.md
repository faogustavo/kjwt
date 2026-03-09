# Platform Compatibility

KJWT delegates all cryptographic operations to [`cryptography-kotlin`](https://github.com/whyoleg/cryptography-kotlin). The provider used at runtime determines which algorithms are available. This page documents which providers are used on each platform and which KJWT algorithms work with each provider.

---

## Supported Targets and Providers

| Platform group | Targets | Optimal provider | Explicit alternatives |
|---|---|---|---|
| JVM | `jvm` | JDK | — |
| JS / wasmJs | `js` (node/browser), `wasmJs` (node/browser) | WebCrypto | — |
| Apple | `iosArm64`, `iosX64`, `iosSimulatorArm64`, `macosX64`, `macosArm64`, `watchosX64`, `watchosArm32`, `watchosArm64`, `watchosSimulatorArm64`, `watchosDeviceArm64`, `tvosX64`, `tvosArm64`, `tvosSimulatorArm64` | CryptoKit (primary) + Apple (fallback) | Apple, CryptoKit, OpenSSL3 (prebuilt) |
| Linux / MinGW | `linuxX64`, `linuxArm64`, `mingwX64` | OpenSSL3 | — |
| Android Native | `androidNativeX64`, `androidNativeX86`, `androidNativeArm64`, `androidNativeArm32` | OpenSSL3 (prebuilt) | — |
| wasmWasi | `wasmWasi` | **None** | — |

The recommended dependency is `cryptography-provider-optimal`, which auto-selects the best available provider for each platform at runtime.

---

## Algorithm Support Per Provider

| KJWT algorithm | Primitive | JDK | WebCrypto | Apple | CryptoKit | OpenSSL3 |
|---|---|---|---|---|---|---|
| HS256 / HS384 / HS512 | HMAC | ✅ | ✅ | ✅ | ✅ | ✅ |
| RS256 / RS384 / RS512 | RSA-PKCS1-v1_5 | ✅ | ✅ | ✅ | ❌ | ✅ |
| PS256 / PS384 / PS512 | RSA-PSS | ✅ | ✅ | ✅ | ❌ | ✅ |
| ES256 / ES384 / ES512 | ECDSA | ✅ | ✅ | ✅ | ✅ | ✅ |
| JweKeyAlgorithm.RsaOaep / RsaOaep256 | RSA-OAEP | ✅ | ✅ | ✅ | ❌ | ✅ |
| A128GCM / A192GCM / A256GCM | AES-GCM | ✅ | ✅ | ❌ | ✅ | ✅ |
| A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512 | AES-CBC + HMAC | ✅ | ✅ | ✅ | ❌ | ✅ |

---

## Apple Targets in Depth

### Using `cryptography-provider-optimal` (recommended)

The optimal provider uses **CryptoKit as primary** with **Apple (CommonCrypto) as fallback**. This combination covers all KJWT algorithms:

- AES-GCM → routed to CryptoKit ✅
- AES-CBC + HMAC → routed to Apple (CommonCrypto) ✅
- RSA (OAEP, PSS, PKCS1) → routed to Apple ✅
- HMAC, ECDSA → available in either provider ✅

**All KJWT algorithms work on Apple targets when using `cryptography-provider-optimal`.**

### Using a single explicit provider on Apple

If you configure only one provider explicitly, some algorithms will fail at runtime:

**Apple provider only** (`cryptography-provider-apple`):
- `A128GCM`, `A192GCM`, `A256GCM` — ❌ AES-GCM is not available in CommonCrypto; JWE with GCM content algorithms will throw at runtime
- All other KJWT algorithms ✅

**CryptoKit provider only** (`cryptography-provider-cryptokit`):
- `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` — ❌
- `RS256` / `RS384` / `RS512`, `PS256` / `PS384` / `PS512` — ❌
- `JweKeyAlgorithm.RsaOaep`, `JweKeyAlgorithm.RsaOaep256` — ❌
- Only `HS256` / `HS384` / `HS512` and `ES256` / `ES384` / `ES512` work ✅

**OpenSSL3 prebuilt** (`cryptography-provider-openssl3-prebuilt`):
- All KJWT algorithms ✅
- Suitable when you need a single consistent provider across Apple, Linux, and Android Native targets

---

## wasmWasi

No `cryptography-kotlin` provider supports the `wasmWasi` target. KJWT compiles for this target, but **all signing and encryption operations will throw at runtime** because no cryptography provider can be registered.

If you include KJWT in a wasmWasi project, the library is effectively non-functional for cryptographic operations.

---

## Recommendation Summary

| Scenario | Recommendation |
|---|---|
| All platforms, full algorithm support | Use `cryptography-provider-optimal` |
| Apple, need all algorithms | Use `cryptography-provider-optimal` (CryptoKit + Apple fallback) |
| Apple, only HS* and ES* | `cryptography-provider-cryptokit` is sufficient |
| Linux / Android Native / MinGW | `cryptography-provider-optimal` selects OpenSSL3 automatically |
| wasmWasi | KJWT crypto operations are not supported on this target |

For most projects, simply adding `cryptography-provider-optimal` covers all platforms with no additional configuration.
