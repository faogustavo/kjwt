# Usage Guide

All signing, verifying, encrypting, and decrypting operations are `suspend` functions and must be called from a coroutine.

## Quick Start

### Sign a JWT (JWS)

```kotlin
import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import co.touchlab.kjwt.model.JwtInstance
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

val jws: JwtInstance.Jws = Jwt.builder()
    .issuer("my-app")
    .subject("user-123")
    .audience("api")
    .expiresIn(1.hours)
    .issuedAt(Clock.System.now())
    .signWith(JwsAlgorithm.HS256, hmacKey)

val token: String = jws.compact()
```

### Verify / Parse a JWS

```kotlin
val parser = Jwt.parser()
    .verifyWith(JwsAlgorithm.HS256, hmacKey)
    .requireIssuer("my-app")
    .requireAudience("api")
    .clockSkew(30L) // seconds of tolerance
    .build()

val jws = parser.parseSigned(token)
val subject: String = jws.payload.subject
```

### Encrypt a JWT (JWE)

```kotlin
val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .expiresIn(1.hours)
    .encryptWith(rsaPublicKey, JweKeyAlgorithm.RsaOaep256, JweContentAlgorithm.A256GCM)

val token: String = jwe.compact()
```

### Decrypt a JWE

```kotlin
val parser = Jwt.parser()
    .decryptWith(JweKeyAlgorithm.RsaOaep256, rsaPrivateKey)
    .build()

val jwe = parser.parseEncrypted(token)
val subject: String = jwe.payload.subject
```

---

## Standard Claims

All seven RFC 7519 registered claims are supported via the builder:

```kotlin
val jws: JwtInstance.Jws = Jwt.builder()
    .issuer("my-app")                           // iss
    .subject("user-123")                        // sub
    .audience("api", "admin")                   // aud (multiple → JSON array)
    .expiration(Clock.System.now() + 1.hours)   // exp (absolute Instant)
    .expiresIn(1.hours)                         // exp (convenience: now + duration)
    .notBefore(Clock.System.now())              // nbf (absolute Instant)
    .notBeforeNow()                             // nbf (convenience: now)
    .issuedAt(Clock.System.now())               // iat
    .issuedNow()                                // iat (convenience: now)
    .id("unique-token-id")                      // jti
    .randomId()                                 // jti (convenience: random UUID, @ExperimentalUuidApi)
    .signWith(JwsAlgorithm.HS256, hmacKey)

val token: String = jws.compact()
```

## Custom Claims

```kotlin
import kotlinx.serialization.json.JsonPrimitive

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    // reified generic - most convenient
    .claim("role", "admin")
    .claim("permissions", listOf("read", "write"))
    // explicit serializer
    .claim("metadata", MyMetadata.serializer(), MyMetadata(version = 2))
    // raw JsonElement
    .claim("raw", JsonPrimitive(42))
    .signWith(JwsAlgorithm.HS256, hmacKey)

val token: String = jws.compact()
```

## Header Parameters

```kotlin
val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .keyId("key-2024-01")                       // kid header parameter
    .header {
        type = "JWT"                            // typ (default: "JWT")
        contentType = "application/json"        // cty
    }
    .signWith(JwsAlgorithm.RS256, rsaPrivateKey)

val token: String = jws.compact()
```

## Parsing Claims

Access standard claims via extension properties. Mandatory variants throw `MissingClaimException` if the claim is absent; `OrNull` variants return `null`:

```kotlin
val payload = jws.payload

// Mandatory - throws MissingClaimException if absent
val iss: String       = payload.issuer
val sub: String       = payload.subject
val aud: Set<String>  = payload.audience
val exp: Instant      = payload.expiration
val nbf: Instant      = payload.notBefore
val iat: Instant      = payload.issuedAt
val jti: String       = payload.jwtId

// Optional - null if absent
val issOrNull: String? = payload.issuerOrNull
// ... same pattern for all claims
```

Access custom claims via `getClaim` / `getClaimOrNull`:

```kotlin
val role: String  = payload.getClaim<String>("role")
val role: String? = payload.getClaimOrNull<String>("role")
```

## Claim Validation

Configure required claims on the parser; any failure throws an appropriate exception:

```kotlin
val parser = Jwt.parser()
    .verifyWith(JwsAlgorithm.ES256, ecPublicKey)
    .requireIssuer("my-app")           // throws IncorrectClaimException on mismatch
    .requireSubject("user-123")
    .requireAudience("api")
    .require("role", "admin")          // generic claim equality check
    .clockSkew(30L)                    // seconds of exp/nbf tolerance
    .build()
```

`exp` and `nbf` are validated automatically. No extra configuration is needed.

## Unsecured JWTs (`alg=none`)

Unsecured JWTs are rejected by default. There are two distinct opt-in mechanisms:

### `allowUnsecured(true)` — accept `alg=none` tokens

Permits tokens where `alg=none` was used at creation time. All other algorithms still require a key configured via `verifyWith()`.

```kotlin
// Create an unsecured JWT
val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .signWith(JwsAlgorithm.None)

val token: String = jws.compact()

// Parse — only alg=none tokens are accepted without a key;
// signed tokens still require verifyWith()
val parser = Jwt.parser()
    .allowUnsecured(true)
    .build()

val parsed = parser.parseSigned(token)
```

### `noVerify()` — skip signature verification entirely

Accepts any token regardless of algorithm without verifying its signature. Use only in contexts where authenticity is not required (e.g. inspecting an already-trusted token's claims).

```kotlin
val parser = Jwt.parser()
    .noVerify()
    .build()

// Parses successfully even if the token was signed with HS256/RS256/etc.
// — the signature is NOT checked
val jws = parser.parseSigned(signedToken)
```

## Auto-Detect JWS vs JWE

When you don't know whether a token is signed or encrypted, use `parse` which detects by part count (3 = JWS, 5 = JWE):

```kotlin
val instance: JwtInstance = parser.parse(token)

when (instance) {
    is JwtInstance.Jws -> println("Signed, subject=${instance.payload.subject}")
    is JwtInstance.Jwe -> println("Encrypted, subject=${instance.payload.subject}")
}
```

## Custom Payload Types

Implement a plain `@Serializable` data class. Use `@SerialName` to map fields to JWT claim names. Fields should have default values so deserialization works when a claim is absent. Unmapped claims are silently ignored.

You can reference standard claim name constants from `JwtPayload.SUB`, `JwtPayload.ISS`, etc.

```kotlin
import co.touchlab.kjwt.model.JwtPayload
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class UserClaims(
    @SerialName(JwtPayload.SUB) val subject: String? = null,
    @SerialName("role") val role: String? = null,
    @SerialName("level") val level: Int? = null,
)
```

Parse using `parseSigned` (or `parseEncrypted`), then call `getPayload<T>()` on the result:

```kotlin
val jws: JwtInstance.Jws = parser.parseSigned(token)
val payload: UserClaims = jws.getPayload<UserClaims>()
println(payload.role)
println(payload.subject)
```

`getPayload<T>()` is available on both `JwtInstance.Jws` and `JwtInstance.Jwe`.

## JWE with Direct Key (`dir`)

For symmetric encryption where the key is used directly as the CEK (no key wrapping):

```kotlin
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.ext.encryptWith  // extension for ByteArray / String keys

// Encrypt - key is the raw CEK bytes (must match content algorithm key size)
val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .encryptWith(cekBytes, JweKeyAlgorithm.Dir, JweContentAlgorithm.A256GCM)

val token: String = jwe.compact()

// Decrypt
val parser = Jwt.parser()
    .decryptWith(JweKeyAlgorithm.Dir, SimpleKey(cekBytes))
    .build()

val jwe = parser.parseEncrypted(token)
```
