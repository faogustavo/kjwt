# Error Handling

All exceptions extend `JwtException`.

## Exception Reference

| Exception | Thrown when |
|---|---|
| `MalformedJwtException` | Token is not valid base64url, wrong number of parts, or payload is not valid JSON |
| `SignatureException` | JWS signature verification fails, or JWE decryption / authentication tag verification fails |
| `UnsupportedJwtException` | Unknown algorithm ID, or `alg=none` when `allowUnsecured` is `false` |
| `ExpiredJwtException` | Current time is past `exp` (accounting for clock skew). Carries `header` and `claims`. |
| `PrematureJwtException` | Current time is before `nbf` (accounting for clock skew). Carries `header` and `claims`. |
| `MissingClaimException` | A required claim (via `.requireIssuer()`, `.requireSubject()`, etc.) is absent from the token |
| `IncorrectClaimException` | A required claim is present but does not match the expected value. Carries `claimName`, `expected`, `actual`. |

## Handling Exceptions

```kotlin
import co.touchlab.kjwt.exception.*

try {
    val jws = parser.parseSignedClaims(token)
} catch (e: ExpiredJwtException) {
    // Token is expired ('exp' > now())
} catch (e: PrematureJwtException) {
    // Token is not yet valid ('nbf' < now())
} catch (e: SignatureException) {
    // Invalid signature or JWE authentication tag mismatch
} catch (e: MissingClaimException) {
    // Claim is not present in the token
} catch (e: IncorrectClaimException) {
    // Claim value does not match expected value defined in the parser
} catch (e: UnsupportedJwtException) {
    // Unknown algorithm or alg=none without allowUnsecured(true)
} catch (e: MalformedJwtException) {
    // Bad base64url, wrong part count, or invalid JSON
} catch (e: JwtException) {
    // Catch-all for any other KJWT error
}
```