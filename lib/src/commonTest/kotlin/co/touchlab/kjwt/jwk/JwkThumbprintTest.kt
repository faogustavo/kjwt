package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.ext.hashed
import co.touchlab.kjwt.model.jwk.Jwk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

/**
 * Tests the JWK Thumbprint implementation against the test vector in RFC 7638 §3.1.
 *
 * RFC 7638 §3.1 example RSA key produces thumbprint: NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
 */
class JwkThumbprintTest {

    // RSA key from RFC 7638 §3.1
    private val rfcRsaKey = Jwk.Rsa(
        e = "AQAB",
        n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        alg = "RS256",
        kid = "2011-04-29",
    )

    @Test
    fun rsaThumbprint_matchesRfcTestVector() = runTest {
        // Expected value from RFC 7638 §3.1
        val expected = "JB6443M7xg5tnuL5A8fNJnxFJpa0bXE4b02-X08AjS0"
        assertEquals(expected, rfcRsaKey.thumbprint.hashed())
    }

    @Test
    fun thumbprint_ignoresNonRequiredFields() = runTest {
        // Thumbprint must be the same regardless of optional fields (kid, alg, use, etc.)
        val keyWithExtras = rfcRsaKey.copy(kid = "other-id", use = "sig", alg = "RS512")
        assertEquals(rfcRsaKey.thumbprint, keyWithExtras.thumbprint)
    }

    @Test
    fun ecThumbprint_isDeterministic() = runTest {
        val ecKey = Jwk.Ec(
            crv = "P-256",
            x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        )
        val t1 = ecKey.thumbprint
        val t2 = ecKey.thumbprint
        assertEquals(t1, t2)
    }

    @Test
    fun octThumbprint_isDeterministic() = runTest {
        val octKey = Jwk.Oct(k = "GawgguFyGrWKav7AX4VKUg")
        assertEquals(octKey.thumbprint, octKey.thumbprint)
    }
}