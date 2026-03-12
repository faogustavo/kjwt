package co.touchlab.kjwt

import co.touchlab.kjwt.exception.ExpiredJwtException
import co.touchlab.kjwt.exception.IncorrectClaimException
import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.exception.PrematureJwtException
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest

class ClaimsValidationTest {

    // ---- Expiration ----

    @Test
    fun parseExpiredToken_throwsExpiredJwtException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 1.hours) // expired 1 hour ago
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)
        }
    }

    @Test
    fun parseExpiredToken_containsClaimsInException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("expired-user")
            .expiration(Clock.System.now() - 1.hours)
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)
        }

        assertEquals("expired-user", ex.claims.subjectOrNull)
        assertNotNull(ex.claims.expirationOrNull)
        assertNotNull(ex.header)
    }

    @Test
    fun parseExpiredToken_withinClockSkew_passes() = runTest {
        val key = hs256Key()
        // Expired 30 seconds ago
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 30.seconds)
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // With 60-second skew, should pass
        Jwt.parser()
            .verifyWith(SigningAlgorithm.HS256, key)
            .clockSkew(60L)
            .build()
            .parseSigned(token) // should not throw
    }

    @Test
    fun parseExpiredToken_outsideClockSkew_throws() = runTest {
        val key = hs256Key()
        // Expired 120 seconds ago
        val token = Jwt.builder()
            .expiration(Clock.System.now() - 120.seconds)
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<ExpiredJwtException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .clockSkew(60L) // skew of 60s is not enough for 120s expired
                .build()
                .parseSigned(token)
        }
    }

    // ---- Not Before ----

    @Test
    fun parsePrematureToken_throwsPrematureJwtException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 1.hours) // not valid for another hour
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<PrematureJwtException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .build()
                .parseSigned(token)
        }
    }

    @Test
    fun parsePrematureToken_withinClockSkew_passes() = runTest {
        val key = hs256Key()
        // Not valid for another 30 seconds
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 30.seconds)
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // With 60-second skew, should pass
        Jwt.parser()
            .verifyWith(SigningAlgorithm.HS256, key)
            .clockSkew(60L)
            .build()
            .parseSigned(token) // should not throw
    }

    @Test
    fun parsePrematureToken_outsideClockSkew_throws() = runTest {
        val key = hs256Key()
        // Not valid for another 120 seconds
        val token = Jwt.builder()
            .notBefore(Clock.System.now() + 120.seconds)
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<PrematureJwtException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .clockSkew(60L)
                .build()
                .parseSigned(token)
        }
    }

    // ---- Issuer ----

    @Test
    fun requireIssuer_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("actual-issuer")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireIssuer("expected-issuer")
                .build()
                .parseSigned(token)
        }

        assertEquals("iss", ex.claimName)
        assertEquals("expected-issuer", ex.expected)
    }

    @Test
    fun requireIssuer_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        // Token with no issuer claim
        val token = Jwt.builder()
            .subject("someone")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireIssuer("expected-issuer")
                .build()
                .parseSigned(token)
        }

        assertEquals("iss", ex.claimName)
    }

    @Test
    fun requireIssuer_caseMismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("Auth.MyApp.io")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // Default comparison is case-sensitive
        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireIssuer("auth.myapp.io")
                .build()
                .parseSigned(token)
        }

        assertEquals("iss", ex.claimName)
        assertEquals("auth.myapp.io", ex.expected)
    }

    @Test
    fun requireIssuer_ignoreCase_passes() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("AUTH.MYAPP.IO")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // Should not throw — comparison is case-insensitive
        Jwt.parser()
            .verifyWith(SigningAlgorithm.HS256, key)
            .requireIssuer("auth.myapp.io", ignoreCase = true)
            .build()
            .parseSigned(token)
    }

    // ---- Subject ----

    @Test
    fun requireSubject_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("actual-subject")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireSubject("expected-subject")
                .build()
                .parseSigned(token)
        }

        assertEquals("sub", ex.claimName)
    }

    @Test
    fun requireSubject_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .issuer("issuer")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireSubject("expected-subject")
                .build()
                .parseSigned(token)
        }

        assertEquals("sub", ex.claimName)
    }

    @Test
    fun requireSubject_caseMismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("User-123")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // Subject comparison is case-sensitive
        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireSubject("user-123")
                .build()
                .parseSigned(token)
        }

        assertEquals("sub", ex.claimName)
    }

    // ---- Audience ----

    @Test
    fun requireAudience_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("actual-aud")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireAudience("expected-aud")
                .build()
                .parseSigned(token)
        }
    }

    @Test
    fun requireAudience_notInArray_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("aud1", "aud2")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireAudience("aud3")
                .build()
                .parseSigned(token)
        }
    }

    @Test
    fun requireAudience_caseMismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .audience("Mobile-App")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // Audience comparison is case-sensitive
        assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireAudience("mobile-app")
                .build()
                .parseSigned(token)
        }
    }

    @Test
    fun requireAudience_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireAudience("expected-aud")
                .build()
                .parseSigned(token)
        }

        assertEquals("aud", ex.claimName)
    }

    // ---- Custom required claims ----

    @Test
    fun requireCustomClaim_present_match_passes() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("role", "admin")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        // Should not throw
        Jwt.parser()
            .verifyWith(SigningAlgorithm.HS256, key)
            .requireClaim("role", "admin")
            .build()
            .parseSigned(token)
    }

    @Test
    fun requireCustomClaim_present_mismatch_throwsIncorrectClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .claim("role", "user")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<IncorrectClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireClaim("role", "admin")
                .build()
                .parseSigned(token)
        }

        assertEquals("role", ex.claimName)
        assertEquals("admin", ex.expected)
    }

    @Test
    fun requireCustomClaim_missing_throwsMissingClaimException() = runTest {
        val key = hs256Key()
        val token = Jwt.builder()
            .subject("user")
            .signWith(SigningAlgorithm.HS256, key)
            .compact()

        val ex = assertFailsWith<MissingClaimException> {
            Jwt.parser()
                .verifyWith(SigningAlgorithm.HS256, key)
                .requireClaim("role", "admin")
                .build()
                .parseSigned(token)
        }

        assertEquals("role", ex.claimName)
    }
}
