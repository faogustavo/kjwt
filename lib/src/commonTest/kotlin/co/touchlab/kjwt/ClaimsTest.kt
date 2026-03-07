package co.touchlab.kjwt

import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.ext.audience
import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.expiration
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.getClaim
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuedAt
import co.touchlab.kjwt.ext.issuedAtOrNull
import co.touchlab.kjwt.ext.issuer
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.jwtId
import co.touchlab.kjwt.ext.jwtIdOrNull
import co.touchlab.kjwt.ext.notBefore
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.ext.subject
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.JwtPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ClaimsTest {

    private fun emptyClaims() = JwtPayload.Builder().build()

    private fun claimsWithSubject() = JwtPayload.Builder().apply {
        subject = "test-subject"
    }.build()

    // ---- Registered claims: missing throws MissingClaimException ----

    @Test
    fun issuer_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().issuer }
        assertEquals(JwtPayload.ISS, ex.claimName)
    }

    @Test
    fun subject_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().subject }
        assertEquals(JwtPayload.SUB, ex.claimName)
    }

    @Test
    fun audience_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().audience }
        assertEquals(JwtPayload.AUD, ex.claimName)
    }

    @Test
    fun expiration_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().expiration }
        assertEquals(JwtPayload.EXP, ex.claimName)
    }

    @Test
    fun notBefore_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().notBefore }
        assertEquals(JwtPayload.NBF, ex.claimName)
    }

    @Test
    fun issuedAt_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().issuedAt }
        assertEquals(JwtPayload.IAT, ex.claimName)
    }

    @Test
    fun jwtId_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().jwtId }
        assertEquals(JwtPayload.JTI, ex.claimName)
    }

    // ---- Registered claims: missing returns null ----

    @Test
    fun issuerOrNull_missing_returnsNull() {
        assertNull(emptyClaims().issuerOrNull)
    }

    @Test
    fun subjectOrNull_missing_returnsNull() {
        assertNull(emptyClaims().subjectOrNull)
    }

    @Test
    fun audienceOrNull_missing_returnsNull() {
        assertNull(emptyClaims().audienceOrNull)
    }

    @Test
    fun expirationOrNull_missing_returnsNull() {
        assertNull(emptyClaims().expirationOrNull)
    }

    @Test
    fun notBeforeOrNull_missing_returnsNull() {
        assertNull(emptyClaims().notBeforeOrNull)
    }

    @Test
    fun issuedAtOrNull_missing_returnsNull() {
        assertNull(emptyClaims().issuedAtOrNull)
    }

    @Test
    fun jwtIdOrNull_missing_returnsNull() {
        assertNull(emptyClaims().jwtIdOrNull)
    }

    // ---- Custom claims ----

    @Test
    fun getClaim_missing_throwsMissingClaimException() {
        val ex = assertFailsWith<MissingClaimException> { emptyClaims().getClaim<String>("role") }
        assertEquals("role", ex.claimName)
    }

    @Test
    fun getClaimOrNull_missing_returnsNull() {
        assertNull(emptyClaims().getClaimOrNull<String>("role"))
    }

    @Test
    fun getClaim_present_returnsValue() {
        val claims = claimsWithSubject()
        assertEquals("test-subject", claims.subject)
    }

    @Test
    fun getClaimOrNull_present_returnsValue() {
        val claims = claimsWithSubject()
        assertEquals("test-subject", claims.subjectOrNull)
    }
}
