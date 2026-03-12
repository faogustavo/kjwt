package co.touchlab.kjwt

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

    // ---- Registered claims: missing throws NullPointerException ----

    @Test
    fun issuer_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().issuer }
    }

    @Test
    fun subject_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().subject }
    }

    @Test
    fun audience_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().audience }
    }

    @Test
    fun expiration_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().expiration }
    }

    @Test
    fun notBefore_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().notBefore }
    }

    @Test
    fun issuedAt_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().issuedAt }
    }

    @Test
    fun jwtId_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().jwtId }
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
    fun getClaim_missing_throwsNullPointerException() {
        assertFailsWith<NullPointerException> { emptyClaims().getClaim<String>("role") }
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
