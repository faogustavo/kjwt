package co.touchlab.kjwt.jwk

import co.touchlab.kjwt.model.jwk.Jwk
import co.touchlab.kjwt.model.jwk.JwkSet
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwkSetTest {

    private val rsaPublicKey = Jwk.Rsa(n = "n", e = "AQAB", kid = "rsa-pub", use = "sig")
    private val rsaPrivateKey = Jwk.Rsa(n = "n", e = "AQAB", d = "d", p = "p", q = "q", dp = "dp", dq = "dq", qi = "qi", kid = "rsa-priv", use = "sig")
    private val ecPublicKey = Jwk.Ec(crv = "P-256", x = "x", y = "y", kid = "ec-pub", use = "enc")
    private val octKey = Jwk.Oct(k = "key", kid = "hmac", use = "sig")

    private val jwks = JwkSet(listOf(rsaPublicKey, rsaPrivateKey, ecPublicKey, octKey))

    @Test
    fun findById_returnsMatchingKey() {
        assertEquals(rsaPublicKey, jwks.findById("rsa-pub"))
        assertEquals(ecPublicKey, jwks.findById("ec-pub"))
        assertEquals(octKey, jwks.findById("hmac"))
    }

    @Test
    fun findById_returnsNullWhenNotFound() {
        assertNull(jwks.findById("nonexistent"))
    }

    @Test
    fun findByUse_returnsAllMatchingKeys() {
        val sigKeys = jwks.findByUse("sig")
        assertEquals(3, sigKeys.size)
        assertTrue(sigKeys.contains(rsaPublicKey))
        assertTrue(sigKeys.contains(rsaPrivateKey))
        assertTrue(sigKeys.contains(octKey))
    }

    @Test
    fun findByUse_enc_returnsEcKey() {
        val encKeys = jwks.findByUse("enc")
        assertEquals(1, encKeys.size)
        assertEquals(ecPublicKey, encKeys[0])
    }

    @Test
    fun publicKeys_filtersOutPrivateKeyMaterial() {
        val publicJwks = jwks.publicKeys()
        // rsaPublicKey + ecPublicKey = 2; rsaPrivateKey and octKey are excluded
        assertEquals(2, publicJwks.keys.size)
        assertTrue(!publicJwks.keys.contains(rsaPrivateKey))
        assertTrue(!publicJwks.keys.contains(octKey))  // oct keys are always private
        assertTrue(publicJwks.keys.contains(rsaPublicKey))
        assertTrue(publicJwks.keys.contains(ecPublicKey))
    }

    @Test
    fun emptyJwks_publicKeysIsEmpty() {
        val empty = JwkSet(emptyList())
        assertEquals(0, empty.publicKeys().keys.size)
    }
}