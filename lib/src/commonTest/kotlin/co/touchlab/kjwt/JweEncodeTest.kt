@file:OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)

package co.touchlab.kjwt

import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class JweEncodeTest {

    // ---- Dir + GCM round-trips ----

    @Test
    fun encryptDir_A128GCM_roundTrip() = runTest {
        val cek = aesSimpleKey(128)
        val token = Jwt.builder()
            .subject("a128gcm-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a128gcm-user", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptDir_A192GCM_roundTrip() = runTest {
        val cek = aesSimpleKey(192)
        val token = Jwt.builder()
            .subject("a192gcm-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A192GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a192gcm-user", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptDir_A256GCM_roundTrip() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("a256gcm-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a256gcm-user", jwe.payload.subjectOrNull)
    }

    // ---- Dir + CBC-HMAC round-trips ----

    @Test
    fun encryptDir_A128CbcHs256_roundTrip() = runTest {
        val cek = aesSimpleKey(256) // 32 bytes: 16 MAC + 16 ENC
        val token = Jwt.builder()
            .subject("a128cbc-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128CbcHs256)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a128cbc-user", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptDir_A192CbcHs384_roundTrip() = runTest {
        val cek = aesSimpleKey(384) // 48 bytes: 24 MAC + 24 ENC
        val token = Jwt.builder()
            .subject("a192cbc-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A192CbcHs384)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a192cbc-user", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptDir_A256CbcHs512_roundTrip() = runTest {
        val cek = aesSimpleKey(512) // 64 bytes: 32 MAC + 32 ENC
        val token = Jwt.builder()
            .subject("a256cbc-user")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256CbcHs512)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.Dir, cek)
            .build()
            .parseEncrypted(token)

        assertEquals("a256cbc-user", jwe.payload.subjectOrNull)
    }

    // ---- RSA-OAEP (SHA-1) round-trips ----

    @Test
    fun encryptRsaOaep_A128GCM_roundTrip() = runTest {
        val keyPair = rsaOaepKeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep-a128gcm")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A128GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep-a128gcm", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptRsaOaep_A256GCM_roundTrip() = runTest {
        val keyPair = rsaOaepKeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep-a256gcm")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep-a256gcm", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptRsaOaep_A256CbcHs512_roundTrip() = runTest {
        val keyPair = rsaOaepKeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep-cbc512")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep, EncryptionContentAlgorithm.A256CbcHs512)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep-cbc512", jwe.payload.subjectOrNull)
    }

    // ---- RSA-OAEP-256 (SHA-256) round-trips ----

    @Test
    fun encryptRsaOaep256_A128GCM_roundTrip() = runTest {
        val keyPair = rsaOaep256KeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep256-a128gcm")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A128GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep256-a128gcm", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptRsaOaep256_A256GCM_roundTrip() = runTest {
        val keyPair = rsaOaep256KeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep256-a256gcm")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep256-a256gcm", jwe.payload.subjectOrNull)
    }

    @Test
    fun encryptRsaOaep256_A256CbcHs512_roundTrip() = runTest {
        val keyPair = rsaOaep256KeyPair()
        val token = Jwt.builder()
            .subject("rsa-oaep256-cbc512")
            .encryptWith(keyPair.publicKey, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256CbcHs512)
            .compact()

        val jwe = Jwt.parser()
            .decryptWith(EncryptionAlgorithm.RsaOaep256, keyPair.privateKey)
            .build()
            .parseEncrypted(token)

        assertEquals("rsa-oaep256-cbc512", jwe.payload.subjectOrNull)
    }

    // ---- Structure / header checks ----

    @Test
    fun encryptDir_A256GCM_compactHasFiveParts() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val parts = token.split('.')
        assertEquals(5, parts.size, "JWE compact token must have exactly 5 parts")
    }

    @Test
    fun encryptDir_A256GCM_headerContainsAlgAndEnc() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val headerJson = decodeTokenHeader(token)
        assertTrue(headerJson.contains("\"alg\":\"dir\""), "Header must contain alg=dir, got: $headerJson")
        assertTrue(headerJson.contains("\"enc\":\"A256GCM\""), "Header must contain enc=A256GCM, got: $headerJson")
    }

    @Test
    fun encryptDir_A256GCM_encryptedKeySegmentEmpty() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val encryptedKeyPart = token.split('.')[1]
        assertEquals("", encryptedKeyPart, "For Dir algorithm, encrypted key segment must be empty")
    }

    @Test
    fun encryptDir_A256GCM_ivLength() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val ivBytes = decodeBase64Url(token.split('.')[2])
        assertEquals(12, ivBytes.size, "AES-GCM IV must be 12 bytes")
    }

    @Test
    fun encryptDir_A128CbcHs256_ivLength() = runTest {
        val cek = aesSimpleKey(256) // 32 bytes for A128CBC-HS256
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A128CbcHs256)
            .compact()

        val ivBytes = decodeBase64Url(token.split('.')[2])
        assertEquals(16, ivBytes.size, "AES-CBC IV must be 16 bytes")
    }

    @Test
    fun encryptDir_A256GCM_tagLength() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val tagBytes = decodeBase64Url(token.split('.')[4])
        assertEquals(16, tagBytes.size, "AES-GCM auth tag must be 16 bytes")
    }

    @Test
    fun encryptDir_A256GCM_withKid() = runTest {
        val cek = aesSimpleKey(256)
        val token = Jwt.builder()
            .keyId("enc-key-id")
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        val headerJson = decodeTokenHeader(token)
        assertTrue(headerJson.contains("\"kid\":\"enc-key-id\""), "Header must contain kid, got: $headerJson")
    }

    // ---- Uniqueness ----

    @Test
    fun encryptDir_A256GCM_twoCallsProduceDifferentTokens() = runTest {
        val cek = aesSimpleKey(256)
        val t1 = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()
        val t2 = Jwt.builder()
            .subject("test")
            .encryptWith(cek, EncryptionAlgorithm.Dir, EncryptionContentAlgorithm.A256GCM)
            .compact()

        assertNotEquals(t1, t2, "Each JWE encryption call must produce a unique token (random IV)")
    }
}
