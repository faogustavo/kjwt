package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.hardware.model.AndroidStrongBoxKeyPreference
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import kotlinx.coroutines.test.runTest
import java.security.KeyStore
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidKeyStoreSigningKeyTest {
    // Removes every key written by these tests from the Android Keystore.
    // Each test uses a keyId that starts with "__kjwt_test_" so cleanup is safe.
    @AfterTest
    fun cleanupKeystore() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList()
            .filter { it.startsWith("__kjwt_test_") }
            .forEach { ks.deleteEntry(it) }
    }

    // -------------------------------------------------------------------------
    // JWS — HMAC
    // -------------------------------------------------------------------------

    @Test
    fun jwsHs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS256, keyId = "__kjwt_test_hs256")
    }

    @Test
    fun jwsHs384SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS384, keyId = "__kjwt_test_hs384")
    }

    @Test
    fun jwsHs512SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.HS512, keyId = "__kjwt_test_hs512")
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PKCS#1 v1.5  (one variant — key generation is slow on emulators)
    // -------------------------------------------------------------------------

    @Test
    fun jwsRs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.RS256, keyId = "__kjwt_test_rs256")
    }

    // -------------------------------------------------------------------------
    // JWS — RSA PSS  (requires API 23+, which is this module's minSdk)
    // -------------------------------------------------------------------------

    @Test
    fun jwsPs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.PS256, keyId = "__kjwt_test_ps256")
    }

    // -------------------------------------------------------------------------
    // JWS — ECDSA  (validates DER↔P1363 conversion for all three curves)
    // -------------------------------------------------------------------------

    @Test
    fun jwsEs256SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES256, keyId = "__kjwt_test_es256")
    }

    @Test
    fun jwsEs384SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES384, keyId = "__kjwt_test_es384")
    }

    @Test
    fun jwsEs512SignAndVerify() = runTest {
        assertJwsRoundTrip(SigningAlgorithm.ES512, keyId = "__kjwt_test_es512")
    }

    // -------------------------------------------------------------------------
    // StrongBox
    // -------------------------------------------------------------------------

    // StrongBox.Preferred must never throw — on devices without StrongBox it
    // silently falls back to the default TEE-backed keystore.
    @Test
    fun strongBoxPreferredFallsBackGracefully() = runTest {
        val processor = AndroidKeyStoreSigningKey.getOrCreateInstance(
            algorithm = SigningAlgorithm.ES256,
            keyId = "__kjwt_test_sb_preferred",
            strongBoxPreference = AndroidStrongBoxKeyPreference.Preferred,
        )
        assertIs<JwsProcessor>(processor)

        val data = "strongbox-fallback-test".encodeToByteArray()
        val sig = processor.sign(data)
        assertTrue(processor.verify(data, sig))
    }

    // StrongBox.None must behave identically to the default.
    @Test
    fun strongBoxNoneWorksNormally() = runTest {
        assertJwsRoundTrip(
            algorithm = SigningAlgorithm.ES256,
            keyId = "__kjwt_test_sb_none",
            strongBoxPreference = AndroidStrongBoxKeyPreference.None,
        )
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    // alg=none must return null — getInstance never auto-creates keys and
    // no none-algorithm key has ever been stored in the keystore.
    @Test
    fun noneAlgorithmReturnsNull() = runTest {
        assertNull(AndroidKeyStoreSigningKey.getInstance(SigningAlgorithm.None, null))
    }

    // When no key exists for a given keyId, getInstance must return null.
    @Test
    fun noAutoGenerationReturnsNull() = runTest {
        assertNull(
            AndroidKeyStoreSigningKey.getInstance(SigningAlgorithm.ES256, "__kjwt_test_missing"),
        )
    }

    // A tampered payload must not verify successfully.
    @Test
    fun tamperedDataFailsVerification() = runTest {
        val processor = AndroidKeyStoreSigningKey.getOrCreateInstance(
            algorithm = SigningAlgorithm.ES256,
            keyId = "__kjwt_test_tamper",
        )

        val original = "header.payload".encodeToByteArray()
        val signature = processor.sign(original)

        assertFalse(
            processor.verify("header.modified".encodeToByteArray(), signature),
            "Tampered data must not pass signature verification",
        )
    }

    // A truncated or corrupted signature must not verify successfully.
    @Test
    fun corruptedSignatureFailsVerification() = runTest {
        val processor = AndroidKeyStoreSigningKey.getOrCreateInstance(
            algorithm = SigningAlgorithm.HS256,
            keyId = "__kjwt_test_corrupt",
        )

        val data = "header.payload".encodeToByteArray()
        val signature = processor.sign(data)
        val corrupted = signature.copyOf(signature.size - 1) // truncate last byte

        assertFalse(
            processor.verify(data, corrupted),
            "Corrupted signature must not pass verification",
        )
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private suspend fun assertJwsRoundTrip(
        algorithm: SigningAlgorithm,
        keyId: String,
        strongBoxPreference: AndroidStrongBoxKeyPreference = AndroidStrongBoxKeyPreference.None,
    ) {
        val processor = AndroidKeyStoreSigningKey.getOrCreateInstance(
            algorithm = algorithm,
            keyId = keyId,
            strongBoxPreference = strongBoxPreference,
        )
        assertNotNull(processor)
        assertIs<JwsProcessor>(processor)

        val data = "header.payload".encodeToByteArray()
        val signature = processor.sign(data)

        assertTrue(
            processor.verify(data, signature),
            "Valid signature for ${algorithm.id} should verify successfully",
        )
        assertFalse(
            processor.verify("header.other".encodeToByteArray(), signature),
            "Signature for ${algorithm.id} should not verify against different data",
        )
    }
}
