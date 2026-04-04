package co.touchlab.kjwt.hardware

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.processor.JweProcessor
import kotlinx.coroutines.test.runTest
import java.security.KeyStore
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidKeyStoreEncryptionKeyTest {
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
    // JWE — RSA-OAEP with several content algorithms
    // -------------------------------------------------------------------------

    @Test
    fun jweRsaOaepA256GcmRoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep,
            contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
            keyId = "__kjwt_test_oaep",
        )
    }

    @Test
    fun jweRsaOaepA128CbcHs256RoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep,
            contentAlgorithm = EncryptionContentAlgorithm.A128CbcHs256,
            keyId = "__kjwt_test_oaep_cbc",
        )
    }

    @Test
    fun jweRsaOaep256A256GcmRoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep256,
            contentAlgorithm = EncryptionContentAlgorithm.A256GCM,
            keyId = "__kjwt_test_oaep256",
        )
    }

    @Test
    fun jweRsaOaep256A256CbcHs512RoundTrip() = runTest {
        assertJweRoundTrip(
            algorithm = EncryptionAlgorithm.RsaOaep256,
            contentAlgorithm = EncryptionContentAlgorithm.A256CbcHs512,
            keyId = "__kjwt_test_oaep256_cbc",
        )
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    // Dir uses a pre-shared symmetric key, which doesn't fit the hardware-backed
    // model — getInstance must return null since no Dir key has been stored.
    @Test
    fun dirAlgorithmReturnsNull() = runTest {
        assertNull(AndroidKeyStoreEncryptionKey.getInstance(EncryptionAlgorithm.Dir, null))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private suspend fun assertJweRoundTrip(
        algorithm: EncryptionAlgorithm,
        contentAlgorithm: EncryptionContentAlgorithm,
        keyId: String,
    ) {
        val processor = AndroidKeyStoreEncryptionKey.getOrCreateInstance(
            algorithm = algorithm,
            keyId = keyId,
        )
        assertIs<JweProcessor>(processor)

        val plaintext = "secret payload content".encodeToByteArray()
        val aad = "protected.header".encodeToByteArray()

        val result = processor.encrypt(plaintext, aad, contentAlgorithm)
        val decrypted = processor.decrypt(
            aad,
            result.encryptedKey,
            result.iv,
            result.ciphertext,
            result.tag,
            contentAlgorithm,
        )

        assertTrue(
            plaintext.contentEquals(decrypted),
            "Decrypted content must match original plaintext for ${algorithm.id}/${contentAlgorithm.id}",
        )
    }
}
