package co.touchlab.kjwt.hardware.helpers

import co.touchlab.kjwt.model.algorithm.Jwa
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate

internal object AndroidKeyStoreManager {
    private const val DEFAULT_JWE_KEY_ALIAS = "__kjwt_default_%s_key__"

    private val keystore: KeyStore
        get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun getKey(keyId: String): KeyStore.Entry? = keystore.getEntry(keyId, null)

    /**
     * Fetches the private key and certificate without going through [KeyStore.getEntry].
     *
     * On API 33–35, `getEntry` throws `IllegalArgumentException("private key algorithm does not match
     * algorithm of public key in end entity certificate")` for Ed25519 keys. The check lives in the
     * [KeyStore.PrivateKeyEntry] constructor in libcore, which requires the private key's algorithm name
     * to equal the algorithm name of the public key in the first certificate:
     * https://android.googlesource.com/platform/libcore/+/refs/heads/android15-release/ojluni/src/main/java/java/security/KeyStore.java
     * The AndroidKeyStore provider on those releases returns mismatching names for Ed25519 keys, so the
     * check fails. Retrieving the key and certificate separately bypasses the check.
     */
    fun getPrivateKeyAndCertificate(keyId: String): Pair<PrivateKey, Certificate>? {
        val privateKey = keystore.getKey(keyId, null) as? PrivateKey ?: return null
        val certificate = keystore.getCertificate(keyId) ?: return null
        return privateKey to certificate
    }

    fun containsKey(keyId: String): Boolean = keystore.containsAlias(keyId)

    fun getDefaultKey(key: String?, algorithm: Jwa): String = key ?: DEFAULT_JWE_KEY_ALIAS.format(algorithm.id)
}
