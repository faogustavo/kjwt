package co.touchlab.kjwt.processor

import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.JweEncryptResult

/**
 * Core abstraction for JWE (encrypted JWT) key encryption and decryption.
 *
 * Combines the [Encryptor] and [Decryptor] functional interfaces and associates them with an
 * [EncryptionAlgorithm] and an optional key ID. Implementations are supplied to
 * [co.touchlab.kjwt.builder.JwtBuilder] for token encryption and to
 * [co.touchlab.kjwt.parser.JwtParserBuilder] for token decryption.
 *
 * @see Encryptor
 * @see Decryptor
 */
public interface JweProcessor : Encryptor, Decryptor {
    /** The JWE key-encryption algorithm this processor implements. */
    public val algorithm: EncryptionAlgorithm

    /** The optional key ID (`kid`) associated with the key material used by this processor. */
    public val keyId: String?
}

/**
 * Functional interface for encrypting a content encryption key (CEK) and the token payload.
 *
 * @see JweProcessor
 */
public fun interface Encryptor {
    /**
     * Encrypts [data] using the given [contentAlgorithm] and returns the full JWE encryption result.
     *
     * @param data the plaintext payload bytes to encrypt
     * @param aad the additional authenticated data (the ASCII encoding of the JWE Protected Header)
     * @param contentAlgorithm the content encryption algorithm to use for encrypting [data]
     * @return the [JweEncryptResult] containing the encrypted key, IV, ciphertext, and authentication tag
     */
    public suspend fun encrypt(
        data: ByteArray,
        aad: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): JweEncryptResult
}

/**
 * Functional interface for decrypting a JWE token payload.
 *
 * @see JweProcessor
 */
public fun interface Decryptor {
    /**
     * Decrypts and authenticates the JWE token components, returning the plaintext payload bytes.
     *
     * @param aad the additional authenticated data (the ASCII encoding of the JWE Protected Header)
     * @param encryptedKey the encrypted content encryption key bytes
     * @param iv the initialization vector bytes
     * @param data the ciphertext bytes to decrypt
     * @param tag the authentication tag bytes
     * @param contentAlgorithm the content encryption algorithm used to encrypt the payload
     * @return the decrypted plaintext payload bytes
     * @throws co.touchlab.kjwt.exception.SignatureException if authentication tag verification fails
     */
    public suspend fun decrypt(
        aad: ByteArray,
        encryptedKey: ByteArray,
        iv: ByteArray,
        data: ByteArray,
        tag: ByteArray,
        contentAlgorithm: EncryptionContentAlgorithm,
    ): ByteArray
}
