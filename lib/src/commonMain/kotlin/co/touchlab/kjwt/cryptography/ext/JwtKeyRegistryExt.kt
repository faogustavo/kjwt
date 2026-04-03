package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinEncryptionProcessor
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinIntegrityProcessor
import co.touchlab.kjwt.cryptography.registry.EncryptionKey
import co.touchlab.kjwt.cryptography.registry.SigningKey
import co.touchlab.kjwt.model.registry.JwtKeyRegistry
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor

/**
 * Registers a [SigningKey] in this registry, merging it with any existing processor for the same
 * algorithm and key ID.
 *
 * @param key the signing key to register
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtKeyRegistry.registerSigningKey(key: SigningKey) {
    registerJwsProcessor(findBestJwsProcessorAndMerge(key))
}

/**
 * Looks up the existing [JwsProcessor] for the algorithm and key ID in [key]'s identifier, then
 * creates a [CryptographyKotlinIntegrityProcessor] that merges [key] with that existing processor.
 *
 * @param key the signing key whose algorithm and key ID are used to locate an existing processor
 * @return a [JwsProcessor] incorporating the new key, merged with any previously registered key
 * @throws IllegalArgumentException if a signing key of the same type is already registered for
 *   the same algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtKeyRegistry.findBestJwsProcessorAndMerge(
    key: SigningKey,
): JwsProcessor {
    val previous = findBestJwsProcessor(key.identifier.algorithm, key.identifier.keyId)
    return try {
        CryptographyKotlinIntegrityProcessor(key, previous)
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException(
            "Signing key for '${key.identifier.algorithm.id}' " +
                "identified by '${key.identifier.keyId}' already registered",
            error,
        )
    }
}

/**
 * Registers an [EncryptionKey] in this registry, merging it with any existing processor for the
 * same algorithm and key ID.
 *
 * @param key the encryption key to register
 * @throws IllegalArgumentException if a key of the same type is already registered for the same
 *   algorithm and key ID
 */
@OptIn(DelicateKJWTApi::class)
public fun JwtKeyRegistry.registerEncryptionKey(key: EncryptionKey) {
    registerJweProcessor(findBestJweProcessorAndMerge(key))
}

/**
 * Looks up the existing [JweProcessor] for the algorithm and key ID in [key]'s identifier, then
 * creates a [CryptographyKotlinEncryptionProcessor] that merges [key] with that existing processor.
 *
 * @param key the encryption key whose algorithm and key ID are used to locate an existing processor
 * @return a [JweProcessor] incorporating the new key, merged with any previously registered key
 * @throws IllegalArgumentException if an encryption key of the same type is already registered for
 *   the same algorithm and key ID
 */
@DelicateKJWTApi
public fun JwtKeyRegistry.findBestJweProcessorAndMerge(
    key: EncryptionKey,
): JweProcessor {
    val previous = findBestJweProcessor(key.identifier.algorithm, key.identifier.keyId)
    return try {
        CryptographyKotlinEncryptionProcessor(key, previous)
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException(
            "Encryption key for '${key.identifier.algorithm.id}' " +
                "identified by '${key.identifier.keyId}' already registered",
            error,
        )
    }
}
