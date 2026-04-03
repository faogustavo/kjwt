package co.touchlab.kjwt.cryptography.ext

import co.touchlab.kjwt.annotations.DelicateKJWTApi
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinEncryptionProcessor
import co.touchlab.kjwt.cryptography.processors.CryptographyKotlinIntegrityProcessor
import co.touchlab.kjwt.cryptography.registry.EncryptionKey
import co.touchlab.kjwt.cryptography.registry.SigningKey
import co.touchlab.kjwt.model.registry.JwtKeyRegistry
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor

@OptIn(DelicateKJWTApi::class)
public fun JwtKeyRegistry.registerSigningKey(key: SigningKey) {
    registerJwsProcessor(findBestJwsProcessorAndMerge(key))
}

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

@OptIn(DelicateKJWTApi::class)
public fun JwtKeyRegistry.registerEncryptionKey(key: EncryptionKey) {
    registerJweProcessor(findBestJweProcessorAndMerge(key))
}

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
