package co.touchlab.kjwt.model.registry

import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.annotations.InternalKJWTApi
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor

/**
 * Default in-memory implementation of [JwtKeyRegistry].
 *
 * Signing processors are keyed by ([SigningAlgorithm], optional key ID) and encryption processors
 * by ([EncryptionAlgorithm], optional key ID). Look-up follows the order defined by
 * [JwtKeyRegistry]: exact match, algorithm-only fallback, then delegate.
 *
 * @see JwtKeyRegistry
 */
@ExperimentalKJWTApi
@OptIn(InternalKJWTApi::class)
public class DefaultJwtKeyRegistry : JwtKeyRegistry {
    @InternalKJWTApi
    override var delegateKeyRegistry: JwtKeyRegistry? = null

    private val signingProcessors = mutableMapOf<Pair<SigningAlgorithm, String?>, JwsProcessor>()
    private val encryptionProcessors = mutableMapOf<Pair<EncryptionAlgorithm, String?>, JweProcessor>()

    override fun delegateTo(other: JwtKeyRegistry) {
        var cursor: JwtKeyRegistry? = other
        while (cursor != null) {
            require(cursor !== this) {
                "Cyclic delegation detected: this registry is already in the delegate chain of the target"
            }
            cursor = cursor.delegateKeyRegistry
        }
        delegateKeyRegistry = other
    }

    override fun registerJwsProcessor(processor: JwsProcessor, keyId: String?) {
        signingProcessors[Pair(processor.algorithm, keyId)] = processor
    }

    override fun registerJweProcessor(processor: JweProcessor, keyId: String?) {
        encryptionProcessors[Pair(processor.algorithm, keyId)] = processor
    }

    override fun findBestJwsProcessor(
        algorithm: SigningAlgorithm,
        keyId: String?,
    ): JwsProcessor? {
        signingProcessors[Pair(algorithm, keyId)]?.let { return it }
        if (keyId != null) {
            signingProcessors[Pair(algorithm, null)]?.let { return it }
        }
        return delegateKeyRegistry?.findBestJwsProcessor(algorithm, keyId)
    }

    override fun findBestJweProcessor(
        algorithm: EncryptionAlgorithm,
        keyId: String?,
    ): JweProcessor? {
        encryptionProcessors[Pair(algorithm, keyId)]?.let { return it }
        if (keyId != null) {
            encryptionProcessors[Pair(algorithm, null)]?.let { return it }
        }
        return delegateKeyRegistry?.findBestJweProcessor(algorithm, keyId)
    }
}
