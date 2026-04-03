package co.touchlab.kjwt.ext

import co.touchlab.kjwt.processor.BaseJweProcessor
import co.touchlab.kjwt.processor.BaseJwsProcessor
import co.touchlab.kjwt.processor.JweDecryptor
import co.touchlab.kjwt.processor.JweEncryptor
import co.touchlab.kjwt.processor.JweProcessor
import co.touchlab.kjwt.processor.JwsProcessor
import co.touchlab.kjwt.processor.JwsSigner
import co.touchlab.kjwt.processor.JwsVerifier

public fun BaseJwsProcessor.mergeWith(other: BaseJwsProcessor?): BaseJwsProcessor {
    if (other == null) return this

    require(algorithm == other.algorithm) { "Cannot merge keys with different identifiers" }
    require(this::class != other::class) { "Cannot merge keys of the same type" }
    require(
        this !is JwsProcessor && other !is JwsProcessor
    ) { "Cannot merge when one of the keys already support both operations" }

    return when (this) {
        is JwsSigner if other is JwsVerifier -> {
            JwsProcessor.combining(this, other)
        }

        is JwsVerifier if other is JwsSigner -> {
            JwsProcessor.combining(other, this)
        }

        else -> {
            error("Cannot merge given keys")
        }
    }
}

public fun BaseJweProcessor.mergeWith(other: BaseJweProcessor?): BaseJweProcessor {
    if (other == null) return this

    require(algorithm == other.algorithm) { "Cannot merge keys with different identifiers" }
    require(this::class != other::class) { "Cannot merge keys of the same type" }
    require(
        this !is JweProcessor && other !is JweProcessor
    ) { "Cannot merge when one of the keys already support both operations" }

    return when (this) {
        is JweEncryptor if other is JweDecryptor -> {
            JweProcessor.combining(this, other)
        }

        is JweDecryptor if other is JweEncryptor -> {
            JweProcessor.combining(other, this)
        }

        else -> {
            error("Cannot merge given keys")
        }
    }
}
