package co.touchlab.kjwt.processor

import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

/**
 * Core abstraction for JWS (signed JWT) signing and verification.
 *
 * Combines the [Signer] and [Verifier] functional interfaces and associates them with a
 * [SigningAlgorithm] and an optional key ID. Implementations are supplied to
 * [co.touchlab.kjwt.builder.JwtBuilder] for signing and to
 * [co.touchlab.kjwt.parser.JwtParserBuilder] for verification.
 *
 * @see Signer
 * @see Verifier
 */
public interface JwsProcessor : Signer, Verifier {
    /** The JWS signing algorithm this processor implements. */
    public val algorithm: SigningAlgorithm

    /** The optional key ID (`kid`) associated with the key material used by this processor. */
    public val keyId: String?
}

/**
 * Functional interface for producing a JWS signature over raw byte data.
 *
 * @see JwsProcessor
 */
public fun interface Signer {
    /**
     * Signs [data] and returns the raw signature bytes.
     *
     * @param data the data to sign
     * @return the raw signature bytes produced by the signing operation
     */
    public suspend fun sign(data: ByteArray): ByteArray
}

/**
 * Functional interface for verifying a JWS signature against raw byte data.
 *
 * @see JwsProcessor
 */
public fun interface Verifier {
    /**
     * Verifies that [signature] is a valid signature over [data].
     *
     * @param data the data that was originally signed
     * @param signature the raw signature bytes to verify
     * @return `true` if the signature is valid, `false` otherwise
     */
    public suspend fun verify(data: ByteArray, signature: ByteArray): Boolean
}
