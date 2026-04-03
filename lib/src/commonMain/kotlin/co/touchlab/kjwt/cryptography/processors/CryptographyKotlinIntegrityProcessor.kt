package co.touchlab.kjwt.cryptography.processors

import co.touchlab.kjwt.cryptography.registry.SigningKey
import co.touchlab.kjwt.cryptography.toCryptographyKotlin
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.processor.JwsProcessor
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA

/**
 * A [JwsProcessor] implementation backed by the cryptography-kotlin library.
 *
 * Wraps a [SigningKey] and delegates all signing and verification operations to the
 * cryptography-kotlin primitives appropriate for the key's algorithm: [HMAC] for MAC-based
 * algorithms, [RSA.PKCS1] for RS256/384/512, [RSA.PSS] for PS256/384/512, and [ECDSA] for
 * ES256/384/512.
 *
 * @see co.touchlab.kjwt.processor.JwsProcessor
 * @see SigningKey
 */
public class CryptographyKotlinIntegrityProcessor(
    internal val key: SigningKey,
) : JwsProcessor {
    internal constructor(
        key: SigningKey,
        previous: JwsProcessor?,
    ) : this(
        key.mergeWith((previous as? CryptographyKotlinIntegrityProcessor)?.key)
    )

    /** The JWS signing algorithm derived from the wrapped [SigningKey]'s identifier. */
    override val algorithm: SigningAlgorithm
        get() = key.identifier.algorithm

    /** The optional key ID (`kid`) derived from the wrapped [SigningKey]'s identifier. */
    override val keyId: String?
        get() = key.identifier.keyId

    /**
     * Signs [data] using the private key material from the wrapped [SigningKey].
     *
     * Dispatches to the cryptography-kotlin primitive that matches the key's algorithm.
     * Returns an empty [ByteArray] when the algorithm is [SigningAlgorithm.None].
     *
     * @param data the raw bytes to sign
     * @return the signature bytes produced by the underlying cryptographic operation
     * @throws IllegalStateException if the wrapped key type is incompatible with the algorithm
     */
    override suspend fun sign(data: ByteArray): ByteArray {
        val privateKey = key.privateKey
        val algorithm = key.identifier.algorithm

        return when (privateKey) {
            is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is RSA.PKCS1.PrivateKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is RSA.PSS.PrivateKey if (algorithm is SigningAlgorithm.PSSBased) -> {
                privateKey.signatureGenerator().generateSignature(data)
            }

            is ECDSA.PrivateKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
                privateKey
                    .signatureGenerator(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                    .generateSignature(data)
            }

            else -> {
                when (algorithm) {
                    SigningAlgorithm.None -> {
                        ByteArray(0)
                    }

                    else -> {
                        error("The keys provided for signing are not valid for the ${algorithm.id}.")
                    }
                }
            }
        }
    }

    /**
     * Verifies that [signature] is a valid signature over [data] using the public key material
     * from the wrapped [SigningKey].
     *
     * Returns `true` if the signature is valid, `false` if the cryptographic verification fails.
     * For [SigningAlgorithm.None], returns `true` only when the signature is empty.
     *
     * @param data the raw bytes that were originally signed
     * @param signature the signature bytes to verify
     * @return `true` if the signature is valid for the given data, `false` otherwise
     * @throws IllegalStateException if the wrapped key type is incompatible with the algorithm
     */
    override suspend fun verify(data: ByteArray, signature: ByteArray): Boolean =
        try {
            val publicKey = key.publicKey
            val algorithm = key.identifier.algorithm

            when (publicKey) {
                is HMAC.Key if (algorithm is SigningAlgorithm.MACBased) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is RSA.PKCS1.PublicKey if (algorithm is SigningAlgorithm.PKCS1Based) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is RSA.PSS.PublicKey if (algorithm is SigningAlgorithm.PSSBased) -> {
                    publicKey.signatureVerifier().verifySignature(data, signature)
                    true
                }

                is ECDSA.PublicKey if (algorithm is SigningAlgorithm.ECDSABased) -> {
                    publicKey
                        .signatureVerifier(algorithm.digest.toCryptographyKotlin(), ECDSA.SignatureFormat.RAW)
                        .verifySignature(data, signature)
                    true
                }

                else -> {
                    when (algorithm) {
                        SigningAlgorithm.None -> {
                            signature.isEmpty()
                        }

                        else -> {
                            null
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            false
        } ?: error("The keys provided for verification are not valid for the ${algorithm.id}.")
}
