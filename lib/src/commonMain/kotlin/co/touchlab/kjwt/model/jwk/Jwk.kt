package co.touchlab.kjwt.model.jwk

import co.touchlab.kjwt.serializers.JwkEcSerializer
import co.touchlab.kjwt.serializers.JwkEcThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkOctSerializer
import co.touchlab.kjwt.serializers.JwkOctThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkRsaSerializer
import co.touchlab.kjwt.serializers.JwkRsaThumbprintSerializer
import co.touchlab.kjwt.serializers.JwkSerializer
import co.touchlab.kjwt.serializers.JwkThumbprintSerializer
import kotlinx.serialization.Serializable

@Serializable(with = JwkSerializer::class)
sealed class Jwk {
    abstract val use: String?
    abstract val keyOps: List<String>?
    abstract val alg: String?
    abstract val kid: String?
    abstract val isPrivate: Boolean

    abstract val thumbprint: Thumbprint

    @Serializable(with = JwkThumbprintSerializer::class)
    sealed class Thumbprint

    /**
     * RSA key (kty = "RSA"). Public key requires [n] and [e].
     * Private key additionally requires [d]; CRT parameters [p], [q], [dp], [dq], [qi]
     * are optional but required for key conversion to cryptography-kotlin types.
     */
    @Serializable(with = JwkRsaSerializer::class)
    data class Rsa(
        val n: String,
        val e: String,
        val d: String? = null,
        val p: String? = null,
        val q: String? = null,
        val dp: String? = null,
        val dq: String? = null,
        val qi: String? = null,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = d != null

        override val thumbprint: Thumbprint by lazy {
            RSAThumbprint(e, n)
        }

        @Serializable(with = JwkRsaThumbprintSerializer::class)
        data class RSAThumbprint(
            val e: String,
            val n: String,
        ) : Thumbprint()

        companion object {
            const val KTY = "RSA"
        }
    }

    /**
     * Elliptic Curve key (kty = "EC"). Public key requires [crv], [x], and [y].
     * Private key additionally requires [d]. Supported curves: "P-256", "P-384", "P-521".
     */
    @Serializable(with = JwkEcSerializer::class)
    data class Ec(
        val crv: String,
        val x: String,
        val y: String,
        val d: String? = null,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = d != null

        override val thumbprint: Thumbprint by lazy {
            ECThumbprint(crv, x, y)
        }

        @Serializable(with = JwkEcThumbprintSerializer::class)
        data class ECThumbprint(
            val crv: String,
            val x: String,
            val y: String,
        ) : Thumbprint()

        companion object {
            const val KTY = "EC"
        }
    }

    /**
     * Symmetric (octet sequence) key (kty = "oct"). The [k] parameter holds the raw key bytes
     * encoded as base64url. Always considered private key material.
     */
    @Serializable(with = JwkOctSerializer::class)
    data class Oct(
        val k: String,
        override val use: String? = null,
        override val keyOps: List<String>? = null,
        override val alg: String? = null,
        override val kid: String? = null,
    ) : Jwk() {
        override val isPrivate: Boolean get() = true

        override val thumbprint: Thumbprint by lazy {
            OctThumbprint(k)
        }

        @Serializable(with = JwkOctThumbprintSerializer::class)
        data class OctThumbprint(val k: String) : Thumbprint()

        companion object {
            const val KTY = "oct"
        }
    }
}
