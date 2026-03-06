package co.touchlab.kjwt.model

import co.touchlab.kjwt.algorithm.JweContentAlgorithm
import co.touchlab.kjwt.algorithm.JweKeyAlgorithm
import co.touchlab.kjwt.algorithm.JwsAlgorithm
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

sealed class JwtHeader {
    abstract val algorithm: String
    abstract val type: String?
    abstract val contentType: String?
    abstract val keyId: String?
    abstract val extra: Map<String, JsonElement>

    internal abstract fun toJsonObject(): JsonObject

    data class Jws(
        override val algorithm: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader() {
        override fun toJsonObject(): JsonObject = buildJsonObject {
            put(ALG, JsonPrimitive(algorithm))
            type?.let { put(TYP, JsonPrimitive(it)) }
            contentType?.let { put(CTY, JsonPrimitive(it)) }
            keyId?.let { put(KID, JsonPrimitive(it)) }
            extra.forEach { (k, v) -> put(k, v) }
        }

        companion object {
            internal fun fromJsonObject(obj: JsonObject): Jws {
                val extra = obj.filterKeys { it !in setOf(ALG, TYP, CTY, KID) }
                return Jws(
                    algorithm = obj[ALG]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'alg' in JWS header"),
                    type = (obj[TYP] as? JsonPrimitive)?.content,
                    contentType = (obj[CTY] as? JsonPrimitive)?.content,
                    keyId = (obj[KID] as? JsonPrimitive)?.content,
                    extra = extra,
                )
            }
        }
    }

    data class Jwe(
        override val algorithm: String,
        val encryption: String,
        override val type: String? = "JWT",
        override val contentType: String? = null,
        override val keyId: String? = null,
        override val extra: Map<String, JsonElement> = emptyMap(),
    ) : JwtHeader() {
        override fun toJsonObject(): JsonObject = buildJsonObject {
            put(ALG, JsonPrimitive(algorithm))
            put(ENC, JsonPrimitive(encryption))
            type?.let { put(TYP, JsonPrimitive(it)) }
            contentType?.let { put(CTY, JsonPrimitive(it)) }
            keyId?.let { put(KID, JsonPrimitive(it)) }
            extra.forEach { (k, v) -> put(k, v) }
        }

        companion object {
            internal fun fromJsonObject(obj: JsonObject): Jwe {
                val extra = obj.filterKeys { it !in setOf(ALG, ENC, TYP, CTY, KID) }
                return Jwe(
                    algorithm = obj[ALG]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'alg' in JWE header"),
                    encryption = obj[ENC]?.let { (it as JsonPrimitive).content }
                        ?: error("Missing 'enc' in JWE header"),
                    type = (obj[TYP] as? JsonPrimitive)?.content,
                    contentType = (obj[CTY] as? JsonPrimitive)?.content,
                    keyId = (obj[KID] as? JsonPrimitive)?.content,
                    extra = extra,
                )
            }
        }
    }

    class Builder {
        var type: String? = "JWT"
        var contentType: String? = null
        var keyId: String? = null
        private val extra: MutableMap<String, JsonElement> = mutableMapOf()

        fun extra(name: String, value: JsonElement) {
            extra[name] = value
        }

        internal fun build(algorithm: JwsAlgorithm<*>) = Jws(
            algorithm = algorithm.id,
            type = type,
            contentType = contentType,
            keyId = keyId,
            extra = extra,
        )

        internal fun build(
            keyAlgorithm: JweKeyAlgorithm<*, *>,
            contentAlgorithm: JweContentAlgorithm,
        ) = Jwe(
            algorithm = keyAlgorithm.id,
            encryption = contentAlgorithm.id,
            type = type,
            contentType = contentType,
            keyId = keyId,
            extra = extra,
        )
    }

    companion object {
        const val ALG = "alg"
        const val ENC = "enc"
        const val TYP = "typ"
        const val CTY = "cty"
        const val KID = "kid"
    }
}