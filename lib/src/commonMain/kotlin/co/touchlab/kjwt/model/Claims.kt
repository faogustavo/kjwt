package co.touchlab.kjwt.model

import co.touchlab.kjwt.exception.MissingClaimException
import co.touchlab.kjwt.internal.JwtJson
import co.touchlab.kjwt.serializers.ClaimsSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable(with = ClaimsSerializer::class)
internal class Claims(@PublishedApi internal val data: Map<String, JsonElement>) : JwtPayload {
    override fun <T> getClaim(serializer: DeserializationStrategy<T>, name: String): T =
        getClaimOrNull(serializer, name) ?: throw MissingClaimException(name)

    override fun <T> getClaimOrNull(serializer: DeserializationStrategy<T>, name: String): T? {
        val element = data[name] ?: return null
        return JwtJson.decodeFromJsonElement(serializer, element)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Claims

        return data == other.data
    }

    override fun hashCode(): Int = data.hashCode()
    override fun toString(): String = "Claims(data=$data)"
}