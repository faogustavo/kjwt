package co.touchlab.kjwt.ext

import co.touchlab.kjwt.model.JwtHeader

inline fun <reified T> JwtHeader.getHeader(name: String): T =
    getHeader(kotlinx.serialization.serializer<T>(), name)

inline fun <reified T> JwtHeader.getHeaderOrNull(name: String): T? =
    getHeaderOrNull(kotlinx.serialization.serializer<T>(), name)

val JwtHeader.encryption: String get() = getHeader(JwtHeader.ENC)
val JwtHeader.encryptionOrNull: String? get() = getHeaderOrNull(JwtHeader.ENC)

val JwtHeader.type: String get() = getHeader(JwtHeader.TYP)
val JwtHeader.typeOrNull: String? get() = getHeaderOrNull(JwtHeader.TYP)

val JwtHeader.contentType: String get() = getHeader(JwtHeader.CTY)
val JwtHeader.contentTypeOrNull: String? get() = getHeaderOrNull(JwtHeader.CTY)

val JwtHeader.keyId: String get() = getHeader(JwtHeader.KID)
val JwtHeader.keyIdOrNull: String? get() = getHeaderOrNull(JwtHeader.KID)
