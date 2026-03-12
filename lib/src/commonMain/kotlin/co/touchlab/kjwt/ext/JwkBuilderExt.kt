package co.touchlab.kjwt.ext

import co.touchlab.kjwt.builder.JwtBuilder
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import co.touchlab.kjwt.model.jwk.Jwk
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512

// ---------------------------------------------------------------------------
// signWith — HMAC (oct)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.HashBased, jwk: Jwk.Oct): JwtInstance.Jws {
    val digest = when (algorithm) {
        SigningAlgorithm.HS256 -> SHA256
        SigningAlgorithm.HS384 -> SHA384
        SigningAlgorithm.HS512 -> SHA512
    }
    return signWith(algorithm, jwk.toHmacKey(digest))
}

// ---------------------------------------------------------------------------
// signWith — RSA PKCS1 (RS*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PKCS1Based, jwk: Jwk.Rsa): JwtInstance.Jws {
    val digest = when (algorithm) {
        SigningAlgorithm.RS256 -> SHA256
        SigningAlgorithm.RS384 -> SHA384
        SigningAlgorithm.RS512 -> SHA512
    }
    return signWith(algorithm, jwk.toRsaPkcs1PrivateKey(digest))
}

// ---------------------------------------------------------------------------
// signWith — RSA PSS (PS*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.PSSBased, jwk: Jwk.Rsa): JwtInstance.Jws {
    val digest = when (algorithm) {
        SigningAlgorithm.PS256 -> SHA256
        SigningAlgorithm.PS384 -> SHA384
        SigningAlgorithm.PS512 -> SHA512
    }
    return signWith(algorithm, jwk.toRsaPssPrivateKey(digest))
}

// ---------------------------------------------------------------------------
// signWith — ECDSA (ES*)
// ---------------------------------------------------------------------------

suspend fun JwtBuilder.signWith(algorithm: SigningAlgorithm.ECDSABased, jwk: Jwk.Ec): JwtInstance.Jws =
    signWith(algorithm, jwk.toEcdsaPrivateKey())

// ---------------------------------------------------------------------------
// encryptWith — RSA-OAEP / RSA-OAEP-256
// ---------------------------------------------------------------------------

@OptIn(dev.whyoleg.cryptography.DelicateCryptographyApi::class)
suspend fun JwtBuilder.encryptWith(
    jwk: Jwk.Rsa,
    keyAlgorithm: EncryptionAlgorithm.OAEPBased,
    contentAlgorithm: EncryptionContentAlgorithm,
): JwtInstance.Jwe {
    val digest = when (keyAlgorithm) {
        EncryptionAlgorithm.RsaOaep -> SHA1
        EncryptionAlgorithm.RsaOaep256 -> SHA256
    }
    return encryptWith(jwk.toRsaOaepPublicKey(digest), keyAlgorithm, contentAlgorithm)
}