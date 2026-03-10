package co.touchlab.kjwt.model.algorithm

import dev.whyoleg.cryptography.materials.key.Key

sealed interface Jwa<PublicKey : Key, PrivateKey : Key> {
    val id: String

    companion object {
        internal val entries: List<Jwa<*, *>> by lazy {
            EncryptionAlgorithm.entries + SigningAlgorithm.entries
        }

        fun fromId(id: String): Jwa<*, *> =
            entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("Unknown JSON Web Algorithm: '$id'")
    }
}