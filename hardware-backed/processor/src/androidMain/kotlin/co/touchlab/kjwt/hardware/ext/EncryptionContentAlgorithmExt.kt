package co.touchlab.kjwt.hardware.ext

import android.os.Build
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm
import java.security.spec.MGF1ParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

public fun EncryptionAlgorithm.toOaepCipherName(): String = when (this) {
    EncryptionAlgorithm.RsaOaep -> "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
    EncryptionAlgorithm.RsaOaep256 -> "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    EncryptionAlgorithm.Dir -> error("Dir does not use a cipher")
}

public fun EncryptionAlgorithm.toOaepParameterSpec(): OAEPParameterSpec = when (this) {
    EncryptionAlgorithm.RsaOaep -> {
        OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )
    }

    EncryptionAlgorithm.RsaOaep256 -> {
        // setMgf1Digests (API 35+) controls the allowed MGF1 digest on the key; below API 35
        // the keystore only permits SHA-1 for MGF1, so the spec must match accordingly.
        val mgf1Spec = if (Build.VERSION.SDK_INT >= 35) MGF1ParameterSpec.SHA256 else MGF1ParameterSpec.SHA1
        OAEPParameterSpec("SHA-256", "MGF1", mgf1Spec, PSource.PSpecified.DEFAULT)
    }

    EncryptionAlgorithm.Dir -> {
        error("Dir does not use OAEP")
    }
}

public fun EncryptionContentAlgorithm.generateCek(
    generateRandomBytes: (Int) -> ByteArray,
): ByteArray = generateRandomBytes(
    when (this) {
        EncryptionContentAlgorithm.A128GCM -> 16
        EncryptionContentAlgorithm.A192GCM -> 24
        EncryptionContentAlgorithm.A256GCM -> 32
        EncryptionContentAlgorithm.A128CbcHs256 -> 32
        EncryptionContentAlgorithm.A192CbcHs384 -> 48
        EncryptionContentAlgorithm.A256CbcHs512 -> 64
    }
)
