package kjwt

import org.jetbrains.dokka.gradle.DokkaExtension

fun DokkaExtension.registerExternalDocumentation() {
    dokkaSourceSets.configureEach {
        externalDocumentationLinks.register("cryptography-kotlin") {
            url("https://whyoleg.github.io/cryptography-kotlin/api/")
        }
    }
}
