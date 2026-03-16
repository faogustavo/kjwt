package kjwt

import gradle.kotlin.dsl.accessors._ae0e2e0f59d526dd61b4865f6e032691.versioning
import org.gradle.api.Project
import org.gradle.kotlin.dsl.assign
import org.jetbrains.dokka.gradle.DokkaExtension

fun DokkaExtension.registerExternalDocumentation() {
    dokkaSourceSets.configureEach {
        externalDocumentationLinks.register("cryptography-kotlin") {
            url("https://whyoleg.github.io/cryptography-kotlin/api/")
        }
    }
}

fun DokkaExtension.registerVersioningPlugin(project: Project) {
    pluginsConfiguration.versioning {
        version = Projects.version
        olderVersionsDir.set(project.rootProject.projectDir.resolve("build/previous-versions"))
        renderVersionsNavigationOnAllPages = true
    }
}