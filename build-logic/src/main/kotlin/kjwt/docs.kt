package kjwt

import org.gradle.api.Project
import org.gradle.kotlin.dsl.named
import org.jetbrains.dokka.gradle.DokkaExtension
import org.jetbrains.dokka.gradle.engine.parameters.DokkaSourceSetSpec
import org.jetbrains.dokka.gradle.engine.plugins.DokkaHtmlPluginParameters
import org.jetbrains.dokka.gradle.engine.plugins.DokkaVersioningPluginParameters

fun DokkaExtension.setupHtmlPlugin() {
    pluginsConfiguration.named<DokkaHtmlPluginParameters>("html") {
        homepageLink.set("https://github.com/touchlab/kjwt")
        footerMessage.set("© 2026 Touchlab")
    }
}

fun DokkaSourceSetSpec.registerSourceLink(project: Project) {
    sourceLink {
        localDirectory.set(project.rootDir)
        remoteLineSuffix.set("#L")
        remoteUrl("https://github.com/touchlab/kjwt/tree/${project.version}/")
    }
}

fun DokkaSourceSetSpec.registerExternalDocumentation() {
    externalDocumentationLinks.register("cryptography-kotlin") {
        url("https://whyoleg.github.io/cryptography-kotlin/api/")
    }
    externalDocumentationLinks.register("kotlinx-serialization") {
        url("https://kotlinlang.org/api/kotlinx.serialization/")
    }
}

fun DokkaExtension.registerVersioningPlugin(project: Project) {
    pluginsConfiguration.named<DokkaVersioningPluginParameters>("versioning") {
        version.set(Projects.VERSION)
        olderVersionsDir.set(project.rootProject.projectDir.resolve("build/previous-versions"))
    }
}
