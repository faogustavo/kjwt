import kjwt.Projects
import kjwt.isRootProject
import kjwt.registerExternalDocumentation
import kjwt.registerSourceLink
import kjwt.registerVersioningPlugin
import kjwt.rootProjectDependencies
import kjwt.setupHtmlPlugin

plugins {
    id("org.jetbrains.dokka")
}

rootProjectDependencies { versionCatalog ->
    Projects.allLibraries.forEach { dokka(project(it)) }
    dokkaPlugin(versionCatalog.findLibrary("dokka-plugin-versioning").get())
}

dokka {
    setupHtmlPlugin()

    dokkaPublications.configureEach {
        suppressInheritedMembers = false
        failOnWarning = true

        if (project.isRootProject) {
            registerVersioningPlugin(project)
        }

        includes.from("README.md")
    }

    dokkaSourceSets.configureEach {
        reportUndocumented = false
        skipEmptyPackages = true

        registerSourceLink(project)
        registerExternalDocumentation()

        if (name.endsWith("Main")) {
            samples.from("src/${name.replace("Main", "Samples")}/kotlin")
        }
    }
}
