import kjwt.Projects
import kjwt.isRootProject
import kjwt.registerExternalDocumentation
import kjwt.registerVersioningPlugin
import kjwt.rootProjectDependencies

plugins {
    id("org.jetbrains.dokka")
}

rootProjectDependencies { versionCatalog ->
    Projects.allLibraries.forEach { dokka(project(it)) }
    dokkaPlugin(versionCatalog.findLibrary("dokka-plugin-versioning").get())
}

dokka {
    dokkaPublications.configureEach {
        suppressInheritedMembers = false
        failOnWarning = true

        if (project.isRootProject) {
            registerVersioningPlugin(project)
        }
    }

    dokkaSourceSets.configureEach {
        reportUndocumented = false
        skipEmptyPackages = true

        sourceLink {
            localDirectory = rootDir
            remoteUrl("https://github.com/faogustavo/kjwt/tree/$version/")
        }

        if (name.endsWith("Main")) {
            samples.from("src/${name.replace("Main", "Samples")}/kotlin")
        }
    }

    registerExternalDocumentation()
}
