import kjwt.registerExternalDocumentation

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.dokka")
}

dokka {
    dokkaPublications.configureEach {
        suppressInheritedMembers = false
        failOnWarning = true
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

kotlin {
    sourceSets.configureEach {
        if (name.endsWith("Test")) {
            kotlin.srcDir("src/${name.replace("Test", "Samples")}/kotlin")
        }
    }
}