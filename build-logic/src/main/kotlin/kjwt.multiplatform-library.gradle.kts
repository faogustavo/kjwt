import kjwt.configureTests
import org.jetbrains.kotlin.gradle.dsl.abi.BinariesSource
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

plugins {
    kotlin("multiplatform")
    id("com.google.devtools.ksp")
    id("io.kotest")
    id("kjwt.linting")
    id("kjwt.dokka")
    id("kjwt.publish")
    `maven-publish`
}

kotlin {
    explicitApi()

    @OptIn(ExperimentalAbiValidation::class)
    abiValidation {
        binariesSource.set(BinariesSource.MAVEN_PUBLICATIONS)

        filters {
            exclude {
                annotatedWith.add("co.touchlab.kjwt.annotations.InternalKJWTApi")
            }
        }
    }

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    sourceSets {
        all {
            languageSettings {
                optIn("co.touchlab.kjwt.annotations.InternalKJWTApi")
                optIn("co.touchlab.kjwt.annotations.ExperimentalKJWTApi")
                optIn("kotlin.time.ExperimentalTime")
            }
        }
    }
}