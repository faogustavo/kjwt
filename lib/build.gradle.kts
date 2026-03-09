//import helpers.allTargets

plugins {
    id("kjwt.multiplatform-library")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.cryptography.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }

        jvmTest.dependencies {
            implementation(libs.cryptography.provider.jdk)
        }

        webTest.dependencies {
            implementation(libs.cryptography.provider.web)
        }

        nativeTest.dependencies {
            implementation(libs.cryptography.provider.openssl)
        }
    }
}