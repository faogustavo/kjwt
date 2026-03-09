package helpers

import gradle.kotlin.dsl.accessors._32f13a2410234c18b32f9f4bfe09beee.sourceSets
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinPlatformType
import org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrTarget

fun KotlinMultiplatformExtension.configureTests() {
    configureKotlinTestDependencies()
    configureJSTests()
}

private fun KotlinMultiplatformExtension.configureKotlinTestDependencies() {
    sourceSets.configureEach {
        when (name) {
            "commonTest" -> "test"
            "jvmTest"    -> "test-junit"
            else         -> null
        }?.let { testDependency ->
            dependencies {
                implementation(kotlin(testDependency))
            }
        }
    }
}

private fun KotlinMultiplatformExtension.configureCryptoProviders() {
    val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

    sourceSets {
        jvmTest.dependencies {
            implementation(libs.findLibrary("cryptography-provider-jdk"))
        }

        webTest.dependencies {
            implementation(libs.findLibrary("cryptography-provider-web"))
        }

        nativeTest.dependencies {
            implementation(libs.findLibrary("cryptography-provider-openssl"))
        }
    }
}

private fun KotlinMultiplatformExtension.configureJSTests() {
    targets.withType<KotlinJsIrTarget>().configureEach {
        // Wasm tests are not behaving as expected
        // TODO: Revisit Wasm Tests
        if (platformType == KotlinPlatformType.wasm) {
            whenBrowserConfigured {
                testTask {
                    enabled = false
                }
            }

            whenNodejsConfigured {
                testTask {
                    enabled = false
                }
            }

            return@configureEach
        }


        whenBrowserConfigured {
            testTask {
                useKarma {
                    useConfigDirectory(project.rootProject.rootDir.resolve("karma.config.d"))
                    useChromeHeadless()
                }
            }
        }
    }
}