package kjwt

import org.gradle.kotlin.dsl.assign
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

fun KotlinMultiplatformExtension.allTargets(
    supportsWasmWasi: Boolean = true,
) {
    jvmTarget()
    webTargets()
    nativeTargets()
    if (supportsWasmWasi) wasmWasiTarget()
}

fun KotlinMultiplatformExtension.appleTargets(
    // not supported by Swift anymore -> not supported by CryptoKit
    supportsWatchosArm32: Boolean = true,
) {
    macosX64()
    macosArm64()

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    watchosX64()
    if (supportsWatchosArm32) watchosArm32()
    watchosArm64()
    watchosSimulatorArm64()
    watchosDeviceArm64()

    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()
}

fun KotlinMultiplatformExtension.desktopTargets() {
    linuxX64()
    linuxArm64()

    mingwX64()

    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.nativeTargets() {
    appleTargets()
    desktopTargets()

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()
}

fun KotlinMultiplatformExtension.jsTarget(
    supportsBrowser: Boolean = true,
) {
    js {
        nodejs()
        if (supportsBrowser) browser()
        binaries.executable()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmJsTarget(
    supportsBrowser: Boolean = true,
) {
    wasmJs {
        nodejs()
        if (supportsBrowser) browser()
        binaries.executable()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmWasiTarget() {
    wasmWasi {
        nodejs()
    }
}

fun KotlinMultiplatformExtension.webTargets(
    supportsBrowser: Boolean = true,
) {
    jsTarget(supportsBrowser = supportsBrowser)
    wasmJsTarget(supportsBrowser = supportsBrowser)
}

fun KotlinMultiplatformExtension.jvmTarget() {
    jvm {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_1_8
        }
    }
}
