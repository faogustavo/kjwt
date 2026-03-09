import helpers.allTargets
import helpers.configureTests

plugins {
    kotlin("multiplatform")
}

kotlin {
    allTargets()
    configureTests()
}
