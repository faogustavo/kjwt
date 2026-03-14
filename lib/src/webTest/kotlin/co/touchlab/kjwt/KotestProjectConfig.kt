package co.touchlab.kjwt

import io.kotest.core.config.AbstractProjectConfig

object KotestProjectConfig : AbstractProjectConfig() {
    override val retries: Int = 3
}