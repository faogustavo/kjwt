package co.touchlab.kjwt

import io.kotest.core.config.AbstractProjectConfig

class KotestProjectConfig : AbstractProjectConfig() {
    override val retries: Int = 3
}