// Taken from https://github.com/whyoleg/cryptography-kotlin/blob/main/karma.config.d/config.js

config.client = config.client || {}
config.client.mocha = config.client.mocha || {}
config.client.mocha.timeout = '6000s'
config.browserNoActivityTimeout = 6000000
config.browserDisconnectTimeout = 6000000