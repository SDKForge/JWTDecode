package dev.sdkforge.jwt.decode.domain.provider

import dev.sdkforge.crypto.domain.rsa.RSAPrivateKey
import dev.sdkforge.crypto.domain.rsa.RSAPublicKey

/**
 * RSA Public/Private Key provider.
 */
interface RSAKeyProvider : KeyProvider<RSAPublicKey, RSAPrivateKey>
