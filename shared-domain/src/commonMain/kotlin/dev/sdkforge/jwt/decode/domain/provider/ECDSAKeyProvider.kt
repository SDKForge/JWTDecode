package dev.sdkforge.jwt.decode.domain.provider

import dev.sdkforge.crypto.domain.ec.ECPrivateKey
import dev.sdkforge.crypto.domain.ec.ECPublicKey

/**
 * Elliptic Curve (EC) Public/Private Key provider.
 */
interface ECDSAKeyProvider : KeyProvider<ECPublicKey, ECPrivateKey>
