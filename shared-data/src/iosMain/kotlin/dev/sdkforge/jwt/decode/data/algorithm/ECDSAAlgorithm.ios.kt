package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.ec.ECPublicKey

internal actual fun verifySignature(
    publicKey: ECPublicKey,
    rBytes: ByteArray,
    sBytes: ByteArray,
) {
    TODO("Not yet implemented")
}
