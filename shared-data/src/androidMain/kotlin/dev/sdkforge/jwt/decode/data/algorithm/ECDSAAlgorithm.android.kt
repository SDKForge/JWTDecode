package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.asNativePublicKey
import dev.sdkforge.crypto.domain.ec.ECPublicKey
import dev.sdkforge.jwt.decode.domain.exception.SignatureException
import java.math.BigInteger
import java.security.interfaces.ECKey

internal actual fun verifySignature(
    publicKey: ECPublicKey,
    rBytes: ByteArray,
    sBytes: ByteArray,
) {
    val order: BigInteger = (publicKey.asNativePublicKey as ECKey).params.order
    val r = BigInteger(1, rBytes)
    val s = BigInteger(1, sBytes)

    // R and S must be less than N
    if (order.compareTo(r) < 1) {
        throw SignatureException("Invalid signature format.")
    }

    if (order.compareTo(s) < 1) {
        throw SignatureException("Invalid signature format.")
    }
}
