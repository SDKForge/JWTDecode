package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.PublicKey

internal actual fun verifySignature(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean {
    TODO("Not yet implemented")
}

internal actual fun verifySignature(
    algorithm: String,
    publicKey: PublicKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean {
    TODO("Not yet implemented")
}

internal actual fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray {
    TODO("Not yet implemented")
}

internal actual fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray {
    TODO("Not yet implemented")
}

internal actual fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    contentBytes: ByteArray,
): ByteArray {
    TODO("Not yet implemented")
}

internal actual fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    contentBytes: ByteArray,
): ByteArray {
    TODO("Not yet implemented")
}
