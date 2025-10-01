package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.PublicKey
import dev.sdkforge.crypto.domain.asNativePrivateKey
import dev.sdkforge.crypto.domain.asNativePublicKey
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal actual fun verifySignature(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean = MessageDigest.isEqual(
    createSignatureFor(
        algorithm = algorithm,
        secretBytes = secretBytes,
        headerBytes = headerBytes,
        payloadBytes = payloadBytes,
    ),
    signatureBytes,
)

internal actual fun verifySignature(
    algorithm: String,
    publicKey: PublicKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean = Signature.getInstance(algorithm).run {
    initVerify(publicKey.asNativePublicKey)

    update(headerBytes)
    update(JWT_PART_SEPARATOR)
    update(payloadBytes)

    verify(signatureBytes)
}

internal actual fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray = Signature.getInstance(algorithm).run {
    initSign(privateKey.asNativePrivateKey)

    update(headerBytes)
    update(JWT_PART_SEPARATOR)
    update(payloadBytes)

    sign()
}

internal actual fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray = Mac.getInstance(algorithm).run {
    init(SecretKeySpec(secretBytes, algorithm))

    update(headerBytes)
    update(JWT_PART_SEPARATOR)

    doFinal(payloadBytes)
}

internal actual fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    contentBytes: ByteArray,
): ByteArray = Mac.getInstance(algorithm).run {
    init(SecretKeySpec(secretBytes, algorithm))

    doFinal(contentBytes)
}

internal actual fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    contentBytes: ByteArray,
): ByteArray = Signature.getInstance(algorithm).run {
    initSign(privateKey.asNativePrivateKey)

    update(contentBytes)

    sign()
}
