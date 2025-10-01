package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.crypto.domain.PrivateKey
import dev.sdkforge.crypto.domain.PublicKey

/**
 * Verify signature for JWT header and payload.
 *
 * @param algorithm      algorithm name.
 * @param secretBytes    algorithm secret.
 * @param header         JWT header.
 * @param payload        JWT payload.
 * @param signatureBytes JWT signature.
 * @return true if signature is valid.
 */
internal fun verifySignature(
    algorithm: String,
    secretBytes: ByteArray,
    header: String,
    payload: String,
    signatureBytes: ByteArray,
): Boolean = verifySignature(
    algorithm = algorithm,
    secretBytes = secretBytes,
    headerBytes = header.encodeToByteArray(),
    payloadBytes = payload.encodeToByteArray(),
    signatureBytes = signatureBytes,
)

/**
 * Verify signature for JWT header and payload.
 *
 * @param algorithm      algorithm name.
 * @param secretBytes    algorithm secret.
 * @param headerBytes    JWT header.
 * @param payloadBytes   JWT payload.
 * @param signatureBytes JWT signature.
 * @return true if signature is valid.
 */
internal expect fun verifySignature(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean

/**
 * Verify signature for JWT header and payload.
 *
 * @param algorithm      algorithm name.
 * @param publicKey      algorithm public key.
 * @param header         JWT header.
 * @param payload        JWT payload.
 * @param signatureBytes JWT signature.
 * @return true if signature is valid.
 */
internal fun verifySignature(
    algorithm: String,
    publicKey: PublicKey,
    header: String,
    payload: String,
    signatureBytes: ByteArray,
): Boolean = verifySignature(
    algorithm = algorithm,
    publicKey = publicKey,
    headerBytes = header.encodeToByteArray(),
    payloadBytes = payload.encodeToByteArray(),
    signatureBytes = signatureBytes,
)

/**
 * Verify signature for JWT header and payload using a public key.
 *
 * @param algorithm      algorithm name.
 * @param publicKey      the public key to use for verification.
 * @param headerBytes    JWT header.
 * @param payloadBytes   JWT payload.
 * @param signatureBytes JWT signature.
 * @return true if signature is valid.
 */
internal expect fun verifySignature(
    algorithm: String,
    publicKey: PublicKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
    signatureBytes: ByteArray,
): Boolean

/**
 * Create signature for JWT header and payload using a private key.
 *
 * @param algorithm    algorithm name.
 * @param privateKey   the private key to use for signing.
 * @param headerBytes  JWT header.
 * @param payloadBytes JWT payload.
 * @return the signature bytes.
 */
internal expect fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray

/**
 * Create signature for JWT header and payload.
 *
 * @param algorithm    algorithm name.
 * @param secretBytes  algorithm secret.
 * @param headerBytes  JWT header.
 * @param payloadBytes JWT payload.
 * @return the signature bytes.
 */
internal expect fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    headerBytes: ByteArray,
    payloadBytes: ByteArray,
): ByteArray

/**
 * Create signature.
 * To get the correct JWT Signature, ensure the content is in the format {HEADER}.{PAYLOAD}
 *
 * @param algorithm    algorithm name.
 * @param secretBytes  algorithm secret.
 * @param contentBytes the content to be signed.
 * @return the signature bytes.
 */
internal expect fun createSignatureFor(
    algorithm: String,
    secretBytes: ByteArray,
    contentBytes: ByteArray,
): ByteArray

/**
 * Create signature using a private key.
 * To get the correct JWT Signature, ensure the content is in the format {HEADER}.{PAYLOAD}
 *
 * @param algorithm    algorithm name.
 * @param privateKey   the private key to use for signing.
 * @param contentBytes the content to be signed.
 * @return the signature bytes.
 */
internal expect fun createSignatureFor(
    algorithm: String,
    privateKey: PrivateKey,
    contentBytes: ByteArray,
): ByteArray

internal const val JWT_PART_SEPARATOR = 46.toByte()
