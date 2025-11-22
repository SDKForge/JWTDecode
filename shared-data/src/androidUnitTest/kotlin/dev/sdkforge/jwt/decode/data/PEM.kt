@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader

@Throws(IOException::class)
private fun parsePEMFile(pemFile: File): ByteArray? {
    if (!pemFile.isFile() || !pemFile.exists()) {
        throw FileNotFoundException("The file '${pemFile.absolutePath}' doesn't exist.")
    }
    val reader = PemReader(java.io.FileReader(pemFile))
    val pemObject: PemObject = reader.readPemObject()
    val content: ByteArray? = pemObject.content
    reader.close()
    return content
}

private fun <PK : PublicKey> getPublicKey(keyBytes: ByteArray?, algorithm: String): PK {
    var publicKey: PublicKey? = null
    try {
        val kf = KeyFactory.getInstance(algorithm)
        val keySpec: EncodedKeySpec = X509EncodedKeySpec(keyBytes)
        publicKey = kf.generatePublic(keySpec)
    } catch (_: NoSuchAlgorithmException) {
        println("Could not reconstruct the public key, the given algorithm could not be found.")
    } catch (_: InvalidKeySpecException) {
        println("Could not reconstruct the public key")
    }

    return publicKey as PK
}

private fun <PK : PrivateKey> getPrivateKey(keyBytes: ByteArray?, algorithm: String): PK {
    var privateKey: PrivateKey? = null
    try {
        val kf = KeyFactory.getInstance(algorithm)
        val keySpec: EncodedKeySpec = PKCS8EncodedKeySpec(keyBytes)
        privateKey = kf.generatePrivate(keySpec)
    } catch (_: NoSuchAlgorithmException) {
        println("Could not reconstruct the private key, the given algorithm could not be found.")
    } catch (_: InvalidKeySpecException) {
        println("Could not reconstruct the private key")
    }

    return privateKey as PK
}

@Throws(IOException::class)
internal fun <PK : PublicKey> readPublicKey(filepath: String, algorithm: String): PK {
    val bytes = parsePEMFile(File(filepath))
    return getPublicKey(bytes, algorithm)
}

@Throws(IOException::class)
internal fun <PK : PrivateKey> readPrivateKey(filepath: String, algorithm: String): PK {
    val bytes = parsePEMFile(File(filepath))
    return getPrivateKey(bytes, algorithm)
}
