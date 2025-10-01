@file:Suppress("ktlint:standard:filename", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data.algorithm

import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import java.util.regex.Pattern
import kotlin.io.encoding.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.fail

private val authHeaderPattern: Pattern = Pattern.compile("^([\\w-]+)\\.([\\w-]+)\\.([\\w-]+)")

fun asJWT(algorithm: Algorithm, header: String, payload: String): String {
    val signatureBytes = (algorithm as SigningAlgorithm).sign(header.toByteArray(), payload.toByteArray())
    val jwtSignature = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(signatureBytes)

    return "$header.$payload.$jwtSignature"
}

fun assertSignatureValue(
    jwt: String,
    expectedSignature: String?,
) {
    val jwtSignature = jwt.split('.').last()

    assertEquals(expectedSignature, jwtSignature)
}

fun assertSignaturePresent(jwt: String) {
    val matcher = authHeaderPattern.matcher(jwt)

    if (!matcher.find() || matcher.groupCount() < 3) {
        fail("No signature present in $jwt")
    }

    assertFalse { matcher.group(3).isNullOrBlank() }
}
