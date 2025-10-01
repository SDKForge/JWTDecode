@file:Suppress("ktlint:standard:function-expression-body", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.Header
import dev.sdkforge.jwt.decode.domain.Payload
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlin.io.encoding.Base64
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The JWTDecoder class holds the decode method to parse a given JWT token into it's JWT representation.
 */
@OptIn(ExperimentalTime::class)
internal class JWTDecoder(parser: dev.sdkforge.jwt.decode.domain.JWTParser, jwt: String) : DecodedJWT {
    private val parts: Array<String> = TokenUtils.splitToken(jwt)

    internal val jwtHeader: Header
    internal val jwtPayload: Payload

    constructor(jwt: String) : this(parser = JWTParser, jwt = jwt)

    init {
        val headerJson: String?
        val payloadJson: String?
        try {
            headerJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(parts[0]).decodeToString()
            payloadJson = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(parts[1]).decodeToString()
        } catch (e: NullPointerException) {
            throw JWTDecodeException("The UTF-8 Charset isn't initialized.", e)
        } catch (e: IllegalArgumentException) {
            throw JWTDecodeException("The input is not a valid base 64 encoded string.", e)
        }
        jwtHeader = parser.parseHeader(headerJson)
        jwtPayload = parser.parsePayload(payloadJson)
    }

    override val algorithm: String? get() = jwtHeader.algorithm
    override val type: String? get() = jwtHeader.type
    override val contentType: String? get() = jwtHeader.contentType
    override val keyId: String? get() = jwtHeader.keyId
    override fun getHeaderClaim(name: String): Claim = jwtHeader.getHeaderClaim(name)
    override val issuer: String? get() = jwtPayload.issuer
    override val subject: String? get() = jwtPayload.subject
    override val audience: List<String>? get() = jwtPayload.audience
    override val expiresAt: Instant? get() = jwtPayload.expiresAt
    override val notBefore: Instant? get() = jwtPayload.notBefore
    override val issuedAt: Instant? get() = jwtPayload.issuedAt
    override val id: String? get() = jwtPayload.id
    override fun getClaim(name: String): Claim = jwtPayload.getClaim(name)

    override val header: String get() = parts[0]
    override val payload: String get() = parts[1]
    override val signature: String get() = parts[2]

    override val token: String get() = "${parts[0]}.${parts[1]}.${parts[2]}"

    override fun toString(): String = token
}
