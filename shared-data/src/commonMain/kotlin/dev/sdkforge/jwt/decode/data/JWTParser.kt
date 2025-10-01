@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Header
import dev.sdkforge.jwt.decode.domain.Payload
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
import kotlinx.serialization.json.Json

/**
 * This class helps in decoding the Header and Payload of the JWT.
 */
internal object JWTParser : dev.sdkforge.jwt.decode.domain.JWTParser {

    internal val JSON = Json {
        ignoreUnknownKeys = true
    }

    @Throws(JWTDecodeException::class)
    override fun parsePayload(json: String): Payload = runCatching {
        JSON.decodeFromString(deserializer = JWTPayloadDeserializationStrategy, string = json)
    }.getOrElse { throw JWTDecodeException(it.message, it) }

    @Throws(JWTDecodeException::class)
    override fun parseHeader(json: String): Header = runCatching {
        JSON.decodeFromString(deserializer = JWTHeaderSerializerDeserializationStrategy, string = json)
    }.getOrElse { throw JWTDecodeException(it.message, it) }
}
