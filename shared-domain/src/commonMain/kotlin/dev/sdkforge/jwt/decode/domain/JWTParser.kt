@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException

/**
 * The JWTParser class defines which parts of the JWT should be converted
 * to its specific Object representation instance.
 */
interface JWTParser {
    /**
     * Parses the given JSON into a [Payload] instance.
     *
     * @param json the content of the Payload in a JSON representation.
     * @return the Payload.
     * @throws JWTDecodeException if the json doesn't have a proper JSON format.
     */
    @Throws(JWTDecodeException::class)
    fun parsePayload(json: String): Payload

    /**
     * Parses the given JSON into a [Header] instance.
     *
     * @param json the content of the Header in a JSON representation.
     * @return the Header.
     * @throws JWTDecodeException if the json doesn't have a proper JSON format.
     */
    @Throws(JWTDecodeException::class)
    fun parseHeader(json: String): Header
}
