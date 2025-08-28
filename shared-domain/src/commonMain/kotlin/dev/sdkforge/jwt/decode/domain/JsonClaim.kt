@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * The ClaimImpl class implements the Claim interface.
 */
@OptIn(ExperimentalTime::class)
internal class JsonClaim(private val value: JsonElement) : BaseClaim() {

    override fun asBoolean(): Boolean? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.booleanOrNull
    }

    override fun asInt(): Int? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.intOrNull
    }

    override fun asLong(): Long? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.longOrNull
    }

    override fun asDouble(): Double? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.doubleOrNull
    }

    override fun asString(): String? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.content
    }

    override fun asDate(): Instant? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.longOrNull?.run {
            Instant.fromEpochSeconds(this)
        }
    }

    @Throws(DecodeException::class)
    override fun <T> asList(deserializer: DeserializationStrategy<T>): List<T> {
        try {
            if (value !is JsonArray) {
                return emptyList()
            }

            return List(value.size) { index -> Json.decodeFromJsonElement<T>(deserializer, value[index]) }
        } catch (e: IllegalArgumentException) {
            throw DecodeException("Failed to decode claim as list", e)
        }
    }

    @Throws(DecodeException::class)
    override fun <T> asObject(deserializer: DeserializationStrategy<T>): T? {
        try {
            if (value is JsonNull) {
                return null
            }

            return Json.decodeFromJsonElement<T>(deserializer, value)
        } catch (e: IllegalArgumentException) {
            throw DecodeException("Failed to decode claim", e)
        }
    }
}
