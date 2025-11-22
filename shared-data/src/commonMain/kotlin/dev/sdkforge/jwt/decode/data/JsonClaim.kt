@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.exception.JWTDecodeException
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
 * The JsonClaim class implements the Claim interface.
 */
@OptIn(ExperimentalTime::class)
internal class JsonClaim(private val value: JsonElement?) : Claim {

    override val isNull: Boolean = when (value) {
        null -> false
        else -> value is JsonNull
    }

    override val isMissing: Boolean
        get() = value == null

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

    override fun asInstant(): Instant? = when (value) {
        !is JsonPrimitive -> null
        else -> value.jsonPrimitive.longOrNull?.run {
            Instant.fromEpochSeconds(this)
        }
    }

    @Throws(JWTDecodeException::class)
    override fun <T> asList(deserializer: DeserializationStrategy<T>): List<T> {
        try {
            if (value !is JsonArray) {
                return emptyList()
            }

            return List(value.size) { index -> Json.decodeFromJsonElement<T>(deserializer, value[index]) }
        } catch (e: IllegalArgumentException) {
            throw JWTDecodeException("Failed to decode claim as list", e)
        }
    }

    @Throws(JWTDecodeException::class)
    override fun <T> asObject(deserializer: DeserializationStrategy<T>): T? {
        try {
            if (isNull || isMissing) {
                return null
            }

            return Json.decodeFromJsonElement<T>(deserializer, value!!)
        } catch (e: IllegalArgumentException) {
            throw JWTDecodeException("Failed to decode claim", e)
        }
    }

    override fun toString(): String = when {
        this.isMissing -> "Missing claim"
        this.isNull -> "Null claim"
        else -> value.toString()
    }
}
