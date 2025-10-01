@file:Suppress("ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.Payload
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

@OptIn(ExperimentalTime::class)
internal data class JWTPayload(
    override val issuer: String? = null,
    override val subject: String? = null,
    override val expiresAt: Instant? = null,
    override val notBefore: Instant? = null,
    override val issuedAt: Instant? = null,
    override val id: String? = null,
    override val audience: List<String>? = null,
    internal val tree: Map<String, JsonElement> = emptyMap(),
) : Payload {

    override fun getClaim(name: String): Claim {
        return this.tree[name]?.run { JsonClaim(this) } ?: EmptyClaim
    }
}

internal data object JWTPayloadDeserializationStrategy : DeserializationStrategy<JWTPayload> {
    override val descriptor: SerialDescriptor = mapSerialDescriptor<String, JsonElement>()

    @OptIn(ExperimentalTime::class)
    override fun deserialize(decoder: Decoder): JWTPayload {
        val tree = decoder.decodeSerializableValue(
            deserializer = MapSerializer(
                keySerializer = String.serializer(),
                valueSerializer = JsonElement.serializer(),
            ),
        )

        return JWTPayload(
            issuer = tree[Claim.Companion.Registered.ISSUER]?.jsonPrimitive?.contentOrNull,
            subject = tree[Claim.Companion.Registered.SUBJECT]?.jsonPrimitive?.contentOrNull,
            expiresAt = tree[Claim.Companion.Registered.EXPIRES_AT]?.asInstant(),
            notBefore = tree[Claim.Companion.Registered.NOT_BEFORE]?.asInstant(),
            issuedAt = tree[Claim.Companion.Registered.ISSUED_AT]?.asInstant(),
            id = tree[Claim.Companion.Registered.JWT_ID]?.jsonPrimitive?.contentOrNull,
            audience = tree[Claim.Companion.Registered.AUDIENCE]?.asAudience(),
            tree = tree,
        )
    }
}

@OptIn(ExperimentalTime::class)
private fun JsonElement.asInstant(): Instant? {
    return when (val value = this) {
        is JsonPrimitive -> value.longOrNull?.run { Instant.fromEpochSeconds(this) }
        else -> null
    }
}

@OptIn(ExperimentalTime::class)
private fun JsonElement.asAudience(): List<String>? {
    return when (val value = this) {
        is JsonPrimitive -> listOfNotNull(value.contentOrNull)
        is JsonArray -> value.mapNotNull { it.jsonPrimitive.contentOrNull }
        else -> null
    }
}
