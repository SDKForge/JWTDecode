@file:Suppress("ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

package dev.sdkforge.jwt.decode.domain

import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json

@OptIn(ExperimentalTime::class)
@Serializable
internal class JWTPayload(
    @SerialName("iss") val iss: String? = null,
    @SerialName("sub") val sub: String? = null,
    @Serializable(with = InstantAsStringSerializer::class) @SerialName("exp") val exp: Instant? = null,
    @Serializable(with = InstantAsStringSerializer::class) @SerialName("nbf") val nbf: Instant? = null,
    @Serializable(with = InstantAsStringSerializer::class) @SerialName("iat") val iat: Instant? = null,
    @SerialName("jti") val jti: String? = null,
    @Serializable(with = AudienceAsStringSerializer::class) @SerialName("aud") val aud: List<String>? = null,
    @Serializable(with = ClaimAsMapSerializer::class) @SerialName("tree") val tree: Map<String, Claim>? = null,
) {
    internal fun claimForName(name: String): Claim {
        return this.tree?.get(name) ?: BaseClaim()
    }
}

@OptIn(ExperimentalTime::class)
object InstantAsStringSerializer : KSerializer<Instant> {
    // Serial names of descriptors should be unique, this is why we advise including app package in the name.
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor("dev.sdkforge.jwt.decode.domain.Instant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeString(value.epochSeconds.toString())
    }

    override fun deserialize(decoder: Decoder): Instant {
        val seconds = decoder.decodeString()
        return Instant.fromEpochSeconds(seconds.toLong())
    }
}

object ClaimAsStringSerializer : KSerializer<Claim> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor("dev.sdkforge.jwt.decode.domain.Claim", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Claim) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): Claim {
        return JsonClaim(Json.parseToJsonElement(decoder.decodeString()))
    }
}

object ClaimAsMapSerializer : KSerializer<Map<String, Claim>> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor
        get() = mapSerialDescriptor<String, Claim>()

    override fun serialize(encoder: Encoder, value: Map<String, Claim>) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): Map<String, Claim> {
        return decoder.decodeSerializableValue<Map<String, Claim>>(MapSerializer(String.serializer(), Claim.serializer()))
    }
}

object AudienceAsStringSerializer : KSerializer<List<String>> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor
        get() = listSerialDescriptor<String>()

    override fun serialize(encoder: Encoder, value: List<String>) {
        encoder.encodeString(value.toString())
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun deserialize(decoder: Decoder): List<String> {
        val singleAudience = decoder.decodeNullableSerializableValue<String>(String.serializer())

        if (singleAudience != null) return listOf(singleAudience)

        return decoder.decodeSerializableValue<List<String>>(ListSerializer(String.serializer()))
    }
}
