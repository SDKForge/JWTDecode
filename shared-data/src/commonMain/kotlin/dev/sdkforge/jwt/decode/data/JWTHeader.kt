@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.Header
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.mapSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * The JWTHeader class implements the Header interface.
 */
internal class JWTHeader(
    override val algorithm: String? = null,
    override val type: String? = null,
    override val contentType: String? = null,
    override val keyId: String? = null,
    internal val tree: Map<String, JsonElement> = emptyMap(),
) : Header {

    override fun getHeaderClaim(name: String): Claim {
        // TODO: add registered claims return?
        return tree[name]?.run { JsonClaim(this) } ?: EmptyClaim
    }
}

internal object JWTHeaderSerializerDeserializationStrategy : DeserializationStrategy<JWTHeader> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor = mapSerialDescriptor<String, JsonElement>()

    override fun deserialize(decoder: Decoder): JWTHeader {
        val tree = decoder.decodeSerializableValue(
            deserializer = MapSerializer(
                keySerializer = String.serializer(),
                valueSerializer = JsonElement.serializer(),
            ),
        )

        return JWTHeader(
            algorithm = tree[Header.Companion.Params.ALGORITHM]?.jsonPrimitive?.contentOrNull,
            type = tree[Header.Companion.Params.TYPE]?.jsonPrimitive?.contentOrNull,
            contentType = tree[Header.Companion.Params.CONTENT_TYPE]?.jsonPrimitive?.contentOrNull,
            keyId = tree[Header.Companion.Params.KEY_ID]?.jsonPrimitive?.contentOrNull,
            tree = tree,
        )
    }
}
