@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.data.algorithm.SigningAlgorithm
import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.Header
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.JWTCreationException
import dev.sdkforge.jwt.decode.domain.exception.SignatureGenerationException
import kotlin.io.encoding.Base64
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature)
 * from a given Header and Payload content.
 */
@OptIn(ExperimentalTime::class)
internal class JWTCreator private constructor(
    private val algorithm: Algorithm,
    headerClaims: Map<String, JsonElement>?,
    payloadClaims: Map<String, JsonElement>?,
) {
    private val headerJson: String
    private val payloadJson: String

    init {
        try {
            headerJson = JWTParser.JSON.encodeToString(headerClaims)
            payloadJson = JWTParser.JSON.encodeToString(payloadClaims)
        } catch (e: Throwable) {
            throw JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e)
        }
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    class Builder internal constructor() {
        private val payloadClaims = mutableMapOf<String, JsonElement>()
        private val headerClaims = mutableMapOf<String, JsonElement>()

        /**
         * Add specific Claims to set as the Header.
         * If provided map is null then nothing is changed
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        fun withHeader(headerClaims: Map<String, Any?>?): Builder {
            if (headerClaims == null) {
                return this
            }

            for (entry in headerClaims.entries) {
                if (entry.value == null) {
                    this.headerClaims[entry.key] = JsonNull
                } else {
                    this.headerClaims[entry.key] = entry.value.asJsonPrimitive
                }
            }

            return this
        }

        /**
         * Add specific Claims to set as the Header.
         * If provided json is null then nothing is changed
         *
         * @param headerClaimsJson the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if json value has invalid structure
         */
        @Throws(IllegalArgumentException::class)
        fun withHeader(headerClaimsJson: String?): Builder {
            if (headerClaimsJson == null) {
                return this
            }

            try {
                val headerClaims: Map<String, JsonElement>? = JWTParser.JSON.decodeFromString(headerClaimsJson)
                return withHeader(headerClaims)
            } catch (e: Throwable) {
                throw IllegalArgumentException("Invalid header JSON", e)
            }
        }

        /**
         * Add a specific Key Id ("kid") claim to the Header.
         * If the [Algorithm] used to sign this token was instantiated with a KeyProvider,
         * the 'kid' value will be taken from that provider and this one will be ignored.
         *
         * @param keyId the Key Id value.
         * @return this same Builder instance.
         */
        fun withKeyId(keyId: String?): Builder = apply {
            this.headerClaims[Header.Companion.Params.KEY_ID] = keyId.asJsonPrimitive
        }

        /**
         * Add a specific Issuer ("iss") claim to the Payload.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        fun withIssuer(issuer: String?): Builder = apply {
            addClaim(Claim.Companion.Registered.ISSUER, issuer)
        }

        /**
         * Add a specific Subject ("sub") claim to the Payload.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        fun withSubject(subject: String?): Builder = apply {
            addClaim(Claim.Companion.Registered.SUBJECT, subject)
        }

        /**
         * Add a specific Audience ("aud") claim to the Payload.
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        fun withAudience(vararg audience: String?): Builder = apply {
            if (audience.asList().size == 1) {
                addClaim(Claim.Companion.Registered.AUDIENCE, audience[0])
                return this
            }

            addClaim(Claim.Companion.Registered.AUDIENCE, audience)
        }

        /**
         * Add a specific Expires At ("exp") claim to the payload. The claim will be written as seconds since the epoch.
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        fun withExpiresAt(expiresAt: LocalDate?): Builder = apply {
            addClaim(Claim.Companion.Registered.EXPIRES_AT, expiresAt)
        }

        /**
         * Add a specific Expires At ("exp") claim to the payload. The claim will be written as seconds since the epoch;
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        fun withExpiresAt(expiresAt: Instant?): Builder = apply {
            addClaim(Claim.Companion.Registered.EXPIRES_AT, expiresAt)
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload. The claim will be written as seconds since the epoch;
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        fun withNotBefore(notBefore: LocalDate?): Builder = apply {
            addClaim(Claim.Companion.Registered.NOT_BEFORE, notBefore)
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload. The claim will be written as seconds since the epoch;
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        fun withNotBefore(notBefore: Instant?): Builder = apply {
            addClaim(Claim.Companion.Registered.NOT_BEFORE, notBefore)
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload. The claim will be written as seconds since the epoch;
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        fun withIssuedAt(issuedAt: LocalDate?): Builder = apply {
            addClaim(Claim.Companion.Registered.ISSUED_AT, issuedAt)
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload. The claim will be written as seconds since the epoch;
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        fun withIssuedAt(issuedAt: Instant?): Builder = apply {
            addClaim(Claim.Companion.Registered.ISSUED_AT, issuedAt)
        }

        /**
         * Add a specific JWT Id ("jti") claim to the Payload.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        fun withJWTId(jwtId: String?): Builder = apply {
            addClaim(Claim.Companion.Registered.JWT_ID, jwtId)
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: Boolean?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: Int?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: Long?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: Double?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: String?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value. The claim will be written as seconds since the epoch.
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: LocalDate?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Claim value. The claim will be written as seconds since the epoch.
         * Milliseconds will be truncated by rounding down to the nearest second.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, value: Instant?): Builder = apply {
            addClaim(name, value)
        }

        /**
         * Add a custom Map Claim with the given items.
         *
         *
         * Accepted nested types are [Map] and [List] with basic types
         * [Boolean], [Int], [Long], [Double],
         * [String] and [Instant]. [Map]s cannot contain null keys or values.
         * [List]s can contain null elements.
         *
         * @param name the Claim's name.
         * @param map  the Claim's key-values.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null, or if the map contents does not validate.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, map: Map<String, *>?): Builder = apply {
            // validate map contents
            require(!(map != null && !validateClaim(map))) {
                "Expected map containing Map, List, Boolean, Int, Long, Double, String and Instant"
            }
            addClaim(name, map)
        }

        /**
         * Add a custom List Claim with the given items.
         *
         * Accepted nested types are [Map] and [List] with basic types
         * [Boolean], [Int], [Long], [Double],
         * [String] and [Instant]. [Map]s cannot contain null keys or values.
         * [List]s can contain null elements.
         *
         * @param name the Claim's name.
         * @param list the Claim's list of values.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null, or if the list contents does not validate.
         */
        @Throws(IllegalArgumentException::class)
        fun withClaim(name: String, list: List<*>?): Builder = apply {
            // validate list contents
            require(!(list != null && !validateClaim(list))) {
                "Expected list containing Map, List, Boolean, Int, Long, Double, String and Date"
            }
            addClaim(name, list)
        }

        /**
         * Add a custom claim with null value.
         *
         * @param name the Claim's name.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null
         */
        @Throws(IllegalArgumentException::class)
        fun withNullClaim(name: String): Builder = apply {
            addClaim(name, null)
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withArrayClaim(name: String, items: Array<String?>?): Builder = apply {
            addClaim(name, items)
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        @Throws(IllegalArgumentException::class)
        fun withArrayClaim(name: String, items: Array<Int?>?): Builder = apply {
            addClaim(name, items)
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null
         */
        @Throws(IllegalArgumentException::class)
        fun withArrayClaim(name: String, items: Array<Long?>?): Builder = apply {
            addClaim(name, items)
        }

        /**
         * Add specific Claims to set as the Payload. If the provided map is null then
         * nothing is changed.
         *
         * Accepted types are [Map] and [List] with basic types
         * [Boolean], [Int], [Long], [Double],
         * [String] and [Instant].
         * [Map]s and [List]s can contain null elements.
         *
         * If any of the claims are invalid, none will be added.
         *
         * @param payloadClaims the values to use as Claims in the token's payload.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if any of the claim keys or null,
         * or if the values are not of a supported type.
         */
        @Throws(IllegalArgumentException::class)
        fun withPayload(payloadClaims: Map<String, *>): Builder = apply {
            require(validatePayload(payloadClaims)) {
                "Claim values must only be of types Map, List, Boolean, Int, Long, Double, String, Instant, and Null"
            }

            // add claims only after validating all claims so as not to corrupt the claims map of this builder
            for (entry in payloadClaims.entries) {
                addClaim(entry.key, entry.value)
            }
        }

        /**
         * Add specific Claims to set as the Payload. If the provided json is null then
         * nothing is changed.
         *
         * If any of the claims are invalid, none will be added.
         *
         * @param payloadClaimsJson the values to use as Claims in the token's payload.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if any of the claim keys or null,
         * or if the values are not of a supported type,
         * or if json value has invalid structure.
         */
        @Throws(IllegalArgumentException::class)
        fun withPayload(payloadClaimsJson: String?): Builder = apply {
            if (payloadClaimsJson == null) {
                return@apply
            }

            try {
                val payloadClaims: Map<String, JsonElement> = JWTParser.JSON.decodeFromString(payloadClaimsJson)
                return withPayload(payloadClaims)
            } catch (e: Throwable) {
                throw IllegalArgumentException("Invalid payload JSON", e)
            }
        }

        private fun validatePayload(payload: Map<String, *>): Boolean {
            for (entry in payload.entries) {
                val value: Any? = entry.value
                if (value is List<*> && !validateClaim((value as List<*>?)!!)) {
                    return false
                } else if (value is Map<*, *> && !validateClaim((value as Map<*, *>?)!!)) {
                    return false
                } else if (!isSupportedType(value)) {
                    return false
                }
            }
            return true
        }

        /**
         * Creates a new JWT and signs it with the given algorithm.
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws dev.sdkforge.jwt.decode.domain.exception.JWTCreationException     if the claims could not be converted to a valid JSON
         * or there was a problem with the signing key.
         */
        @Throws(IllegalArgumentException::class, JWTCreationException::class)
        fun sign(algorithm: Algorithm): String {
            headerClaims[Header.Companion.Params.ALGORITHM] = algorithm.name.asJsonPrimitive

            if (!headerClaims.containsKey(Header.Companion.Params.TYPE)) {
                headerClaims[Header.Companion.Params.TYPE] = "JWT".asJsonPrimitive
            }

            val signingKeyId = (algorithm as? SigningAlgorithm)?.signingKeyId

            if (signingKeyId != null) {
                withKeyId(signingKeyId)
            }

            return JWTCreator(algorithm, headerClaims, payloadClaims).sign()
        }

        private fun addClaim(name: String, value: Any?) {
            payloadClaims[name] = value.asJsonPrimitive
        }

        companion object {
            private fun validateClaim(map: Map<*, *>): Boolean {
                // do not accept null values in maps
                for (entry in map.entries) {
                    val value: Any? = entry.value
                    if (!isSupportedType(value)) {
                        return false
                    }

                    if (entry.key !is String) {
                        return false
                    }
                }
                return true
            }

            private fun validateClaim(list: List<*>): Boolean {
                // accept null values in list
                for (`object` in list) {
                    if (!isSupportedType(`object`)) {
                        return false
                    }
                }
                return true
            }

            private fun isSupportedType(value: Any?): Boolean = when (value) {
                is List<*> -> validateClaim(value)
                is Map<*, *> -> validateClaim(value)
                is Array<*> -> value.all(::isSupportedType)
                else -> isBasicType(value)
            }

            private fun isBasicType(value: Any?): Boolean = when (value) {
                null -> true
                is JsonElement -> true
                is Instant -> true
                is Boolean,
                is Int,
                is Long,
                is Double,
                is String,
                -> true

                else -> false
            }
        }
    }

    @Throws(SignatureGenerationException::class)
    private fun sign(): String {
        val header: String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(headerJson.encodeToByteArray())
        val payload: String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(payloadJson.encodeToByteArray())

        if (algorithm !is SigningAlgorithm) {
            throw SignatureGenerationException(algorithm, IllegalArgumentException("Algorithm must implement SigningAlgorithm"))
        }

        val signatureBytes = algorithm.sign(
            headerBytes = header.encodeToByteArray(),
            payloadBytes = payload.encodeToByteArray(),
        )
        val signature: String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(signatureBytes)

        return "$header.$payload.$signature"
    }

    companion object {
        /**
         * Initialize a JWTCreator instance.
         *
         * @return a JWTCreator.Builder instance to configure.
         */
        fun init(): Builder = Builder()
    }
}

@OptIn(ExperimentalTime::class)
private val Any?.asJsonPrimitive: JsonElement
    get() = when (this) {
        null -> JsonNull
        is JsonPrimitive -> this
        is JsonObject -> this
        is String? -> JsonPrimitive(this)
        is Number? -> JsonPrimitive(this)
        is Boolean? -> JsonPrimitive(this)
        is Instant -> JsonPrimitive(this.epochSeconds)
        is Array<*> -> JsonArray(this.map { it.asJsonPrimitive })
        is List<*> -> JsonArray(this.map { it.asJsonPrimitive })
        is Map<*, *> -> buildJsonObject {
            this@asJsonPrimitive.forEach { (key, value) ->
                if (key !is String) {
                    throw IllegalArgumentException("Map keys must be Strings")
                }
                put(key, value.asJsonPrimitive)
            }
        }

        else -> throw IllegalArgumentException("Unsupported type: ${this::class.simpleName}")
    }
