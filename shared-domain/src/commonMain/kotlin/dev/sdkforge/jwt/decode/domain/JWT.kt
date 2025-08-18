@file:Suppress("ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

package dev.sdkforge.jwt.decode.domain

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.serialization.json.Json

/**
 * Wrapper class for values contained inside a Json Web Token (JWT).
 */
@OptIn(ExperimentalTime::class)
class JWT(private var token: String) {

    private val json: Json = Json { ignoreUnknownKeys = true }

    private var payload: JWTPayload? = null

    /**
     * Decode a given string JWT token.
     *
     * @param token the string JWT token.
     * @throws DecodeException if the token cannot be decoded
     */
    init {
        decode(token)

        this.token = token
    }

    /**
     * Get the Header values from this JWT as a Map of Strings.
     *
     * @return the Header values of the JWT.
     */
    var header: Map<String?, String?>? = null
        private set

    /**
     * Get the Signature from this JWT as a Base64 encoded String.
     *
     * @return the Signature of the JWT.
     */
    var signature: String? = null
        private set

    /**
     * Get the value of the "iss" claim, or null if it's not available.
     *
     * @return the Issuer value or null.
     */
    val issuer: String? get() = payload?.iss

    /**
     * Get the value of the "sub" claim, or null if it's not available.
     *
     * @return the Subject value or null.
     */
    val subject: String? get() = payload?.sub

    /**
     * Get the value of the "aud" claim, or an empty list if it's not available.
     *
     * @return the Audience value or an empty list.
     */
    val audience: List<String?> get() = payload?.aud.orEmpty()

    /**
     * Get the value of the "exp" claim, or null if it's not available.
     *
     * @return the Expiration Time value or null.
     */
    val expiresAt: Instant? get() = payload?.exp

    /**
     * Get the value of the "nbf" claim, or null if it's not available.
     *
     * @return the Not Before value or null.
     */
    val notBefore: Instant? get() = payload?.nbf

    /**
     * Get the value of the "iat" claim, or null if it's not available.
     *
     * @return the Issued At value or null.
     */
    val issuedAt: Instant? get() = payload?.iat

    /**
     * Get the value of the "jti" claim, or null if it's not available.
     *
     * @return the JWT ID value or null.
     */
    val id: String? get() = payload?.jti

    /**
     * Get a Claim given it's name. If the Claim wasn't specified in the JWT payload, a BaseClaim will be returned.
     *
     * @param name the name of the Claim to retrieve.
     * @return a valid Claim.
     */
    fun getClaim(name: String): Claim {
        return payload?.claimForName(name) ?: BaseClaim()
    }

    /**
     * Get all the Claims.
     *
     * @return a valid Map of Claims.
     */
    val claims: Map<String, Claim>? get() = payload?.tree.orEmpty()

    /**
     * Validates that this JWT was issued in the past and hasn't expired yet.
     *
     * @param leeway the time leeway in seconds in which the token should still be considered valid.
     * @return if this JWT has already expired or not.
     */
    fun isExpired(leeway: Duration): Boolean {
        require(leeway.inWholeSeconds >= 0) { "The leeway must be a positive value." }
        val todayTime = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
        val futureToday = (todayTime + leeway)
        val pastToday = (todayTime - leeway)
        val exp = payload?.exp
        val iat = payload?.iat
        val expValid = exp == null || pastToday <= exp
        val iatValid = iat == null || futureToday >= iat
        return !expValid || !iatValid
    }

    /**
     * Returns the String representation of this JWT.
     *
     * @return the String Token.
     */
    override fun toString(): String = token

    // =====================================
    // ===========Private Methods===========
    // =====================================
    private fun decode(token: String) {
        val parts = splitToken(token)

        header = parseJson<Map<String?, String?>?>(base64Decode(parts[0]))
        payload = parseJson<JWTPayload>(base64Decode(parts[1]))
        signature = parts[2]
    }

    private fun splitToken(token: String): List<String> {
        var parts: List<String> = token.split('.')
        if (parts.size == 2 && token.endsWith('.')) {
            // Tokens with alg='none' have empty String as Signature.
            parts = listOf<String>(parts[0], parts[1], "")
        }
        if (parts.size != 3) {
            throw DecodeException("The token was expected to have 3 parts, but got ${parts.size}.")
        }
        return parts
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun base64Decode(string: String?): String? {
        string ?: return null

        try {
            return base64Decoder.decode(string).decodeToString()
        } catch (e: IllegalArgumentException) {
            throw DecodeException("Received bytes didn't correspond to a valid Base64 encoded string.", e)
        }
    }

    private inline fun <reified T> parseJson(json: String?): T? {
        json ?: return null

        try {
            return this.json.decodeFromString(json)
        } catch (e: Exception) {
            throw DecodeException("The token's payload had an invalid JSON format.", e)
        }
    }

    companion object {
        private val TAG: String? = JWT::class.simpleName
        private val base64Decoder = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
    }
}
