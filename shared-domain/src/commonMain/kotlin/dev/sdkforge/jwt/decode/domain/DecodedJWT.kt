@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.domain

import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Class that represents a Json Web Token that was decoded from it's string representation.
 */
interface DecodedJWT :
    Payload,
    Header {
    /**
     * Getter for the String Token used to create this JWT instance.
     *
     * @return the String Token.
     */
    val token: String

    /**
     * Getter for the Header contained in the JWT as a Base64 encoded String.
     * This represents the first part of the token.
     *
     * @return the Header of the JWT.
     */
    val header: String

    /**
     * Getter for the Payload contained in the JWT as a Base64 encoded String.
     * This represents the second part of the token.
     *
     * @return the Payload of the JWT.
     */
    val payload: String

    /**
     * Getter for the Signature contained in the JWT as a Base64 encoded String.
     * This represents the third part of the token.
     *
     * @return the Signature of the JWT.
     */
    val signature: String
}

@OptIn(ExperimentalTime::class)
fun DecodedJWT.isExpired(leeway: Duration): Boolean {
    require(leeway.inWholeSeconds >= 0) { "The leeway must be a positive value." }

    val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
    val future: Instant = now + leeway
    val past: Instant = now - leeway
    val expiresAt = expiresAt
    val issuedAt = issuedAt
    val expValid = expiresAt == null || past <= expiresAt
    val iatValid = issuedAt == null || future >= issuedAt

    return !expValid || !iatValid
}
