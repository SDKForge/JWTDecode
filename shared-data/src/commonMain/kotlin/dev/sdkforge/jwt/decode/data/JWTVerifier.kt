@file:Suppress("ktlint:standard:class-signature", "ktlint:standard:function-signature", "ktlint:standard:function-expression-body")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.data.algorithm.VerificationAlgorithm
import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.DecodedJWT
import dev.sdkforge.jwt.decode.domain.Verification
import dev.sdkforge.jwt.decode.domain.algorithm.Algorithm
import dev.sdkforge.jwt.decode.domain.exception.AlgorithmMismatchException
import dev.sdkforge.jwt.decode.domain.exception.IncorrectClaimException
import dev.sdkforge.jwt.decode.domain.exception.InvalidClaimException
import dev.sdkforge.jwt.decode.domain.exception.JWTVerificationException
import dev.sdkforge.jwt.decode.domain.exception.MissingClaimException
import dev.sdkforge.jwt.decode.domain.exception.TokenExpiredException
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atTime
import kotlinx.datetime.toInstant
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * The JWTVerifier class holds the verify method to assert that a given Token has not only a proper JWT format,
 * but also its signature matches.
 *
 * @see dev.sdkforge.jwt.decode.domain.JWTVerifier
 */
internal class JWTVerifier internal constructor(
    private val algorithm: Algorithm,
    internal val expectedChecks: List<ExpectedCheckHolder>,
) : dev.sdkforge.jwt.decode.domain.JWTVerifier {

    private val parser: JWTParser = JWTParser

    /**
     * [Verification] implementation that accepts all the expected Claim values for verification, and
     * builds a [dev.sdkforge.jwt.decode.domain.JWTVerifier] used to verify a JWT's signature and expected claims.
     *
     * Note that this class is **not** thread-safe. Calling [.build] returns an instance of
     * [dev.sdkforge.jwt.decode.domain.JWTVerifier] which can be reused.
     */
    @OptIn(ExperimentalTime::class)
    internal class BaseVerification internal constructor(private val algorithm: Algorithm) : Verification {
        private val expectedChecks = mutableListOf<ExpectedCheckHolder>()
        private var defaultLeeway: Long = 0
        private val customLeewayMap = mutableMapOf<String, Long>()
        private var ignoreIssuedAt = false
        private var instant: Instant? = null

        override fun withIssuer(vararg issuer: String): Verification = apply {
            val value: List<String> = issuer.asList()

            addCheck(Claim.Companion.Registered.ISSUER) { claim, decodedJWT ->
                if (verifyNull(claim, value) || value.isEmpty()) {
                    return@addCheck true
                } else if (!value.contains(claim.asString())) {
                    throw IncorrectClaimException(
                        "The Claim 'iss' value doesn't match the required issuer.",
                        Claim.Companion.Registered.ISSUER,
                        claim,
                    )
                }
                true
            }
        }

        override fun withSubject(subject: String): Verification = apply {
            addCheck(Claim.Companion.Registered.SUBJECT) { claim, decodedJWT ->
                verifyNull(claim, subject) || subject == claim.asString()
            }
        }

        override fun withAudience(vararg audience: String): Verification = apply {
            val value: List<String>? = audience.asList().ifEmpty { null }

            addCheck(Claim.Companion.Registered.AUDIENCE) { claim, decodedJWT ->
                if (verifyNull(claim, value)) {
                    return@addCheck true
                }
                if (!assertValidAudienceClaim(decodedJWT.audience, value, true)) {
                    throw IncorrectClaimException(
                        message = "The Claim 'aud' value doesn't contain the required audience.",
                        claimName = Claim.Companion.Registered.AUDIENCE,
                        claim = claim,
                    )
                }
                true
            }
        }

        override fun withAnyOfAudience(vararg audience: String): Verification = apply {
            val value: List<String>? = audience.asList().ifEmpty { null }

            addCheck(Claim.Companion.Registered.AUDIENCE) { claim, decodedJWT ->
                if (verifyNull(claim, value)) {
                    return@addCheck true
                }
                if (!assertValidAudienceClaim(decodedJWT.audience, value, false)) {
                    throw IncorrectClaimException(
                        message = "The Claim 'aud' value doesn't contain the required audience.",
                        claimName = Claim.Companion.Registered.AUDIENCE,
                        claim = claim,
                    )
                }
                true
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun acceptLeeway(leeway: Long): Verification = apply {
            assertPositive(leeway)
            this.defaultLeeway = leeway
        }

        @Throws(IllegalArgumentException::class)
        override fun acceptExpiresAt(leeway: Long): Verification = apply {
            assertPositive(leeway)
            customLeewayMap[Claim.Companion.Registered.EXPIRES_AT] = leeway
        }

        @Throws(IllegalArgumentException::class)
        override fun acceptNotBefore(leeway: Long): Verification = apply {
            assertPositive(leeway)
            customLeewayMap[Claim.Companion.Registered.NOT_BEFORE] = leeway
        }

        @Throws(IllegalArgumentException::class)
        override fun acceptIssuedAt(leeway: Long): Verification = apply {
            assertPositive(leeway)
            customLeewayMap[Claim.Companion.Registered.ISSUED_AT] = leeway
        }

        override fun ignoreIssuedAt(): Verification = apply {
            this.ignoreIssuedAt = true
        }

        override fun withJWTId(jwtId: String): Verification = apply {
            addCheck(Claim.Companion.Registered.JWT_ID) { claim, decodedJWT ->
                verifyNull(claim, jwtId) || jwtId == claim.asString()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaimPresence(name: String): Verification = apply {
            // since addCheck already checks presence, we just return true
            withClaim(name) { claim, decodedJWT -> true }
        }

        @Throws(IllegalArgumentException::class)
        override fun withNullClaim(name: String): Verification = apply {
            withClaim(name) { claim, decodedJWT -> claim.isNull }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: Boolean): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || value == claim.asBoolean()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: Int): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || value == claim.asInt()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: Long): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || value == claim.asLong()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: Double): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || value == claim.asDouble()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: String): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || value == claim.asString()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: LocalDate): Verification = apply {
            return withClaim(name, value.atTime(hour = 0, minute = 0).toInstant(TimeZone.UTC))
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, value: Instant): Verification = apply {
            // Since date-time claims are serialized as epoch seconds,
            // we need to compare them with only seconds-granularity
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, value) || Instant.fromEpochSeconds(value.epochSeconds) == claim.asInstant()
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withClaim(name: String, predicate: Function2<Claim, DecodedJWT, Boolean>): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, predicate) || predicate.invoke(claim, decodedJWT)
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withArrayClaim(name: String, vararg items: String): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, items) || assertValidCollectionClaim(claim, items) { it.jsonPrimitive.content }
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withArrayClaim(name: String, vararg items: Int): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, items) || assertValidCollectionClaim(claim, items.toTypedArray()) { it.jsonPrimitive.int }
            }
        }

        @Throws(IllegalArgumentException::class)
        override fun withArrayClaim(name: String, vararg items: Long): Verification = apply {
            addCheck(name) { claim, decodedJWT ->
                verifyNull(claim, items) || assertValidCollectionClaim(claim, items.toTypedArray()) { it.jsonPrimitive.long }
            }
        }

        override fun build(): JWTVerifier {
            return this.build(instant = Clock.System.now())
        }

        /**
         * Creates a new and reusable instance of the JWTVerifier with the configuration already provided.
         * ONLY FOR TEST PURPOSES.
         *
         * @param instant the instance that will handle the current time.
         * @return a new JWTVerifier instance with a custom [Instant]
         */
        fun build(instant: Instant): JWTVerifier {
            this.instant = instant
            addMandatoryClaimChecks()
            return JWTVerifier(algorithm, expectedChecks)
        }

        /**
         * Fetches the Leeway set for claim or returns the [BaseVerification.defaultLeeway].
         *
         * @param name Claim for which leeway is fetched
         * @return Leeway value set for the claim
         */
        fun getLeewayFor(name: String): Long {
            return customLeewayMap.getOrElse(name) { defaultLeeway }
        }

        private fun addMandatoryClaimChecks() {
            val expiresAtLeeway = getLeewayFor(Claim.Companion.Registered.EXPIRES_AT)
            val notBeforeLeeway = getLeewayFor(Claim.Companion.Registered.NOT_BEFORE)
            val issuedAtLeeway = getLeewayFor(Claim.Companion.Registered.ISSUED_AT)

            expectedChecks.add(
                constructExpectedCheck(Claim.Companion.Registered.EXPIRES_AT) { claim, decodedJWT ->
                    assertValidInstantClaim(
                        claimName = Claim.Companion.Registered.EXPIRES_AT,
                        claim = claim,
                        leeway = expiresAtLeeway,
                        shouldBeFuture = true,
                    )
                },
            )
            expectedChecks.add(
                constructExpectedCheck(Claim.Companion.Registered.NOT_BEFORE) { claim, decodedJWT ->
                    assertValidInstantClaim(
                        claimName = Claim.Companion.Registered.NOT_BEFORE,
                        claim = claim,
                        leeway = notBeforeLeeway,
                        shouldBeFuture = false,
                    )
                },
            )
            if (!ignoreIssuedAt) {
                expectedChecks.add(
                    constructExpectedCheck(Claim.Companion.Registered.ISSUED_AT) { claim, decodedJWT ->
                        assertValidInstantClaim(
                            claimName = Claim.Companion.Registered.ISSUED_AT,
                            claim = claim,
                            leeway = issuedAtLeeway,
                            shouldBeFuture = false,
                        )
                    },
                )
            }
        }

        private fun assertValidCollectionClaim(
            claim: Claim,
            expectedClaimValue: Array<*>,
            mapper: (JsonElement) -> Any,
        ): Boolean {
            val claimArr: List<Any> = claim.asList(JsonElement.serializer()).map(mapper)
            val valueArr: List<Any?> = expectedClaimValue.asList()
            return claimArr.containsAll(valueArr)
        }

        private fun assertValidInstantClaim(
            claimName: String,
            claim: Claim?,
            leeway: Long,
            shouldBeFuture: Boolean,
        ): Boolean {
            val claimVal: Instant? = claim?.asInstant()
            val now: Instant = Instant.fromEpochSeconds(instant!!.epochSeconds)
            val isValid: Boolean
            if (shouldBeFuture) {
                isValid = assertInstantIsFuture(claimVal, leeway, now)
                if (!isValid) {
                    throw TokenExpiredException(
                        "The Token has expired on $claimVal.",
                        claimVal,
                    )
                }
            } else {
                isValid = assertInstantIsLessThanOrEqualToNow(claimVal, leeway, now)
                if (!isValid) {
                    throw IncorrectClaimException(
                        "The Token can't be used before $claimVal.",
                        claimName,
                        claim,
                    )
                }
            }
            return true
        }

        private fun assertInstantIsFuture(claimVal: Instant?, leeway: Long, now: Instant): Boolean {
            return claimVal == null || now.minus(leeway.seconds) < claimVal
        }

        private fun assertInstantIsLessThanOrEqualToNow(
            claimVal: Instant?,
            leeway: Long,
            now: Instant,
        ): Boolean {
            return !(claimVal != null && now.plus(leeway.seconds) < claimVal)
        }

        private fun assertValidAudienceClaim(
            actualAudience: List<String?>?,
            expectedAudience: List<String?>?,
            shouldContainAll: Boolean,
        ): Boolean = when {
            actualAudience == null -> false
            expectedAudience == null -> false
            shouldContainAll -> actualAudience.containsAll(expectedAudience)
            else -> !disjoint(actualAudience, expectedAudience)
        }

        private fun assertPositive(leeway: Long) {
            require(leeway >= 0) { "Leeway value can't be negative." }
        }

        private fun addCheck(name: String, predicate: Function2<Claim, DecodedJWT, Boolean>) {
            expectedChecks.add(
                constructExpectedCheck(name) { claim, decodedJWT ->
                    if (claim.isMissing) {
                        throw MissingClaimException(name)
                    }
                    predicate.invoke(claim, decodedJWT)
                },
            )
        }

        private fun constructExpectedCheck(
            claimName: String,
            check: Function2<Claim, DecodedJWT, Boolean>,
        ): ExpectedCheckHolder = object : ExpectedCheckHolder {
            override val claimName: String get() = claimName
            override fun verify(claim: Claim, decodedJWT: DecodedJWT): Boolean = check.invoke(claim, decodedJWT)
        }

        private fun verifyNull(claim: Claim, value: Any?): Boolean {
            return value == null && claim.isNull
        }
    }

    /**
     * Perform the verification against the given Token, using any previous configured options.
     *
     * @param token to verify.
     * @return a verified and decoded JWT.
     * @throws dev.sdkforge.jwt.decode.domain.exception.AlgorithmMismatchException     if the algorithm stated in the token's header is not equal to
     * the one defined in the [JWTVerifier].
     * @throws dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException if the signature is invalid.
     * @throws dev.sdkforge.jwt.decode.domain.exception.TokenExpiredException          if the token has expired.
     * @throws dev.sdkforge.jwt.decode.domain.exception.MissingClaimException          if a claim to be verified is missing.
     * @throws dev.sdkforge.jwt.decode.domain.exception.IncorrectClaimException        if a claim contained a different value than the expected one.
     */
    @Throws(JWTVerificationException::class)
    override fun verify(token: String): DecodedJWT {
        val jwt: DecodedJWT = JWTDecoder(parser, token)
        return verify(jwt)
    }

    /**
     * Perform the verification against the given decoded JWT, using any previous configured options.
     *
     * @param jwt to verify.
     * @return a verified and decoded JWT.
     * @throws dev.sdkforge.jwt.decode.domain.exception.AlgorithmMismatchException     if the algorithm stated in the token's header is not equal to
     * the one defined in the [JWTVerifier].
     * @throws dev.sdkforge.jwt.decode.domain.exception.SignatureVerificationException if the signature is invalid.
     * @throws dev.sdkforge.jwt.decode.domain.exception.TokenExpiredException          if the token has expired.
     * @throws dev.sdkforge.jwt.decode.domain.exception.MissingClaimException          if a claim to be verified is missing.
     * @throws dev.sdkforge.jwt.decode.domain.exception.IncorrectClaimException        if a claim contained a different value than the expected one.
     */
    @Throws(JWTVerificationException::class)
    override fun verify(jwt: DecodedJWT): DecodedJWT {
        verifyAlgorithm(jwt, algorithm)
        (algorithm as VerificationAlgorithm).verify(jwt)
        verifyClaims(jwt, expectedChecks)
        return jwt
    }

    @Throws(AlgorithmMismatchException::class)
    private fun verifyAlgorithm(jwt: DecodedJWT, expectedAlgorithm: Algorithm) {
        if (expectedAlgorithm.name != jwt.algorithm) {
            throw AlgorithmMismatchException(
                "The provided Algorithm doesn't match the one defined in the JWT's Header.",
            )
        }
    }

    @Throws(TokenExpiredException::class, InvalidClaimException::class)
    private fun verifyClaims(jwt: DecodedJWT, expectedChecks: List<ExpectedCheckHolder>) {
        for (expectedCheck in expectedChecks) {
            val isValid: Boolean
            val claimName: String = expectedCheck.claimName
            val claim: Claim = jwt.getClaim(claimName)

            isValid = expectedCheck.verify(claim, jwt)

            if (!isValid) {
                throw IncorrectClaimException(
                    message = "The Claim '$claimName' value doesn't match the required one.",
                    claimName = claimName,
                    claim = claim,
                )
            }
        }
    }

    companion object {
        /**
         * Initialize a [Verification] instance using the given Algorithm.
         *
         * @param algorithm the Algorithm to use on the JWT verification.
         * @return a [Verification] instance to configure.
         * @throws IllegalArgumentException if the provided algorithm is null.
         */
        @Throws(IllegalArgumentException::class)
        internal fun init(algorithm: Algorithm): Verification {
            return BaseVerification(algorithm)
        }

        // Collections.disjoint() body
        fun disjoint(c1: Collection<*>, c2: Collection<*>): Boolean {
            // The collection to be used for contains(). Preference is given to
            // the collection who's contains() has lower O() complexity.
            var contains: Collection<*> = c2
            // The collection to be iterated. If the collections' contains() impl
            // are of different O() complexity, the collection with slower
            // contains() will be used for iteration. For collections who's
            // contains() are of the same complexity then best performance is
            // achieved by iterating the smaller collection.
            var iterate = c1

            // Performance optimization cases. The heuristics:
            //   1. Generally iterate over c1.
            //   2. If c1 is a Set then iterate over c2.
            //   3. If either collection is empty then result is always true.
            //   4. Iterate over the smaller Collection.
            if (c1 is Set<*>) {
                // Use c1 for contains as a Set's contains() is expected to perform
                // better than O(N/2)
                iterate = c2
                contains = c1
            } else if (c2 !is Set<*>) {
                // Both are mere Collections. Iterate over smaller collection.
                // Example: If c1 contains 3 elements and c2 contains 50 elements and
                // assuming contains() requires ceiling(N/2) comparisons then
                // checking for all c1 elements in c2 would require 75 comparisons
                // (3 * ceiling(50/2)) vs. checking all c2 elements in c1 requiring
                // 100 comparisons (50 * ceiling(3/2)).
                val c1size = c1.size
                val c2size = c2.size
                if (c1size == 0 || c2size == 0) {
                    // At least one collection is empty. Nothing will match.
                    return true
                }

                if (c1size > c2size) {
                    iterate = c2
                    contains = c1
                }
            }

            for (e in iterate) {
                if (contains.contains(e)) {
                    // Found a common element. Collections are not disjoint.
                    return false
                }
            }

            // No common elements were found.
            return true
        }
    }
}
