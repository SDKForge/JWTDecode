package dev.sdkforge.jwt.decode.domain.exception

import dev.sdkforge.jwt.decode.domain.Claim

/**
 * This exception is thrown when the expected value is not found while verifying the Claims.
 *
 * @param message The error message
 * @param claimName The Claim name for which verification failed
 * @param claim The Claim value for which verification failed
 */
class IncorrectClaimException(
    message: String,
    /**
     * This method can be used to fetch the name for which the Claim verification failed.
     *
     * @return The claim name for which the verification failed.
     */
    val claimName: String,
    /**
     * The value for which the verification failed.
     */
    val claim: Claim?,
) : InvalidClaimException(message)
