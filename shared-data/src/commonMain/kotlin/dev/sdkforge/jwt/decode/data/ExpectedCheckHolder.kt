@file:Suppress("ktlint:standard:function-signature")

package dev.sdkforge.jwt.decode.data

import dev.sdkforge.jwt.decode.domain.Claim
import dev.sdkforge.jwt.decode.domain.DecodedJWT

/**
 * This holds the checks that are run to verify a JWT.
 */
internal interface ExpectedCheckHolder {
    /**
     * The claim name that will be checked.
     *
     * @return the claim name
     */
    val claimName: String

    /**
     * The verification that will be run.
     *
     * @param claim the claim for which verification is done
     * @param decodedJWT the JWT on which verification is done
     * @return whether the verification passed or not
     */
    fun verify(claim: Claim, decodedJWT: DecodedJWT): Boolean
}
