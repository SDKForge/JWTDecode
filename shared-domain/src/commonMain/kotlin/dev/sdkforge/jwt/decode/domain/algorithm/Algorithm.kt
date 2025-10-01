package dev.sdkforge.jwt.decode.domain.algorithm

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 */
abstract class Algorithm(
    /**
     * Getter for the name of this Algorithm, as defined in the JWT Standard.
     *
     * @return the algorithm name.
     */
    val name: String,
    /**
     * Getter for the description of this Algorithm, required when instantiating a Mac or Signature object.
     *
     * @return the algorithm description.
     */
    val description: String,
) {

    override fun toString(): String = description

    companion object
}
