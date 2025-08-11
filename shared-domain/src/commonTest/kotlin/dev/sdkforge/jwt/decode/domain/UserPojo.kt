@file:Suppress("ktlint:standard:class-signature")

package dev.sdkforge.jwt.decode.domain

import kotlinx.serialization.Serializable

@Serializable
internal data class UserPojo(
    private val name: String?,
    private val id: Int,
)
