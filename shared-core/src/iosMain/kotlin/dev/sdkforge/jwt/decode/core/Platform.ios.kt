package dev.sdkforge.jwt.decode.core

import platform.UIKit.UIDevice

actual val currentPlatform: Platform = object : Platform {
    override val name: String get() = UIDevice.currentDevice.systemName
    override val version: String get() = UIDevice.currentDevice.systemVersion
}
