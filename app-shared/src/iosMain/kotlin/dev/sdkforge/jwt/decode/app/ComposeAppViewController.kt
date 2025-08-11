package dev.sdkforge.jwt.decode.app

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.ComposeUIViewController
import kotlin.experimental.ExperimentalObjCName

@OptIn(ExperimentalObjCName::class)
@Suppress("FunctionName")
@ObjCName("create")
fun ComposeAppViewController() = ComposeUIViewController(
    configure = {
        enforceStrictPlistSanityCheck = false
    },
) {
    App(
        modifier = Modifier
            .fillMaxSize(),
    )
}
